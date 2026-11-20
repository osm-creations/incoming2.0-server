import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, expect, test, vi } from 'vitest';
import { injectSelectionUrl } from '../src/lib/injectSelection.ts';
import { usesPlainPresentation } from '../src/lib/userSettings.ts';

let worker;
let database;
let adminHeaders;
let performer;
let performerHeaders;
const setUpPassword = randomUUID();
const setupSecret = randomUUID();
const externalCalls = [];
const emails = [];
const rejectedMailboxes = new Set();
let externalResponse;

async function request(path, { method = 'GET', headers = {}, body, status = 200 } = {}) {
  const response = await worker.dispatchFetch('https://test.local/api/v1' + path, {
    method,
    headers: { ...headers, ...(body && { 'Content-Type': 'application/json' }) },
    body: body && JSON.stringify(body)
  });
  const json = await response.json();
  expect(response.status, method + ' ' + path + ' ' + (json.error?.message ?? '')).toBe(status);
  return { data: json.data, headers: response.headers };
}

function login(userId, password, client = 'ios', status = 200) {
  return request('/auth/login', { method: 'POST', body: { login: userId, password, client }, status });
}

beforeAll(async () => {
  const bundle = await build({
    entryPoints: ['src/index.ts'], bundle: true, format: 'esm', write: false,
    plugins: [{ name: 'capture-test-mail', setup(b) {
      b.onResolve({ filter: /^\.\/smtp$/ }, () => ({ path: 'mailer', namespace: 'test' }));
      b.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: `export async function sendMail(env, mail) {
        const response = await fetch('https://mail.example.test', { method: 'POST', body: JSON.stringify(mail) });
        if (!response.ok) throw new Error('Mail delivery failed');
      }` }));
    } }]
  });
  worker = new Miniflare(convertV4MiniflareOptions({
    modules: true,
    script: bundle.outputFiles[0].text,
    compatibilityDate: '2026-09-30',
    d1Databases: ['DB'],
    bindings: {
      PUBLIC_BASE_URL: 'https://test.local',
      RESET_PUBLIC_URL: 'https://reset.example.test/',
      CORS_ALLOWED_ORIGINS: '*',
      INJECT_SELECTION_URL_TEMPLATE: 'https://selection.example.org/current?user={userId}',
      PLAIN_PRESENTATION_ACCOUNT: ' Performer@Example.ORG ',
      SETUP_SECRET: setupSecret,
      TOKEN_PEPPER: randomUUID(),
      JWT_SECRET: randomUUID(),
      CAPABILITY_SIGNING_SECRET: randomUUID()
    },
    outboundService: async request => {
      if (new URL(request.url).hostname === 'mail.example.test') {
        const mail = await request.json();
        if (rejectedMailboxes.has(mail.to)) return new Response('', { status: 502 });
        emails.push(mail);
        return new Response('', { status: 200 });
      }
      externalCalls.push([request.method, request.url]);
      return externalResponse(request);
    }
  }));
  database = await worker.getD1Database('DB');
  const schema = await readFile(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8');
  for (const statement of schema.split(';').map(s => s.trim()).filter(Boolean)) {
    if (!statement.startsWith('PRAGMA')) await database.prepare(statement).run();
  }

  const adminPassword = randomUUID();
  await request('/setup/admin', {
    method: 'POST', headers: { 'X-Setup-Secret': setupSecret },
    body: { publicUserId: 'admin', password: adminPassword, email: 'admin@example.org' }, status: 201
  });
  const web = await login('admin', adminPassword, 'web');
  adminHeaders = {
    Cookie: web.headers.getSetCookie().map(cookie => cookie.split(';')[0]).join('; '),
    'X-CSRF-Token': web.data.csrfToken
  };
  const user = await request('/admin/users', {
    method: 'POST', headers: adminHeaders, status: 201,
    body: { publicUserId: 'performer', password: setUpPassword, email: 'performer@example.org' }
  });
  const signedIn = await login(user.data.publicUserId, setUpPassword);
  performer = signedIn.data;
  performerHeaders = { Authorization: 'Bearer ' + performer.accessToken };
}, 30_000);

afterAll(async () => { await worker?.dispose(); });

test('selects the same presentation for the owner and their signed App Clip link', async () => {
  for (const [headers, plain] of [[performerHeaders, true], [adminHeaders, undefined]]) {
    const { data } = await request('/clip-configs/primary', { headers });
    expect(data.config.usesPlainPresentation).toBe(plain);
    expect(data.config.reveal_delay_seconds).toBe(5);
    const url = new URL(data.invocationUrl);
    const [, , publicUserId, publicConfigId] = url.pathname.split('/');
    const { data: clip } = await request('/app-clip/bootstrap', {
      method: 'POST', status: 201,
      body: { publicUserId, publicConfigId, capability: url.searchParams.get('t') }
    });
    expect(clip.configuration.usesPlainPresentation).toBe(plain);
    expect(clip.configuration.revealDelaySeconds).toBe(5);
    expect(JSON.stringify(clip.configuration)).not.toContain('@');
  }
});

test('matches only an exact public user ID or normalized email', () => {
  const match = account => usesPlainPresentation(account, 'Review_A', 'review@example.org');
  expect(match(' Review_A ')).toBe(true);
  expect(match(' REVIEW@example.org ')).toBe(true);
  for (const account of [undefined, ' ', 'review_a', 'Review', 'review@example.com', '*']) {
    expect(match(account)).toBeUndefined();
  }
});

test('keeps existing notes, manual names and 11z previews independent', async () => {
  const path = '/clip-configs/primary';
  const fresh = await request(path, {
    method: 'PATCH', headers: adminHeaders, body: { staticText: 'First note on a new user' }
  });
  expect(fresh.data.config.caller_name).toBeNull();
  const save = body => request(path, { method: 'PATCH', headers: performerHeaders, body });
  const initial = (await request(path, { headers: performerHeaders })).data;
  expect(initial.config.caller_name).toBeNull();

  // An existing config predates the independent caller setting.
  await database.prepare('UPDATE clip_configs SET static_text=?1 WHERE id=?2')
    .bind('\n  Legacy Caller  \nSecond line', initial.config.id).run();
  expect((await request(path, { headers: performerHeaders })).data.config.caller_name).toBe('Legacy Caller');
  const saved = (await save({ staticText: 'Force word' })).data;
  expect(saved.config.caller_name).toBe('Legacy Caller');
  expect(saved.invocationUrl).toBe(initial.invocationUrl);
  await save({ callerName: 'Manual Caller', injectUserId: 'Test_123' });

  const invocation = new URL(initial.invocationUrl);
  const boot = (await request('/app-clip/bootstrap', {
    method: 'POST', status: 201,
    body: { publicUserId: 'performer', publicConfigId: initial.config.public_config_id, capability: invocation.searchParams.get('t') }
  })).data;
  expect(boot.configuration).toMatchObject({ staticText: 'Force word', callerName: 'Manual Caller', hasInjectUserId: true });
  expect(JSON.stringify(boot.configuration)).not.toContain('Test_123');
  const selection = '/app-clip/sessions/' + boot.session.id + '/selection';
  const clipHeaders = { Authorization: 'Clip ' + boot.session.token };
  externalResponse = () => Response.json({ value: 'hello', count: 2114 });
  expect((await request(selection, { headers: clipHeaders })).data).toEqual({ value: 'hello' });
  expect(externalCalls).toEqual([['GET', 'https://selection.example.org/current?user=Test_123']]);
  externalResponse = () => Response.redirect('https://example.org');
  await request(selection, { headers: clipHeaders, status: 502 });
  expect(externalCalls.at(-1)).toEqual(['GET', 'https://selection.example.org/current?user=Test_123']);
  const cleared = (await save({ callerName: '', injectUserId: '' })).data;
  expect(cleared.config).toMatchObject({ static_text: 'Force word', caller_name: null, inject_user_id: null });
  expect((await save({ staticText: 'New force' })).data.config.caller_name).toBeNull();
  await request(selection, { headers: clipHeaders, status: 404 });
});

test('keeps two performers’ settings, existing links and Inject selections scoped to their accounts', async () => {
  const password = randomUUID();
  const primary = '/clip-configs/primary';
  const save = (headers, body) => request(primary, { method: 'PATCH', headers, body });
  const bootstrap = (invocationUrl, override = {}, status = 201) => {
    const url = new URL(invocationUrl);
    const [, , publicUserId, publicConfigId] = url.pathname.split('/');
    return request('/app-clip/bootstrap', {
      method: 'POST', status,
      body: { publicUserId, publicConfigId, capability: url.searchParams.get('t'), ...override }
    });
  };
  const selection = (id, token, status = 200) => request('/app-clip/sessions/' + id + '/selection', {
    headers: { Authorization: 'Clip ' + token }, status
  });
  async function createAccount(id, email) {
    const created = await request('/admin/users', {
      method: 'POST', headers: adminHeaders, body: { publicUserId: id, email, password, role: 'MAGICIAN' }, status: 201
    });
    const signedIn = (await login(id, password)).data;
    expect(signedIn.user.id).toBe(created.data.id);
    return { Authorization: 'Bearer ' + signedIn.accessToken };
  }
  const alpha = await createAccount('CasePair', 'alpha@example.org');
  expect((await login('CASEPAIR', password)).data.user.publicUserId).toBe('CasePair');
  const beta = await createAccount('casepair', 'beta@example.org');
  await login('CASEPAIR', password, 'ios', 401);
  expect((await login('BETA@example.org', password)).data.user.publicUserId).toBe('casepair');

  const a = (await save(alpha, { staticText: 'Rose', callerName: 'Alice', injectUserId: 'inject-A', revealDelaySeconds: 34 })).data;
  const b = (await save(beta, { staticText: 'Key', callerName: 'Bryn', injectUserId: 'inject-B' })).data;
  const alphaSettings = await request(primary, { headers: alpha });
  expect(alphaSettings.headers.get('Cache-Control')).toContain('no-store');
  expect(alphaSettings.data.config).toMatchObject({ static_text: 'Rose', caller_name: 'Alice', inject_user_id: 'inject-A' });
  expect((await request(primary, { headers: beta })).data.config)
    .toMatchObject({ static_text: 'Key', caller_name: 'Bryn', inject_user_id: 'inject-B' });
  await request('/clip-configs/' + a.config.id, { headers: beta, status: 404 });
  await bootstrap(a.invocationUrl, { publicUserId: 'casepair' }, 404);

  // A second config belongs to the same performer and shares only that performer's account settings.
  const extra = await request('/clip-configs', { method: 'POST', headers: alpha, status: 201,
    body: { name: 'Alternate trick', mode: 'STATIC', staticText: 'Coin' } });
  const oldLink = await bootstrap(a.invocationUrl);
  expect(oldLink.headers.get('Cache-Control')).toContain('no-store');
  expect(oldLink.data.configuration).toMatchObject({ staticText: 'Rose', callerName: 'Alice' });
  expect((await bootstrap(extra.data.invocationUrl)).data.configuration)
    .toMatchObject({ staticText: 'Coin', callerName: 'Alice', revealDelaySeconds: 34 });
  const aSession = oldLink.data.session;
  const bClip = (await bootstrap(b.invocationUrl)).data;
  const bSession = bClip.session;
  expect(bClip.configuration).toMatchObject({ staticText: 'Key', callerName: 'Bryn' });
  externalResponse = req => Response.json({ value: new URL(req.url).searchParams.get('user') });
  expect((await selection(aSession.id, aSession.token)).data.value).toBe('inject-A');
  expect((await selection(bSession.id, bSession.token)).data.value).toBe('inject-B');
  await selection(aSession.id, bSession.token, 401);

  await save(beta, { callerName: 'Beth', injectUserId: 'inject-B2' });
  expect((await selection(bSession.id, bSession.token)).data.value).toBe('inject-B2');
  expect((await bootstrap(b.invocationUrl)).data.configuration.callerName).toBe('Beth');
  await save(beta, { callerName: '', injectUserId: '' });
  await selection(bSession.id, bSession.token, 404);
  expect((await selection(aSession.id, aSession.token)).data.value).toBe('inject-A');
  expect((await bootstrap(a.invocationUrl)).data.configuration.callerName).toBe('Alice');
});

test('upgrades legacy settings and preserves each performer’s reveal delay on their existing links', async () => {
  const path = '/clip-configs/primary';
  const save = (headers, body, status = 200) => request(path, { method: 'PATCH', headers, body, status });
  const original = (await save(performerHeaders, { callerName: 'Jamie', injectUserId: 'performer-selection' })).data;
  const other = (await request(path, { headers: adminHeaders })).data;
  const revealDelay = async link => {
    const url = new URL(link);
    const [, , publicUserId, publicConfigId] = url.pathname.split('/');
    const clip = await request('/app-clip/bootstrap', {
      method: 'POST', status: 201, body: { publicUserId, publicConfigId, capability: url.searchParams.get('t') }
    });
    return clip.data.configuration.revealDelaySeconds;
  };

  // Restore the previous production schema with existing accounts and signed links.
  await database.prepare('ALTER TABLE incoming_user_settings DROP COLUMN reveal_delay_seconds').run();
  const [legacy, legacyDelay] = await Promise.all([
    request(path, { headers: performerHeaders }), revealDelay(original.invocationUrl)
  ]);
  expect(legacy.data.config).toMatchObject({ caller_name: 'Jamie', inject_user_id: 'performer-selection', reveal_delay_seconds: 5 });
  expect(legacyDelay).toBe(5);

  // A write may also be the first request after the Worker is deployed.
  await database.prepare('ALTER TABLE incoming_user_settings DROP COLUMN reveal_delay_seconds').run();
  await save(adminHeaders, { revealDelaySeconds: 17 });
  for (const seconds of [60, 0]) {
    const updated = (await save(performerHeaders, { revealDelaySeconds: seconds })).data;
    expect(updated.invocationUrl).toBe(original.invocationUrl);
    expect(updated.config).toMatchObject({ caller_name: 'Jamie', inject_user_id: 'performer-selection', reveal_delay_seconds: seconds });
    expect(await revealDelay(original.invocationUrl)).toBe(seconds);
    expect(await revealDelay(other.invocationUrl)).toBe(17);
  }
  for (const invalid of [-1, 61, 0.5, '15', null]) {
    await save(performerHeaders, { revealDelaySeconds: invalid }, 422);
  }
  await save(performerHeaders, { staticText: '', callerName: '' });
  expect(await revealDelay(original.invocationUrl)).toBe(0);
});

test('admin reset revokes existing credentials and preserves the account', async () => {
  const path = '/admin/users/' + performer.user.id + '/reset-password';
  const password = randomUUID();
  await request(path, { method: 'POST', headers: { Cookie: adminHeaders.Cookie }, body: { password }, status: 403 });
  await request(path, { method: 'POST', headers: adminHeaders, body: { password } });
  await request('/auth/me', { headers: performerHeaders, status: 401 });
  await request('/auth/refresh', { method: 'POST', body: { refreshToken: performer.refreshToken }, status: 401 });
  await login('performer', setUpPassword, 'ios', 401);
  expect((await login('performer', password)).data.user.id).toBe(performer.user.id);
});

test('defaults to the established URL and encodes an ID once in a configured path or query', () => {
  expect(injectSelectionUrl(undefined, 'Test_123').href).toBe('https://11z.co/_w/Test_123/selection');
  expect(injectSelectionUrl('https://api.example.org/{userId}/current', 'A/B').href)
    .toBe('https://api.example.org/A%2FB/current');
  expect(injectSelectionUrl('https://api.example.org/?q={userId}', 'A&B').href)
    .toBe('https://api.example.org/?q=A%26B');
});

test.each([
  '',
  'http://example.org/{userId}',
  'https://{userId}.example.org/',
  'https://example.org:{userId}/api',
  'https://user:pass@example.org/{userId}',
  'https://example.org/path',
  'https://example.org/{userId}/{userId}',
  'https://example.org/path#{userId}',
  'https://example.org/{userId}?other={unknown}'
])('rejects an invalid URL template %s', template => {
  expect(() => injectSelectionUrl(template, 'Alice')).toThrow();
});

test('compact NFC tags resolve only their active configuration and rotate with existing signed links', async () => {
  const created = await request('/clip-configs', {
    method: 'POST', headers: adminHeaders, status: 201,
    body: { name: 'Short tag test', mode: 'DIRECT_NOTES', staticText: 'Sunflower' }
  });
  const config = created.data.config;
  const compact = new URL(created.data.shortInvocationUrl);
  expect(compact.pathname).toMatch(/^\/c\/[A-Za-z0-9_-]{22}$/);
  expect(compact.search).toBe('');
  const token = compact.pathname.slice('/c/'.length);
  const legacy = new URL(created.data.invocationUrl);
  const open = (shortToken, status = 201) => request('/app-clip/bootstrap', { method: 'POST', body: { shortToken }, status });
  const openLegacy = (status = 201) => request('/app-clip/bootstrap', {
    method: 'POST', status, body: { publicUserId: 'admin', publicConfigId: config.public_config_id, capability: legacy.searchParams.get('t') }
  });
  const stored = await database.prepare('SELECT token_hash, version FROM incoming_short_links WHERE config_id=?1').bind(config.id).first();
  expect(stored.token_hash).not.toBe(token);
  expect(stored.version).toBe(config.capability_version);
  // URI type + short-record header + single https:// prefix byte + hostname and path.
  const production = new URL(compact.pathname, 'https://incoming2-0-server.incoming-osmcreations.workers.dev');
  expect(Buffer.byteLength(production.href.slice('https://'.length)) + 5).toBe(82);
  expect((await worker.dispatchFetch(compact.href)).status).toBe(200);
  expect((await open(token)).data.configuration.staticText).toBe('Sunflower');
  expect((await openLegacy()).data.configuration.staticText).toBe('Sunflower');
  await open('A'.repeat(22), 404);
  await request('/clip-configs/' + config.id, { method: 'PATCH', headers: adminHeaders, body: { staticText: 'Tulip', enabled: false } });
  await open(token, 404);
  await request('/clip-configs/' + config.id, { method: 'PATCH', headers: adminHeaders, body: { enabled: true } });
  expect((await open(token)).data.configuration.staticText).toBe('Tulip');
  const rotated = await request('/clip-configs/' + config.id + '/rotate-link', { method: 'POST', headers: adminHeaders });
  const replacement = new URL(rotated.data.shortInvocationUrl).pathname.slice('/c/'.length);
  expect(replacement).not.toBe(token);
  await open(token, 404);
  await openLegacy(404);
  expect((await open(replacement)).data.configuration.staticText).toBe('Tulip');
  await request('/clip-configs/' + config.id, { method: 'DELETE', headers: adminHeaders });
  await open(replacement, 404);
});

function ticketFrom(email) {
  const match = email.text.match(/https:\/\/reset\.example\.test\/\S*/);
  expect(match).toBeTruthy();
  const link = new URL(match[0]);
  expect(link.search).toBe('');
  return new URLSearchParams(link.hash.slice(1)).get('token');
}

test('sends a seven-day welcome, redeems one link atomically and revokes temporary credentials and existing sessions', async () => {
  const address = 'welcome@example.test';
  const created = await request('/admin/users', { method: 'POST', headers: adminHeaders, body: { email: address }, status: 201 });
  expect(created.data.welcomeEmailSent).toBe(true);
  expect(created.data.password).toBeUndefined();
  const mail = emails.findLast(m => m.to === address);
  expect(mail.text).toContain('User ID: ' + created.data.publicUserId);
  const temporary = mail.text.match(/Temporary password: (\S+)/)[1];
  const token = ticketFrom(mail);
  const session = (await login(address, temporary)).data;
  const tickets = (await database.prepare('SELECT * FROM password_reset_tokens WHERE user_id=?1').bind(created.data.id).all()).results;
  expect(tickets).toHaveLength(1);
  const row = tickets[0];
  expect(JSON.stringify(row)).not.toContain(token.split('.')[0]);
  expect(JSON.stringify(row)).not.toContain(temporary);
  expect(Date.parse(row.expires_at) - Date.parse(row.created_at)).toBe(7 * 24 * 3600000);

  const choices = [randomUUID(), randomUUID()];
  const resolve = password => worker.dispatchFetch('https://test.local/api/v1/auth/reset-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password })
  });
  const result = await Promise.all(choices.map(resolve));
  expect(result.map(x => x.status).sort()).toEqual([200, 400]);
  const index = result.findIndex(x => x.status === 200);
  expect((await login(address, choices[index])).data.forcePasswordChange).toBe(false);
  await login(address, choices[1-index], 'ios', 401);
  await login(address, temporary, 'ios', 401);
  await request('/auth/me', { headers: { Authorization: 'Bearer ' + session.accessToken }, status: 401 });
  await request('/auth/refresh', { method: 'POST', body: { refreshToken: session.refreshToken }, status: 401 });
  await request('/auth/reset-password', { method: 'POST', body: { token, password: randomUUID() }, status: 400 });
  await request('/admin/users', { method: 'POST', headers: adminHeaders, body: { email: address }, status: 409 });
  expect(emails.filter(m => m.to === address)).toHaveLength(1);
});

test('expired temporary passwords can be recovered by email; links and login expire independently', async () => {
  const address = 'retry@example.test';
  const temporary = randomUUID();
  rejectedMailboxes.add(address);
  const created = (await request('/admin/users', { method: 'POST', headers: adminHeaders,
    body: { email: address, password: temporary }, status: 201 })).data;
  expect(created.welcomeEmailSent).toBe(false);
  const session = (await login(address, temporary)).data;
  await database.prepare("UPDATE password_reset_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE user_id=?1").bind(created.id).run();
  await login(address, temporary, 'ios', 401);
  await request('/auth/me', { headers: { Authorization: 'Bearer ' + session.accessToken }, status: 401 });
  await request('/auth/refresh', { method: 'POST', body: { refreshToken: session.refreshToken }, status: 401 });
  rejectedMailboxes.delete(address);
  const forgot = email => request('/auth/forgot-password', { method:'POST', body:{ email } });
  const missing = await forgot('missing@example.test');
  const actual = await forgot(address.toUpperCase());
  expect(actual.data).toEqual(missing.data);
  await vi.waitFor(() => expect(emails.some(m => m.to === address)).toBe(true));
  const reset = emails.findLast(m => m.to === address);
  const token = ticketFrom(reset);
  expect(reset.text).not.toContain(temporary);
  const row = await database.prepare('SELECT * FROM password_reset_tokens WHERE user_id=?1 AND id!=?2').bind(created.id, 'welcome:' + created.id).first();
  expect(Date.parse(row.expires_at) - Date.parse(row.created_at)).toBe(3600000);
  await database.prepare("UPDATE password_reset_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1").bind(row.id).run();
  await request('/auth/reset-password', { method:'POST', body:{ token, password:randomUUID() }, status:400 });
  await forgot(address);
  await vi.waitFor(() => expect(emails.filter(m => m.to === address)).toHaveLength(2));
  const newPassword = randomUUID();
  await request('/auth/reset-password', { method:'POST', body:{ token:ticketFrom(emails.findLast(m => m.to === address)), password:newPassword } });
  await login(address, newPassword);
});

test('old links stay invalid after account changes, rate-limited and disabled accounts produce the same public response', async () => {
  const address = 'status@example.test';
  const made = (await request('/admin/users', { method: 'POST', headers: adminHeaders, body: { email: address }, status: 201 })).data;
  const invalid = token => request('/auth/reset-password', { method:'POST', body:{ token, password:randomUUID() }, status:400 });
  const adminChange = (suffix, body = {}) => request('/admin/users/' + made.id + suffix, { method:suffix ? 'POST':'PATCH', headers:adminHeaders, body });
  const welcome = emails.findLast(m => m.to === address);
  const invite = ticketFrom(welcome);
  const temporary = welcome.text.match(/Temporary password: (\S+)/)[1];
  await adminChange('', { email: 'changed@example.test' });
  await login(made.publicUserId, temporary, 'ios', 401);
  await adminChange('', { email: address });
  await invalid(invite);
  const forgot = email => request('/auth/forgot-password', { method:'POST', headers:{ 'CF-Connecting-IP':'192.0.2.68' }, body:{ email } });
  const active = await forgot(address);
  await vi.waitFor(() => expect(emails.filter(m => m.to === address)).toHaveLength(2));
  const oldToken = ticketFrom(emails.findLast(m => m.to === address));
  await adminChange('/disable');
  expect((await forgot(address)).data).toEqual(active.data);
  await invalid(oldToken);
  await adminChange('/enable');
  await invalid(oldToken);
  await forgot(address);
  await vi.waitFor(() => expect(emails.filter(m => m.to === address)).toHaveLength(3));
  expect((await forgot(address)).data).toEqual(active.data);
  expect((await forgot('nonexistent@example.test')).data).toEqual(active.data);
  const newToken = ticketFrom(emails.findLast(m => m.to === address));
  await adminChange('/reset-password', { password: randomUUID() });
  await invalid(newToken);
  expect(emails.filter(m => m.to === address)).toHaveLength(3);
});

test('legacy users with a forced-change flag and no enrollment row keep their original login', async () => {
  const info = (await request('/admin/users', { method: 'POST', headers: adminHeaders,
    body: { email: 'legacy@example.test', password: setUpPassword }, status: 201 })).data;
  await database.prepare('DELETE FROM password_reset_tokens WHERE user_id=?1').bind(info.id).run();
  await database.prepare("UPDATE users SET created_at='2000-01-01T00:00:00Z' WHERE id=?1").bind(info.id).run();
  expect((await login(info.publicUserId, setUpPassword)).data.forcePasswordChange).toBe(true);
});

test('throttles public reset requests across different addresses on the same IP and checks the signed proof', async () => {
  const address = 'limit@example.test';
  await request('/admin/users', { method: 'POST', headers: adminHeaders, body: { email: address }, status: 201 });
  const invite = ticketFrom(emails.findLast(m => m.to === address));
  const wrongProof = invite.replace(/\.(.)/, (_, c) => '.' + (c === 'x' ? 'y' : 'x'));
  const redeem = (token, status) => request('/auth/reset-password', { method: 'POST',
    headers: { 'CF-Connecting-IP': '192.0.2.200' }, body: { token, password: randomUUID() }, status });
  await redeem(wrongProof, 400);
  await redeem(invite, 200);

  const forgot = (mail, ip) => request('/auth/forgot-password',
    { method: 'POST', headers: { 'CF-Connecting-IP': ip }, body: { email: mail } });
  const ip = '192.0.2.171';
  // All requests are counted even when submitted at the same time.
  await Promise.all(Array.from({ length: 12 }, (_, i) => forgot('ip-miss-' + i + '@example.test', ip)));
  const limited = await forgot(address, ip);
  const fresh = await forgot(address, '192.0.2.172');
  expect(limited.data).toEqual(fresh.data);
  await vi.waitFor(() => expect(emails.filter(m => m.to === address && m.subject.includes('Reset'))).toHaveLength(1));
});

test('the app login link opens the configured site and public recovery CORS does not grant admin credentials', async () => {
  const entry = await worker.dispatchFetch('https://test.local/forgot-password?next=https://elsewhere.example/', { redirect: 'manual' });
  expect(entry.status).toBe(302);
  expect(entry.headers.get('Location')).toBe('https://reset.example.test/');
  expect(entry.headers.get('Cache-Control')).toBe('no-store');
  const preflight = path => worker.dispatchFetch('https://test.local/api/v1' + path, {
    method: 'OPTIONS', headers: {
      Origin: 'https://reset.example.test', 'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type'
    }
  });
  for (const path of ['/auth/forgot-password', '/auth/reset-password']) {
    const response = await preflight(path);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(response.headers.has('Access-Control-Allow-Credentials')).toBe(false);
  }
  const admin = await preflight('/admin/users');
  expect(admin.headers.get('Access-Control-Allow-Origin')).toBeFalsy();
});
