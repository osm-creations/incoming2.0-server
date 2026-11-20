import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, expect, test } from 'vitest';
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
  const bundle = await build({ entryPoints: ['src/index.ts'], bundle: true, format: 'esm', write: false });
  worker = new Miniflare(convertV4MiniflareOptions({
    modules: true,
    script: bundle.outputFiles[0].text,
    compatibilityDate: '2026-09-30',
    d1Databases: ['DB'],
    bindings: {
      PUBLIC_BASE_URL: 'https://test.local',
      INJECT_SELECTION_URL_TEMPLATE: 'https://selection.example.org/current?user={userId}',
      PLAIN_PRESENTATION_ACCOUNT: ' Performer@Example.ORG ',
      SETUP_SECRET: setupSecret,
      TOKEN_PEPPER: randomUUID(),
      JWT_SECRET: randomUUID(),
      CAPABILITY_SIGNING_SECRET: randomUUID()
    },
    outboundService: request => {
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
