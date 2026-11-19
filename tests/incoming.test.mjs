import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, expect, test } from 'vitest';

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
      SETUP_SECRET: setupSecret,
      TOKEN_PEPPER: randomUUID(),
      JWT_SECRET: randomUUID(),
      CAPABILITY_SIGNING_SECRET: randomUUID()
    },
    outboundService: request => {
      externalCalls.push([request.method, request.url]);
      return externalResponse();
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
  expect(externalCalls).toEqual([['GET', 'https://11z.co/_w/Test_123/selection']]);
  externalResponse = () => Response.redirect('https://example.org');
  await request(selection, { headers: clipHeaders, status: 502 });
  const cleared = (await save({ callerName: '', injectUserId: '' })).data;
  expect(cleared.config).toMatchObject({ static_text: 'Force word', caller_name: null, inject_user_id: null });
  expect((await save({ staticText: 'New force' })).data.config.caller_name).toBeNull();
  await request(selection, { headers: clipHeaders, status: 404 });
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
