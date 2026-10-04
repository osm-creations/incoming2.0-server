import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { apiError, jsonBody, ok } from '../lib/http';
import { hashOpaqueToken, newSessionToken, verifyCapability } from '../lib/security';
import { randomPublicId } from '../lib/encoding';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const bootstrapSchema = z.object({ publicUserId: z.string().min(3).max(100), publicConfigId: z.string().min(3).max(100), capability: z.string().min(20).max(2000) });
app.post('/bootstrap', async c => {
  const body = await jsonBody(c, bootstrapSchema);
  if ('error' in body) return body.error;
  const cap = await verifyCapability(body.data.capability, c.env);
  if (!cap || cap.publicUserId !== body.data.publicUserId || cap.publicConfigId !== body.data.publicConfigId) return apiError(c, 404, 'EXPERIENCE_UNAVAILABLE', 'This experience is unavailable.');
  const row = await c.env.DB.prepare(`SELECT cc.*, u.public_user_id, u.status user_status FROM clip_configs cc JOIN users u ON u.id=cc.owner_user_id
    WHERE cc.public_config_id=?1 AND u.public_user_id=?2 LIMIT 1`).bind(body.data.publicConfigId, body.data.publicUserId).first();
  if (!row || row.user_status !== 'ACTIVE' || !row.enabled || row.capability_version !== cap.version) return apiError(c, 404, 'EXPERIENCE_UNAVAILABLE', 'This experience is unavailable.');

  const options = row.mode === 'MENU' ? await c.env.DB.prepare(`SELECT id, value, display_order FROM clip_menu_options WHERE config_id=?1 AND enabled=1 ORDER BY display_order`).bind(row.id).all() : { results: [] };
  const sessionToken = newSessionToken();
  const sessionHash = await hashOpaqueToken(sessionToken, c.env.TOKEN_PEPPER);
  const publicSessionId = randomPublicId('sess', 10);
  const now = new Date();
  const expiresAt = new Date(Date.now() + Number(c.env.APP_CLIP_SESSION_TTL_SECONDS || '1200') * 1000);
  await c.env.DB.prepare(`INSERT INTO app_clip_sessions (id, public_session_id, config_id, owner_user_id, session_token_hash, status, latest_revision, expires_at, last_seen_at, created_at)
    VALUES (?1, ?2, ?3, ?4, ?5, 'ACTIVE', 0, ?6, ?7, ?7)`)
    .bind(crypto.randomUUID(), publicSessionId, row.id, row.owner_user_id, sessionHash, expiresAt.toISOString(), now.toISOString()).run();

  return ok(c, {
    session: { id: publicSessionId, token: sessionToken, expiresAt: expiresAt.toISOString() },
    configuration: {
      name: row.name,
      mode: row.mode,
      staticText: row.static_text,
      openOverflowInitially: Boolean(row.open_overflow_initially),
      options: options.results.map((o: any) => ({ id: o.id, value: o.value }))
    }
  }, 201);
});

async function clipSession(c: any) {
  const auth = c.req.header('Authorization') ?? '';
  if (!auth.startsWith('Clip ')) return null;
  const hash = await hashOpaqueToken(auth.slice(5), c.env.TOKEN_PEPPER);
  const row = await c.env.DB.prepare(`SELECT * FROM app_clip_sessions WHERE public_session_id=?1 AND session_token_hash=?2 LIMIT 1`).bind(c.req.param('id'), hash).first();
  if (!row || Date.parse(row.expires_at) <= Date.now()) return null;
  await c.env.DB.prepare(`UPDATE app_clip_sessions SET last_seen_at=?2 WHERE id=?1`).bind(row.id, new Date().toISOString()).run();
  return row;
}

app.get('/sessions/:id/state', async c => {
  const session = await clipSession(c);
  if (!session) return apiError(c, 401, 'SESSION_EXPIRED', 'This session has expired.');
  const after = Number(c.req.query('afterRevision') ?? '0');
  const injection = await c.env.DB.prepare(`SELECT id, type, value, revision, created_at FROM injections WHERE session_id=?1 AND consumed_at IS NULL AND revision>?2 ORDER BY revision DESC LIMIT 1`).bind(session.id, Number.isFinite(after) ? after : 0).first();
  if (!injection) return ok(c, { revision: session.latest_revision, changed: false, status: session.status });
  await c.env.DB.prepare(`UPDATE app_clip_sessions SET status='INJECTION_READY' WHERE id=?1`).bind(session.id).run();
  return ok(c, { revision: injection.revision, changed: true, status: 'INJECTION_READY', payload: { type: injection.type, text: injection.value } });
});

const selectSchema = z.object({ optionId: z.string().uuid() });
app.post('/sessions/:id/select', async c => {
  const session = await clipSession(c);
  if (!session) return apiError(c, 401, 'SESSION_EXPIRED', 'This session has expired.');
  const body = await jsonBody(c, selectSchema);
  if ('error' in body) return body.error;
  const option = await c.env.DB.prepare(`SELECT value FROM clip_menu_options WHERE id=?1 AND config_id=?2 AND enabled=1`).bind(body.data.optionId, session.config_id).first<{ value: string }>();
  if (!option) return apiError(c, 404, 'OPTION_UNAVAILABLE', 'That option is unavailable.');
  await c.env.DB.prepare(`UPDATE app_clip_sessions SET selected_value=?2, status='NOTES' WHERE id=?1`).bind(session.id, option.value).run();
  return ok(c, { selectedValue: option.value });
});

const statusSchema = z.object({ status: z.enum(['NOTES','BLACK_WAITING']) });
app.patch('/sessions/:id/status', async c => {
  const session = await clipSession(c);
  if (!session) return apiError(c, 401, 'SESSION_EXPIRED', 'This session has expired.');
  const body = await jsonBody(c, statusSchema);
  if ('error' in body) return body.error;
  await c.env.DB.prepare(`UPDATE app_clip_sessions SET status=?2 WHERE id=?1`).bind(session.id, body.data.status).run();
  return ok(c, { status: body.data.status });
});

const consumeSchema = z.object({ result: z.enum(['ACCEPTED','DECLINED']) });
app.post('/sessions/:id/consume', async c => {
  const session = await clipSession(c);
  if (!session) return apiError(c, 401, 'SESSION_EXPIRED', 'This session has expired.');
  const body = await jsonBody(c, consumeSchema);
  if ('error' in body) return body.error;
  const latest = await c.env.DB.prepare(`SELECT id FROM injections WHERE session_id=?1 AND consumed_at IS NULL ORDER BY revision DESC LIMIT 1`).bind(session.id).first<{ id: string }>();
  if (latest) await c.env.DB.prepare(`UPDATE injections SET consumed_at=?2, result=?3 WHERE id=?1`).bind(latest.id, new Date().toISOString(), body.data.result).run();
  await c.env.DB.prepare(`UPDATE app_clip_sessions SET status='NOTES' WHERE id=?1`).bind(session.id).run();
  return ok(c, { consumed: Boolean(latest) });
});

export default app;
