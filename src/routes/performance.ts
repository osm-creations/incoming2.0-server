import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { authMiddleware, magicianOnly } from '../middleware/core';
import { apiError, jsonBody, ok } from '../lib/http';
import { audit } from '../lib/db';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
app.use('*', authMiddleware, magicianOnly);

app.get('/sessions', async c => {
  const result = await c.env.DB.prepare(`SELECT s.public_session_id, s.status, s.selected_value, s.latest_revision, s.created_at, s.expires_at, s.last_seen_at,
    cc.id config_id, cc.name config_name, cc.mode
    FROM app_clip_sessions s JOIN clip_configs cc ON cc.id=s.config_id
    WHERE s.owner_user_id=?1 AND datetime(s.expires_at) > datetime('now')
    ORDER BY s.created_at DESC LIMIT 20`).bind(c.get('authUser')!.id).all();
  return ok(c, { sessions: result.results });
});

const injectSchema = z.object({ value: z.string().trim().min(1).max(120), type: z.enum(['INCOMING_CALL']).default('INCOMING_CALL') });
app.post('/sessions/:id/inject', async c => {
  const body = await jsonBody(c, injectSchema);
  if ('error' in body) return body.error;
  const session = await c.env.DB.prepare(`SELECT * FROM app_clip_sessions WHERE public_session_id=?1 AND owner_user_id=?2 AND datetime(expires_at) > datetime('now')`).bind(c.req.param('id'), c.get('authUser')!.id).first<any>();
  if (!session) return apiError(c, 404, 'SESSION_NOT_FOUND', 'Active session not found.');
  const revision = Number(session.latest_revision) + 1;
  const now = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE injections SET consumed_at=?2, result='REPLACED' WHERE session_id=?1 AND consumed_at IS NULL`).bind(session.id, now),
    c.env.DB.prepare(`INSERT INTO injections (id, session_id, owner_user_id, type, value, revision, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`)
      .bind(crypto.randomUUID(), session.id, c.get('authUser')!.id, body.data.type, body.data.value, revision, now),
    c.env.DB.prepare(`UPDATE app_clip_sessions SET latest_revision=?2, status='INJECTION_PENDING' WHERE id=?1`).bind(session.id, revision)
  ]);
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'INJECTION_SENT', targetType: 'APP_CLIP_SESSION', targetId: session.id, metadata: { revision }, requestId: c.get('requestId') });
  return ok(c, { revision, status: 'INJECTION_PENDING' }, 201);
});

app.delete('/sessions/:id/injection', async c => {
  const session = await c.env.DB.prepare(`SELECT * FROM app_clip_sessions WHERE public_session_id=?1 AND owner_user_id=?2 AND datetime(expires_at) > datetime('now')`).bind(c.req.param('id'), c.get('authUser')!.id).first<any>();
  if (!session) return apiError(c, 404, 'SESSION_NOT_FOUND', 'Active session not found.');
  const now = new Date().toISOString();
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE injections SET consumed_at=?2, result='CLEARED' WHERE session_id=?1 AND consumed_at IS NULL`).bind(session.id, now),
    c.env.DB.prepare(`UPDATE app_clip_sessions SET status='BLACK_WAITING' WHERE id=?1`).bind(session.id)
  ]);
  return ok(c, { cleared: true });
});

export default app;
