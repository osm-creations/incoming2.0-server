import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { apiError, jsonBody, ok } from '../lib/http';
import { adminCsrf, adminOnly, authMiddleware } from '../middleware/core';
import { audit } from '../lib/db';
import { hashPassword } from '../lib/security';
import { randomPublicId } from '../lib/encoding';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
app.use('*', authMiddleware, adminOnly, adminCsrf);

const createSchema = z.object({
  publicUserId: z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9_-]+$/).optional(),
  email: z.string().email().max(254),
  password: z.string().min(10).max(200),
  role: z.enum(['ADMIN', 'MAGICIAN']).default('MAGICIAN')
});

app.get('/dashboard', async c => {
  const counts = await c.env.DB.prepare(`SELECT
    COUNT(*) total,
    SUM(CASE WHEN status='ACTIVE' THEN 1 ELSE 0 END) active,
    SUM(CASE WHEN status='DISABLED' THEN 1 ELSE 0 END) disabled
    FROM users`).first<{ total: number; active: number; disabled: number }>();
  const recent = await c.env.DB.prepare(`SELECT id, public_user_id, email, role, status, created_at, last_login_at FROM users ORDER BY created_at DESC LIMIT 8`).all();
  return ok(c, { counts: counts ?? { total: 0, active: 0, disabled: 0 }, recent: recent.results });
});

app.get('/users', async c => {
  const q = (c.req.query('q') ?? '').trim().toLowerCase();
  const stmt = q
    ? c.env.DB.prepare(`SELECT id, public_user_id, email, role, status, force_password_change, created_at, updated_at, last_login_at FROM users WHERE lower(email) LIKE ?1 OR lower(public_user_id) LIKE ?1 ORDER BY created_at DESC LIMIT 100`).bind(`%${q}%`)
    : c.env.DB.prepare(`SELECT id, public_user_id, email, role, status, force_password_change, created_at, updated_at, last_login_at FROM users ORDER BY created_at DESC LIMIT 100`);
  const result = await stmt.all();
  return ok(c, { users: result.results });
});

app.post('/users', async c => {
  const body = await jsonBody(c, createSchema);
  if ('error' in body) return body.error;
  const id = crypto.randomUUID();
  const publicUserId = body.data.publicUserId ?? randomPublicId('incoming', 7);
  const email = body.data.email.trim().toLowerCase();
  const now = new Date().toISOString();
  try {
    await c.env.DB.prepare(`INSERT INTO users (id, public_user_id, email, password_hash, role, status, force_password_change, created_at, updated_at)
      VALUES (?1, ?2, ?3, ?4, ?5, 'ACTIVE', 1, ?6, ?6)`)
      .bind(id, publicUserId, email, await hashPassword(body.data.password), body.data.role, now).run();
  } catch {
    return apiError(c, 409, 'USER_EXISTS', 'A user with that email or public user ID already exists.');
  }
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'ADMIN_USER_CREATED', targetType: 'USER', targetId: id, metadata: { role: body.data.role }, requestId: c.get('requestId') });
  return ok(c, { id, publicUserId, email, role: body.data.role, status: 'ACTIVE' }, 201);
});

app.get('/users/:id', async c => {
  const user = await c.env.DB.prepare(`SELECT id, public_user_id, email, role, status, force_password_change, created_at, updated_at, last_login_at FROM users WHERE id=?1`).bind(c.req.param('id')).first();
  if (!user) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
  return ok(c, { user });
});

const updateSchema = z.object({ email: z.string().email().max(254).optional(), publicUserId: z.string().min(3).max(64).regex(/^[A-Za-z0-9_-]+$/).optional() }).refine(v => v.email || v.publicUserId, 'No updates');
app.patch('/users/:id', async c => {
  const body = await jsonBody(c, updateSchema);
  if ('error' in body) return body.error;
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE id=?1`).bind(c.req.param('id')).first();
  if (!existing) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
  try {
    if (body.data.email) await c.env.DB.prepare(`UPDATE users SET email=?2, updated_at=?3 WHERE id=?1`).bind(c.req.param('id'), body.data.email.trim().toLowerCase(), new Date().toISOString()).run();
    if (body.data.publicUserId) await c.env.DB.prepare(`UPDATE users SET public_user_id=?2, updated_at=?3 WHERE id=?1`).bind(c.req.param('id'), body.data.publicUserId, new Date().toISOString()).run();
  } catch { return apiError(c, 409, 'CONFLICT', 'Email or public user ID already in use.'); }
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'ADMIN_USER_UPDATED', targetType: 'USER', targetId: c.req.param('id'), requestId: c.get('requestId') });
  return ok(c, { updated: true });
});

app.post('/users/:id/disable', async c => {
  if (c.get('authUser')!.id === c.req.param('id')) return apiError(c, 409, 'SELF_DISABLE_BLOCKED', 'You cannot disable your own account here.');
  const result = await c.env.DB.prepare(`UPDATE users SET status='DISABLED', updated_at=?2 WHERE id=?1`).bind(c.req.param('id'), new Date().toISOString()).run();
  if (!result.meta.changes) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
  await c.env.DB.prepare(`UPDATE auth_sessions SET revoked_at=?2 WHERE user_id=?1 AND revoked_at IS NULL`).bind(c.req.param('id'), new Date().toISOString()).run();
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'ADMIN_USER_DISABLED', targetType: 'USER', targetId: c.req.param('id'), requestId: c.get('requestId') });
  return ok(c, { status: 'DISABLED' });
});

app.post('/users/:id/enable', async c => {
  const result = await c.env.DB.prepare(`UPDATE users SET status='ACTIVE', updated_at=?2 WHERE id=?1`).bind(c.req.param('id'), new Date().toISOString()).run();
  if (!result.meta.changes) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'ADMIN_USER_ENABLED', targetType: 'USER', targetId: c.req.param('id'), requestId: c.get('requestId') });
  return ok(c, { status: 'ACTIVE' });
});

app.get('/audit', async c => {
  const result = await c.env.DB.prepare(`SELECT id, actor_user_id, action, target_type, target_id, metadata_json, request_id, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100`).all();
  return ok(c, { audit: result.results });
});

export default app;
