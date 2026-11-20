import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { apiError, jsonBody, ok } from '../lib/http';
import { adminCsrf, adminOnly, authMiddleware } from '../middleware/core';
import { audit } from '../lib/db';
import { withUserSettings } from '../lib/userSettings';
import { hashPassword } from '../lib/security';
import { newPasswordTicket, sendWelcome } from '../lib/passwordRecovery';
import { randomPublicId, randomToken } from '../lib/encoding';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
app.use('*', authMiddleware, adminOnly, adminCsrf);

const createSchema = z.object({
  publicUserId: z.preprocess(
    value => typeof value === 'string' && value.trim() === '' ? undefined : value,
    z.string()
      .trim()
      .min(3, 'Public User ID must be at least 3 characters.')
      .max(64, 'Public User ID must be at most 64 characters.')
      .regex(/^[A-Za-z0-9_-]+$/, 'Public User ID may contain only letters, numbers, underscore (_) and hyphen (-).')
      .optional()
  ),
  email: z.string().trim().email('Enter a valid email address.').max(254, 'Email is too long.'),
  password: z.string().min(12, 'Temporary password must be at least 12 characters.').max(200, 'Password is too long.').optional(),
  role: z.enum(['ADMIN', 'MAGICIAN'], { message: 'Role must be ADMIN or MAGICIAN.' }).default('MAGICIAN')
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
  const password = body.data.password ?? randomToken(20);
  const ticket = await newPasswordTicket(c.env, { id, email, credential_version: 0 }, true);
  const passwordHash = await hashPassword(password);
  const db = c.env.DB;
  try {
    await db.batch([
      db.prepare(`INSERT INTO users (id, public_user_id, email, password_hash, role, status, force_password_change, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 'ACTIVE', 1, ?6, ?6)`).bind(id, publicUserId, email, passwordHash, body.data.role, now),
      ticket.statement,
      db.prepare(`INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, metadata_json, request_id, created_at)
        VALUES (?1, ?2, 'ADMIN_USER_CREATED', 'USER', ?3, ?4, ?5, ?6)`)
        .bind(crypto.randomUUID(), c.get('authUser')!.id, id, JSON.stringify({ role: body.data.role }), c.get('requestId'), now)
    ]);
  } catch (error) {
    if (!/UNIQUE constraint failed: users\.(email|public_user_id)/i.test(String(error))) throw error;
    return apiError(c, 409, 'USER_EXISTS', 'A user with that email or public user ID already exists.');
  }
  let welcomeEmailSent = false;
  try {
    await sendWelcome(c.env, email, publicUserId, password, ticket.token);
    welcomeEmailSent = true;
  } catch {
    console.error(JSON.stringify({ event: 'welcome_email_failed', requestId: c.get('requestId') }));
  }
  return ok(c, { id, publicUserId, email, role: body.data.role, status: 'ACTIVE', welcomeEmailSent }, 201);
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
    const db = c.env.DB;
    const email = body.data.email?.trim().toLowerCase() ?? null;
    const now = new Date().toISOString();
    await withUserSettings(db, () => db.batch([
      db.prepare(`INSERT INTO incoming_user_settings (user_id, credential_version)
        SELECT id,1 FROM users WHERE id=?1 AND email<>?2
        ON CONFLICT(user_id) DO UPDATE SET credential_version=credential_version+1`).bind(c.req.param('id'), email),
      db.prepare(`UPDATE auth_sessions SET revoked_at=?3 WHERE user_id=?1 AND revoked_at IS NULL
        AND EXISTS (SELECT 1 FROM users WHERE id=?1 AND email<>?2)`).bind(c.req.param('id'), email, now),
      db.prepare(`UPDATE password_reset_tokens SET used_at=coalesce(used_at,?3),
        expires_at=CASE WHEN id='welcome:'||user_id THEN min(expires_at,?3) ELSE expires_at END
        WHERE user_id=?1 AND (used_at IS NULL OR id='welcome:'||user_id)
        AND EXISTS (SELECT 1 FROM users WHERE id=?1 AND email<>?2)`).bind(c.req.param('id'), email, now),
      db.prepare(`UPDATE users SET email=coalesce(?2,email), public_user_id=coalesce(?3,public_user_id), updated_at=?4 WHERE id=?1`)
        .bind(c.req.param('id'), email, body.data.publicUserId ?? null, now)
    ]));
  } catch { return apiError(c, 409, 'CONFLICT', 'Email or public user ID already in use.'); }
  await audit(c.env.DB, { actorUserId: c.get('authUser')!.id, action: 'ADMIN_USER_UPDATED', targetType: 'USER', targetId: c.req.param('id'), requestId: c.get('requestId') });
  return ok(c, { updated: true });
});

const resetSchema = createSchema.pick({ password: true }).required();
app.post('/users/:id/reset-password', async c => {
  const body = await jsonBody(c, resetSchema);
  if ('error' in body) return body.error;
  const userId = c.req.param('id');
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(body.data.password);
  const db = c.env.DB;
  const [updated] = await withUserSettings(db, () => db.batch([
    db.prepare(`UPDATE users SET password_hash=?2, force_password_change=0, updated_at=?3 WHERE id=?1`)
      .bind(userId, passwordHash, now),
    db.prepare(`INSERT INTO incoming_user_settings (user_id, credential_version)
      SELECT id, 1 FROM users WHERE id=?1
      ON CONFLICT(user_id) DO UPDATE SET credential_version=credential_version+1`).bind(userId),
    db.prepare(`UPDATE auth_sessions SET revoked_at=?2 WHERE user_id=?1 AND revoked_at IS NULL`).bind(userId, now),
    db.prepare(`INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, request_id, created_at)
      SELECT ?1, ?2, 'ADMIN_PASSWORD_RESET', 'USER', id, ?3, ?4 FROM users WHERE id=?5`)
      .bind(crypto.randomUUID(), c.get('authUser')!.id, c.get('requestId'), now, userId)
  ]));
  if (!updated?.meta.changes) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
  return ok(c, { updated: true });
});

app.post('/users/:id/disable', async c => {
  if (c.get('authUser')!.id === c.req.param('id')) return apiError(c, 409, 'SELF_DISABLE_BLOCKED', 'You cannot disable your own account here.');
  const db = c.env.DB;
  const id = c.req.param('id');
  const now = new Date().toISOString();
  const [, result] = await withUserSettings(db, () => db.batch([
    db.prepare(`INSERT INTO incoming_user_settings (user_id, credential_version)
      SELECT id,1 FROM users WHERE id=?1 AND status='ACTIVE'
      ON CONFLICT(user_id) DO UPDATE SET credential_version=credential_version+1`).bind(id),
    db.prepare("UPDATE users SET status='DISABLED', updated_at=?2 WHERE id=?1").bind(id, now),
    db.prepare('UPDATE auth_sessions SET revoked_at=?2 WHERE user_id=?1 AND revoked_at IS NULL').bind(id, now),
    db.prepare('UPDATE password_reset_tokens SET used_at=?2 WHERE user_id=?1 AND used_at IS NULL').bind(id, now)
  ]));
  if (!result?.meta.changes) return apiError(c, 404, 'NOT_FOUND', 'User not found.');
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
