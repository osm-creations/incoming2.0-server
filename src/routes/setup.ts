import { Hono } from 'hono';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { apiError, jsonBody, ok } from '../lib/http';
import { hashPassword } from '../lib/security';
import { audit } from '../lib/db';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
const schema = z.object({ publicUserId: z.string().min(3).max(64).regex(/^[A-Za-z0-9_-]+$/), email: z.string().email(), password: z.string().min(12).max(200) });

app.post('/admin', async c => {
  if (c.req.header('X-Setup-Secret') !== c.env.SETUP_SECRET) return apiError(c, 404, 'NOT_FOUND', 'Not found.');
  const existing = await c.env.DB.prepare(`SELECT COUNT(*) count FROM users WHERE role='ADMIN'`).first<{ count: number }>();
  if ((existing?.count ?? 0) > 0) return apiError(c, 409, 'ALREADY_INITIALIZED', 'An admin account already exists.');
  const body = await jsonBody(c, schema);
  if ('error' in body) return body.error;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await c.env.DB.prepare(`INSERT INTO users (id, public_user_id, email, password_hash, role, status, force_password_change, created_at, updated_at)
    VALUES (?1, ?2, ?3, ?4, 'ADMIN', 'ACTIVE', 0, ?5, ?5)`)
    .bind(id, body.data.publicUserId, body.data.email.toLowerCase(), await hashPassword(body.data.password), now).run();
  await audit(c.env.DB, { actorUserId: id, action: 'SYSTEM_INITIAL_ADMIN_CREATED', targetType: 'USER', targetId: id, requestId: c.get('requestId') });
  return ok(c, { created: true, id, publicUserId: body.data.publicUserId }, 201);
});

export default app;
