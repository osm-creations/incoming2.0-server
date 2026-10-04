import { createMiddleware } from 'hono/factory';
import { getCookie } from 'hono/cookie';
import { verifyAccessToken } from '../lib/security';
import { findUserById, toAuthUser } from '../lib/db';
import { apiError } from '../lib/http';
import type { Bindings, Variables } from '../types/env';

export const requestIdMiddleware = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  c.set('requestId', crypto.randomUUID());
  c.header('X-Request-Id', c.get('requestId'));
  await next();
});

export const authMiddleware = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  const auth = c.req.header('Authorization');
  const token = auth?.startsWith('Bearer ') ? auth.slice(7) : getCookie(c, 'access_token');
  if (!token) return apiError(c, 401, 'UNAUTHENTICATED', 'Authentication required.');
  try {
    const payload = await verifyAccessToken(token, c.env);
    const sub = typeof payload.sub === 'string' ? payload.sub : null;
    if (!sub) return apiError(c, 401, 'INVALID_TOKEN', 'Authentication required.');
    const row = await findUserById(c.env.DB, sub);
    if (!row || row.status !== 'ACTIVE') return apiError(c, 401, 'ACCOUNT_UNAVAILABLE', 'Authentication required.');
    c.set('authUser', toAuthUser(row));
    await next();
  } catch {
    return apiError(c, 401, 'INVALID_TOKEN', 'Authentication required.');
  }
});

export const adminOnly = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  const user = c.get('authUser');
  if (!user || user.role !== 'ADMIN') return apiError(c, 403, 'FORBIDDEN', 'Admin access required.');
  await next();
});

export const magicianOnly = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  const user = c.get('authUser');
  if (!user || (user.role !== 'MAGICIAN' && user.role !== 'ADMIN')) return apiError(c, 403, 'FORBIDDEN', 'Magician access required.');
  await next();
});

export const adminCsrf = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) return next();
  const cookie = getCookie(c, 'csrf_token');
  const header = c.req.header('X-CSRF-Token');
  if (!cookie || !header || cookie !== header) return apiError(c, 403, 'CSRF_FAILED', 'Request could not be verified.');
  await next();
});
