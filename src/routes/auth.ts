import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { z } from 'zod';
import type { Bindings, Variables } from '../types/env';
import { apiError, jsonBody, ok } from '../lib/http';
import { audit, findUserById, findUserByLogin, hasActiveCredentials, toAuthUser } from '../lib/db';
import { clearLoginFailures, assertLoginAllowed, recordLoginFailure } from '../lib/rateLimit';
import { hashOpaqueToken, issueAccessToken, newRefreshToken, verifyPassword } from '../lib/security';
import { randomToken } from '../lib/encoding';
import { redeemPasswordTicket, sendForgotPassword, takePasswordAttempt } from '../lib/passwordRecovery';
import { authMiddleware } from '../middleware/core';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const forgotSchema = z.object({ email: z.string().trim().email().max(254) });
const newPasswordSchema = z.object({ token: z.string().min(1).max(256), password: z.string().min(12).max(200) });

app.post('/forgot-password', async c => {
  const body = await jsonBody(c, forgotSchema);
  if ('error' in body) return body.error;
  const email = body.data.email.toLowerCase();
  const ip = c.req.header('CF-Connecting-IP') ?? 'local';
  const env = c.env;
  const requestId = c.get('requestId');
  if (await takePasswordAttempt(env, 'forgot-ip', ip, 12)
      && await takePasswordAttempt(env, 'forgot-email', email, 3)) {
    // Response timing and content must not reveal whether we found the account.
    c.executionCtx.waitUntil(sendForgotPassword(env, email).catch(() =>
      console.error(JSON.stringify({ event: 'password_reset_email_failed', requestId }))));
  }
  c.header('Cache-Control', 'no-store');
  return ok(c, { message: 'If an active account uses that email, you will receive a password reset link.' });
});

app.post('/reset-password', async c => {
  const body = await jsonBody(c, newPasswordSchema);
  if ('error' in body) return body.error;
  c.header('Cache-Control', 'no-store');
  if (!await takePasswordAttempt(c.env, 'redeem-ip', c.req.header('CF-Connecting-IP') ?? 'local', 30)) {
    c.header('Retry-After', '3600');
    return apiError(c, 429, 'RATE_LIMITED', 'Too many attempts. Please try again later.');
  }
  if (!await redeemPasswordTicket(c.env, body.data.token, body.data.password, c.get('requestId'))) {
    return apiError(c, 400, 'RESET_LINK_INVALID', 'This link is invalid or has expired. Request a new password reset email.');
  }
  return ok(c, { updated: true });
});

const loginSchema = z.object({
  login: z.string().trim().min(3).max(254),
  password: z.string().min(8).max(200),
  client: z.enum(['ios', 'web']).default('ios')
});

app.post('/login', async c => {
  const body = await jsonBody(c, loginSchema);
  if ('error' in body) return body.error;
  const ip = c.req.header('CF-Connecting-IP') ?? 'local';
  const rateKey = `${ip}:${body.data.login.trim().toLowerCase()}`;
  const allowed = await assertLoginAllowed(c.env.DB, rateKey);
  if (!allowed.allowed) {
    c.header('Retry-After', String(allowed.retryAfter ?? 60));
    return apiError(c, 429, 'RATE_LIMITED', 'Too many login attempts. Try again later.');
  }

  const row = await findUserByLogin(c.env.DB, body.data.login);
  const valid = row ? await verifyPassword(body.data.password, row.password_hash) : false;
  if (!row || !valid || !hasActiveCredentials(row)) {
    await recordLoginFailure(c.env.DB, rateKey);
    return apiError(c, 401, 'INVALID_CREDENTIALS', 'Invalid user ID/email or password.');
  }
  await clearLoginFailures(c.env.DB, rateKey);

  const user = toAuthUser(row);
  const accessToken = await issueAccessToken(user, c.env, row.credential_version);
  const refreshToken = newRefreshToken();
  const refreshHash = await hashOpaqueToken(refreshToken, c.env.TOKEN_PEPPER);
  const sessionId = crypto.randomUUID();
  const now = new Date();
  const refreshExpires = new Date(Date.now() + Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') * 1000);
  const [created] = await c.env.DB.batch([
    c.env.DB.prepare(`INSERT INTO auth_sessions (id, user_id, refresh_token_hash, token_family_id, expires_at, created_at)
      SELECT ?1, ?2, ?3, ?4, ?5, ?6 FROM users WHERE id=?2 AND password_hash=?7 AND status='ACTIVE'
      AND COALESCE((SELECT credential_version FROM incoming_user_settings WHERE user_id=?2),0)=?8
      AND (force_password_change=0 OR NOT EXISTS (SELECT 1 FROM password_reset_tokens
        WHERE id='welcome:'||?2 AND expires_at<=strftime('%Y-%m-%dT%H:%M:%fZ','now')))`)
      .bind(sessionId, user.id, refreshHash, crypto.randomUUID(), refreshExpires.toISOString(), now.toISOString(), row.password_hash, row.credential_version),
    c.env.DB.prepare(`UPDATE users SET last_login_at=?2, updated_at=?2 WHERE id=?1
      AND EXISTS (SELECT 1 FROM auth_sessions WHERE id=?3 AND user_id=?1)`).bind(user.id, now.toISOString(), sessionId)
  ]);
  if (!created?.meta.changes) return apiError(c, 401, 'INVALID_CREDENTIALS', 'Please sign in again.');
  await audit(c.env.DB, { actorUserId: user.id, action: 'AUTH_LOGIN', targetType: 'USER', targetId: user.id, requestId: c.get('requestId') });

  if (body.data.client === 'web') {
    const csrf = randomToken(24);
    const secure = new URL(c.req.url).protocol === 'https:';
    setCookie(c, 'access_token', accessToken, { httpOnly: true, secure, sameSite: 'Lax', path: '/', maxAge: Number(c.env.ACCESS_TOKEN_TTL_SECONDS || '900') });
    setCookie(c, 'refresh_token', refreshToken, { httpOnly: true, secure, sameSite: 'Lax', path: '/api/v1/auth', maxAge: Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') });
    setCookie(c, 'csrf_token', csrf, { httpOnly: false, secure, sameSite: 'Lax', path: '/', maxAge: Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') });
    // The CSRF cookie is intentionally host-only on the API domain. The admin
    // app may run on a sibling subdomain, so return the same non-secret token
    // in the authenticated login response instead of requiring document.cookie.
    return ok(c, { user, forcePasswordChange: Boolean(row.force_password_change), csrfToken: csrf });
  }

  return ok(c, { accessToken, refreshToken, expiresIn: Number(c.env.ACCESS_TOKEN_TTL_SECONDS || '900'), user, forcePasswordChange: Boolean(row.force_password_change) });
});

const refreshSchema = z.object({ refreshToken: z.string().min(20).optional() });
app.post('/refresh', async c => {
  let bodyToken: string | undefined;
  try { bodyToken = refreshSchema.parse(await c.req.json()).refreshToken; } catch { /* web cookie mode */ }
  const presented = bodyToken ?? getCookie(c, 'refresh_token');
  if (!presented) return apiError(c, 401, 'INVALID_REFRESH', 'Session expired.');
  const tokenHash = await hashOpaqueToken(presented, c.env.TOKEN_PEPPER);
  const session = await c.env.DB.prepare(`SELECT * FROM auth_sessions WHERE refresh_token_hash = ?1 LIMIT 1`).bind(tokenHash).first<{ id: string; user_id: string; token_family_id: string; expires_at: string; revoked_at: string | null }>();
  if (!session || session.revoked_at || Date.parse(session.expires_at) <= Date.now()) return apiError(c, 401, 'INVALID_REFRESH', 'Session expired.');
  const row = await findUserById(c.env.DB, session.user_id);
  if (!row || !hasActiveCredentials(row)) return apiError(c, 401, 'INVALID_REFRESH', 'Session expired.');

  const newRefresh = newRefreshToken();
  const newHash = await hashOpaqueToken(newRefresh, c.env.TOKEN_PEPPER);
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') * 1000).toISOString();
  const [rotated] = await c.env.DB.batch([
    c.env.DB.prepare(`INSERT INTO auth_sessions (id, user_id, refresh_token_hash, token_family_id, expires_at, created_at)
      SELECT ?1, user_id, ?2, token_family_id, ?3, ?4 FROM auth_sessions
      WHERE id=?5 AND revoked_at IS NULL AND expires_at>?4`)
      .bind(crypto.randomUUID(), newHash, expiresAt, now, session.id),
    c.env.DB.prepare(`UPDATE auth_sessions SET revoked_at=?2, last_used_at=?2 WHERE id=?1 AND revoked_at IS NULL`).bind(session.id, now)
  ]);
  if (!rotated?.meta.changes) return apiError(c, 401, 'INVALID_REFRESH', 'Session expired.');
  const user = toAuthUser(row);
  const accessToken = await issueAccessToken(user, c.env, row.credential_version);

  if (!bodyToken) {
    const secure = new URL(c.req.url).protocol === 'https:';
    let csrf = getCookie(c, 'csrf_token');
    if (!csrf) {
      csrf = randomToken(24);
      setCookie(c, 'csrf_token', csrf, { httpOnly: false, secure, sameSite: 'Lax', path: '/', maxAge: Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') });
    }
    setCookie(c, 'access_token', accessToken, { httpOnly: true, secure, sameSite: 'Lax', path: '/', maxAge: Number(c.env.ACCESS_TOKEN_TTL_SECONDS || '900') });
    setCookie(c, 'refresh_token', newRefresh, { httpOnly: true, secure, sameSite: 'Lax', path: '/api/v1/auth', maxAge: Number(c.env.REFRESH_TOKEN_TTL_SECONDS || '2592000') });
    return ok(c, { user, csrfToken: csrf });
  }
  return ok(c, { accessToken, refreshToken: newRefresh, expiresIn: Number(c.env.ACCESS_TOKEN_TTL_SECONDS || '900'), user });
});

app.post('/logout', async c => {
  let presented: string | undefined;
  try { presented = (await c.req.json() as { refreshToken?: string }).refreshToken; } catch { presented = getCookie(c, 'refresh_token'); }
  if (presented) {
    const hash = await hashOpaqueToken(presented, c.env.TOKEN_PEPPER);
    await c.env.DB.prepare(`UPDATE auth_sessions SET revoked_at = ?2 WHERE refresh_token_hash = ?1 AND revoked_at IS NULL`).bind(hash, new Date().toISOString()).run();
  }
  deleteCookie(c, 'access_token', { path: '/' });
  deleteCookie(c, 'refresh_token', { path: '/api/v1/auth' });
  deleteCookie(c, 'csrf_token', { path: '/' });
  return ok(c, { loggedOut: true });
});


app.get('/csrf', authMiddleware, async c => {
  const csrf = getCookie(c, 'csrf_token');
  if (!csrf) return apiError(c, 403, 'CSRF_UNAVAILABLE', 'CSRF token is unavailable. Please sign in again.');
  return ok(c, { csrfToken: csrf });
});

app.get('/me', authMiddleware, async c => ok(c, { user: c.get('authUser') }));

export default app;
