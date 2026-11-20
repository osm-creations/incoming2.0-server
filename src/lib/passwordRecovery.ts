import type { Bindings } from '../types/env';
import { randomToken, timingSafeEqual, utf8 } from './encoding';
import { hashOpaqueToken, hashPassword, hmacSignature } from './security';
import { withUserSettings } from './userSettings';
import { sendMail } from './smtp';
import { resetSite } from './resetSite';

const hour = 60 * 60 * 1000;
const welcomeLifetime = 7 * 24 * hour;

type Account = { id: string; email: string; credential_version: number };

function signature(env: Bindings, user: Account, nonce: string) {
  return hmacSignature(JSON.stringify(['incoming-password-v1', nonce, user.id, user.email, user.credential_version]), env.TOKEN_PEPPER);
}

export async function newPasswordTicket(env: Bindings, user: Account, welcome = false) {
  const nonce = randomToken(32);
  const [digest, proof] = await Promise.all([hashOpaqueToken(nonce, env.TOKEN_PEPPER), signature(env, user, nonce)]);
  const now = Date.now();
  const statement = env.DB.prepare(`INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
    SELECT ?1, id, ?3, ?4, ?5 FROM users WHERE id=?2 AND email=?6 AND status='ACTIVE'
    AND coalesce((SELECT credential_version FROM incoming_user_settings WHERE user_id=?2),0)=?7`)
    .bind(welcome ? 'welcome:' + user.id : crypto.randomUUID(), user.id, digest,
      new Date(now + (welcome ? welcomeLifetime : hour)).toISOString(), new Date(now).toISOString(), user.email, user.credential_version);
  return { statement, token: nonce + '.' + proof };
}

function resetLink(env: Bindings, token: string) {
  const url = resetSite(env);
  if (!url) throw new Error('Invalid reset page configuration');
  url.hash = new URLSearchParams({ token }).toString();
  return url.href;
}

export function sendWelcome(env: Bindings, email: string, publicUserId: string, password: string, token: string) {
  return sendMail(env, {
    to: email, subject: 'Your Incoming account',
    text: `Welcome to Incoming.\n\nUser ID: ${publicUserId}\nTemporary password: ${password}\n\nSet your own password within 7 days:\n${resetLink(env, token)}\n\nThe temporary password and this link expire in 7 days. Once you choose a password, use it to sign in.`
  });
}

export async function sendForgotPassword(env: Bindings, email: string) {
  const user = await withUserSettings(env.DB, () => env.DB.prepare(`SELECT u.id, u.email, coalesce(s.credential_version, 0) AS credential_version
    FROM users u LEFT JOIN incoming_user_settings s ON s.user_id=u.id
    WHERE u.email=?1 AND u.status='ACTIVE'`).bind(email).first<Account>());
  if (!user) return;
  const ticket = await newPasswordTicket(env, user);
  const link = resetLink(env, ticket.token);
  // Welcome rows also record the lifetime of current temporary credentials.
  const [, issued] = await env.DB.batch([
    env.DB.prepare("DELETE FROM password_reset_tokens WHERE user_id=?1 AND id != ?2 AND (expires_at<=?3 OR used_at IS NOT NULL)")
      .bind(user.id, 'welcome:' + user.id, new Date().toISOString()),
    ticket.statement
  ]);
  if (!issued?.meta.changes) return;
  await sendMail(env, {
    to: user.email, subject: 'Reset your Incoming password',
    text: `Someone requested a password reset for your Incoming account.\n\nChoose a new password using this link within 1 hour:\n${link}\n\nIf you did not request this, you can ignore this email. Your current password still works.`
  });
}

// The conditional UPSERT counts concurrent requests in the same window atomically.
export async function takePasswordAttempt(env: Bindings, scope: string, identifier: string, limit: number) {
  const key = 'recovery:' + scope + ':' + await hashOpaqueToken(identifier, env.TOKEN_PEPPER);
  const now = Date.now();
  const cutoff = new Date(now - hour).toISOString();
  const row = await env.DB.prepare(`INSERT INTO login_rate_limits (rate_key, attempts, window_started_at) VALUES (?1, 1, ?2)
    ON CONFLICT(rate_key) DO UPDATE SET
      attempts=CASE WHEN window_started_at<=?3 THEN 1 ELSE attempts+1 END,
      window_started_at=CASE WHEN window_started_at<=?3 THEN excluded.window_started_at ELSE window_started_at END
    WHERE window_started_at<=?3 OR attempts<?4`).bind(key, new Date(now).toISOString(), cutoff, limit).run();
  // Reclaim anonymous rate buckets after their window even when an address never returns.
  if (crypto.getRandomValues(new Uint8Array(1))[0]! < 8) {
    await env.DB.prepare(`DELETE FROM login_rate_limits WHERE rate_key IN
      (SELECT rate_key FROM login_rate_limits WHERE rate_key GLOB 'recovery:*' AND window_started_at<=?1 LIMIT 128)`)
      .bind(cutoff).run();
  }
  return row.meta.changes === 1;
}

export async function redeemPasswordTicket(env: Bindings, token: string, password: string, requestId: string) {
  if (!/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const [nonce, proof] = token.split('.') as [string, string];
  const digest = await hashOpaqueToken(nonce, env.TOKEN_PEPPER);
  const db = env.DB;
  const user = await withUserSettings(db, () => db.prepare(`SELECT u.id, u.email, coalesce(s.credential_version,0) AS credential_version
    FROM password_reset_tokens t JOIN users u ON u.id=t.user_id LEFT JOIN incoming_user_settings s ON s.user_id=u.id
    WHERE t.token_hash=?1 AND t.used_at IS NULL AND t.expires_at>?2 AND u.status='ACTIVE'`)
    .bind(digest, new Date().toISOString()).first<Account>());
  if (!user || !timingSafeEqual(utf8(proof), utf8(await signature(env, user, nonce)))) return false;

  // The new salted hash is unique to this redemption. The other statements
  // in the D1 transaction only run for the request that won the first UPDATE.
  const newHash = await hashPassword(password);
  const now = new Date().toISOString();
  const changedUser = 'SELECT id FROM users WHERE id=?1 AND password_hash=?2';
  const [changed] = await db.batch([
    db.prepare(`UPDATE users SET password_hash=?2, force_password_change=0, updated_at=?3
      WHERE id=?1 AND status='ACTIVE' AND email=?4
      AND coalesce((SELECT credential_version FROM incoming_user_settings WHERE user_id=?1),0)=?5
      AND EXISTS (SELECT 1 FROM password_reset_tokens WHERE token_hash=?6 AND user_id=?1 AND used_at IS NULL AND expires_at>?3)`)
      .bind(user.id, newHash, now, user.email, user.credential_version, digest),
    db.prepare(`INSERT INTO incoming_user_settings (user_id, credential_version)
      SELECT id, 1 FROM users WHERE id=?1 AND password_hash=?2
      ON CONFLICT(user_id) DO UPDATE SET credential_version=credential_version+1`).bind(user.id, newHash),
    db.prepare(`UPDATE auth_sessions SET revoked_at=?3 WHERE user_id IN (${changedUser}) AND revoked_at IS NULL`).bind(user.id, newHash, now),
    db.prepare(`UPDATE password_reset_tokens SET used_at=?3 WHERE user_id IN (${changedUser}) AND used_at IS NULL`).bind(user.id, newHash, now),
    db.prepare(`INSERT INTO audit_logs (id, action, target_type, target_id, request_id, created_at)
      SELECT ?3,'EMAIL_PASSWORD_SET','USER',id,?4,?5 FROM users WHERE id=?1 AND password_hash=?2`)
      .bind(user.id, newHash, crypto.randomUUID(), requestId, now)
  ]);
  return changed?.meta.changes === 1;
}
