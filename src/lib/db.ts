import { withUserSettings } from './userSettings';
import type { AuthUser } from '../types/env';

export type UserRow = {
  id: string;
  public_user_id: string;
  email: string;
  password_hash: string;
  credential_version: number;
  role: 'ADMIN' | 'MAGICIAN';
  status: 'ACTIVE' | 'DISABLED';
  force_password_change: number;
  temporary_password_expires_at: string | null;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
};

export function toAuthUser(row: UserRow): AuthUser {
  return {
    id: row.id,
    publicUserId: row.public_user_id,
    email: row.email,
    role: row.role,
    status: row.status
  };
}

export function hasActiveCredentials(row: UserRow) {
  return row.status === 'ACTIVE' && (!row.temporary_password_expires_at || Date.parse(row.temporary_password_expires_at) > Date.now());
}

const authUserQuery = `SELECT u.*, COALESCE(s.credential_version, 0) AS credential_version,
  CASE WHEN u.force_password_change=1 THEN
    (SELECT expires_at FROM password_reset_tokens WHERE id='welcome:'||u.id)
  END AS temporary_password_expires_at
  FROM users u LEFT JOIN incoming_user_settings s ON s.user_id=u.id`;

export async function findUserByLogin(db: D1Database, login: string): Promise<UserRow | null> {
  const identifier = login.trim();
  const { results } = await withUserSettings(db, () => db.prepare(`${authUserQuery}
    WHERE lower(u.email)=?1 OR lower(u.public_user_id)=?1
    ORDER BY (u.public_user_id=?2) DESC LIMIT 2`).bind(identifier.toLowerCase(), identifier).all<UserRow>());
  // Public IDs are case-sensitive in D1. Accept alternate casing only if it identifies one user.
  const [candidate] = results;
  if (candidate && (results.length === 1 || candidate.public_user_id === identifier)) return candidate;
  return null;
}

export function findUserById(db: D1Database, id: string): Promise<UserRow | null> {
  return withUserSettings(db, () => db.prepare(`${authUserQuery} WHERE u.id=?1 LIMIT 1`).bind(id).first<UserRow>());
}

export async function audit(db: D1Database, entry: {
  actorUserId?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown> | null;
  requestId?: string | null;
}) {
  await db.prepare(`INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, metadata_json, request_id, created_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`)
    .bind(
      crypto.randomUUID(), entry.actorUserId ?? null, entry.action, entry.targetType ?? null,
      entry.targetId ?? null, entry.metadata ? JSON.stringify(entry.metadata) : null,
      entry.requestId ?? null, new Date().toISOString()
    ).run();
}
