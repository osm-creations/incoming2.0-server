import type { AuthUser } from '../types/env';

export type UserRow = {
  id: string;
  public_user_id: string;
  email: string;
  password_hash: string;
  role: 'ADMIN' | 'MAGICIAN';
  status: 'ACTIVE' | 'DISABLED';
  force_password_change: number;
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

export async function findUserByLogin(db: D1Database, login: string): Promise<UserRow | null> {
  const normalized = login.trim().toLowerCase();
  return db.prepare(`SELECT * FROM users WHERE lower(email) = ?1 OR lower(public_user_id) = ?1 LIMIT 1`)
    .bind(normalized).first<UserRow>();
}

export async function findUserById(db: D1Database, id: string): Promise<UserRow | null> {
  return db.prepare(`SELECT * FROM users WHERE id = ?1 LIMIT 1`).bind(id).first<UserRow>();
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
