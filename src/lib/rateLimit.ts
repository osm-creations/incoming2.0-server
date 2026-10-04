export async function assertLoginAllowed(db: D1Database, key: string): Promise<{ allowed: boolean; retryAfter?: number }> {
  const now = Date.now();
  const row = await db.prepare(`SELECT attempts, window_started_at, blocked_until FROM login_rate_limits WHERE rate_key = ?1`).bind(key).first<{ attempts: number; window_started_at: string; blocked_until: string | null }>();
  if (!row) return { allowed: true };
  if (row.blocked_until) {
    const blockedUntil = Date.parse(row.blocked_until);
    if (blockedUntil > now) return { allowed: false, retryAfter: Math.ceil((blockedUntil - now) / 1000) };
  }
  if (now - Date.parse(row.window_started_at) > 15 * 60 * 1000) {
    await db.prepare(`DELETE FROM login_rate_limits WHERE rate_key = ?1`).bind(key).run();
  }
  return { allowed: true };
}

export async function recordLoginFailure(db: D1Database, key: string) {
  const now = new Date();
  const row = await db.prepare(`SELECT attempts, window_started_at FROM login_rate_limits WHERE rate_key = ?1`).bind(key).first<{ attempts: number; window_started_at: string }>();
  if (!row || Date.now() - Date.parse(row.window_started_at) > 15 * 60 * 1000) {
    await db.prepare(`INSERT INTO login_rate_limits (rate_key, attempts, window_started_at, blocked_until) VALUES (?1, 1, ?2, NULL)
      ON CONFLICT(rate_key) DO UPDATE SET attempts = 1, window_started_at = excluded.window_started_at, blocked_until = NULL`)
      .bind(key, now.toISOString()).run();
    return;
  }
  const attempts = row.attempts + 1;
  const blockedUntil = attempts >= 5 ? new Date(Date.now() + Math.min(30, attempts * 2) * 60 * 1000).toISOString() : null;
  await db.prepare(`UPDATE login_rate_limits SET attempts = ?2, blocked_until = ?3 WHERE rate_key = ?1`)
    .bind(key, attempts, blockedUntil).run();
}

export async function clearLoginFailures(db: D1Database, key: string) {
  await db.prepare(`DELETE FROM login_rate_limits WHERE rate_key = ?1`).bind(key).run();
}
