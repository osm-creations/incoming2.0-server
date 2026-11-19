const settingsTable = `CREATE TABLE IF NOT EXISTS incoming_user_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  caller_name TEXT,
  inject_user_id TEXT,
  credential_version INTEGER NOT NULL DEFAULT 0
)`;

// Existing D1 databases acquire the additive table on first use. Wrangler's
// Git-connected deploy does not apply D1 migrations automatically.
export async function withUserSettings<T>(db: D1Database, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const cause = error instanceof Error ? error.cause : null;
    if (!/no such table: (?:main\.)?incoming_user_settings\b/i.test(`${error} ${cause}`)) throw error;
    await db.prepare(settingsTable).run();
    return operation();
  }
}

export type UserSettings = {
  caller_name: string | null;
  inject_user_id: string | null;
};

export function effectiveCallerName(stored: string | null | undefined, note: string | null): string | null {
  // SQL NULL denotes a legacy account. An explicit empty string clears the name.
  if (stored != null) return stored || null;
  const name = note?.split(/[\n\r\u0085\u2028\u2029]/u).map(line => line.trim()).find(Boolean);
  return name?.slice(0, 120) || null;
}

export function loadUserSettings(db: D1Database, id: string) {
  return withUserSettings(db, () => db.prepare(
    'SELECT caller_name, inject_user_id FROM incoming_user_settings WHERE user_id=?1'
  ).bind(id).first<UserSettings>());
}
