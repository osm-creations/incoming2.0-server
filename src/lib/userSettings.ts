export const defaultRevealDelaySeconds = 5;
const revealDelayColumn = `reveal_delay_seconds INTEGER NOT NULL DEFAULT ${defaultRevealDelaySeconds}
  CHECK (typeof(reveal_delay_seconds) = 'integer' AND reveal_delay_seconds BETWEEN 0 AND 60)`;

const settingsTable = `CREATE TABLE IF NOT EXISTS incoming_user_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  caller_name TEXT,
  inject_user_id TEXT,
  credential_version INTEGER NOT NULL DEFAULT 0,
  ${revealDelayColumn}
)`;

function databaseMessage(error: unknown) {
  return `${error} ${error instanceof Error ? error.cause : ''}`;
}

// Git-connected deploys do not apply D1 migrations. Upgrade existing settings
// in place on first use, including when requests from two isolates overlap.
export async function withUserSettings<T>(db: D1Database, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const message = databaseMessage(error);
    if (/no such table: (?:main\.)?incoming_user_settings\b/i.test(message)) {
      await db.prepare(settingsTable).run();
    } else if (/no such column: reveal_delay_seconds\b|incoming_user_settings has no column named reveal_delay_seconds\b/i.test(message)) {
      try {
        await db.prepare(`ALTER TABLE incoming_user_settings ADD COLUMN ${revealDelayColumn}`).run();
      } catch (upgradeError) {
        if (!/duplicate column name: reveal_delay_seconds\b/i.test(databaseMessage(upgradeError))) throw upgradeError;
      }
    } else {
      throw error;
    }
    return operation();
  }
}

export type UserSettings = {
  caller_name: string | null;
  inject_user_id: string | null;
  reveal_delay_seconds: number;
};

export function usesPlainPresentation(configuredAccount: string | undefined, publicUserId: string, email: string): true | undefined {
  const account = configuredAccount?.trim();
  if (!account) return undefined;
  // Emails are stored in lowercase. Public IDs are unique with case-sensitive comparison.
  const matches = account.includes('@') ? account.toLowerCase() === email : account === publicUserId;
  return matches || undefined;
}

export function effectiveCallerName(stored: string | null | undefined, note: string | null): string | null {
  // SQL NULL denotes a legacy account. An explicit empty string clears the name.
  if (stored != null) return stored || null;
  const name = note?.split(/[\n\r\u0085\u2028\u2029]/u).map(line => line.trim()).find(Boolean);
  return name?.slice(0, 120) || null;
}

export function loadUserSettings(db: D1Database, id: string) {
  return withUserSettings(db, () => db.prepare(
    'SELECT caller_name, inject_user_id, reveal_delay_seconds FROM incoming_user_settings WHERE user_id=?1'
  ).bind(id).first<UserSettings>());
}
