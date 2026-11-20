import type { Bindings } from '../types/env';
import { hashOpaqueToken, shortCapability } from './security';

const shortLinksTable = `CREATE TABLE IF NOT EXISTS incoming_short_links (
  config_id TEXT PRIMARY KEY REFERENCES clip_configs(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE
)`;

function missingShortLinksTable(error: unknown) {
  return /no such table: (?:main\.)?incoming_short_links\b/i.test(`${error} ${error instanceof Error ? error.cause : ''}`);
}

export async function shortInvocationUrl(env: Bindings, configId: string, version: number) {
  const token = await shortCapability(configId, version, env);
  const hash = await hashOpaqueToken(token, env.CAPABILITY_SIGNING_SECRET);
  const register = () => env.DB.prepare(`INSERT INTO incoming_short_links(config_id, version, token_hash)
    SELECT id, ?2, ?3 FROM clip_configs WHERE id=?1 AND capability_version=?2
    ON CONFLICT(config_id) DO UPDATE SET version=excluded.version, token_hash=excluded.token_hash
    WHERE version!=excluded.version OR token_hash!=excluded.token_hash`).bind(configId, version, hash).run();
  try {
    await register();
  } catch (error) {
    if (!missingShortLinksTable(error)) throw error;
    await env.DB.prepare(shortLinksTable).run();
    await register();
  }
  return `${env.PUBLIC_BASE_URL.replace(/\/$/, '')}/c/${token}`;
}

export type ClipIdentity = { configId: string; version: number };

// A missing table means no compact tag has been issued on this database yet.
export async function resolveShortCapability(env: Bindings, token: string) {
  const hash = await hashOpaqueToken(token, env.CAPABILITY_SIGNING_SECRET);
  try {
    return await env.DB.prepare('SELECT config_id AS configId, version FROM incoming_short_links WHERE token_hash=?1')
      .bind(hash).first<ClipIdentity>();
  } catch (error) {
    if (!missingShortLinksTable(error)) throw error;
    return null;
  }
}
