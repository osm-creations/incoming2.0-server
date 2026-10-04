PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  public_user_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('ADMIN','MAGICIAN')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','DISABLED')),
  force_password_change INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  token_family_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_family ON auth_sessions(token_family_id);

CREATE TABLE IF NOT EXISTS clip_configs (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  public_config_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK(mode IN ('MENU','STATIC','DIRECT_NOTES')),
  enabled INTEGER NOT NULL DEFAULT 1,
  static_text TEXT,
  open_overflow_initially INTEGER NOT NULL DEFAULT 0,
  capability_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_clip_configs_owner ON clip_configs(owner_user_id);

CREATE TABLE IF NOT EXISTS clip_menu_options (
  id TEXT PRIMARY KEY,
  config_id TEXT NOT NULL,
  value TEXT NOT NULL,
  display_order INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(config_id) REFERENCES clip_configs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_clip_options_config_order ON clip_menu_options(config_id, display_order);

CREATE TABLE IF NOT EXISTS app_clip_sessions (
  id TEXT PRIMARY KEY,
  public_session_id TEXT NOT NULL UNIQUE,
  config_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  session_token_hash TEXT NOT NULL UNIQUE,
  selected_value TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  latest_revision INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(config_id) REFERENCES clip_configs(id) ON DELETE CASCADE,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_clip_sessions_owner_status ON app_clip_sessions(owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_clip_sessions_expires ON app_clip_sessions(expires_at);

CREATE TABLE IF NOT EXISTS injections (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'INCOMING_CALL',
  value TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT,
  result TEXT,
  FOREIGN KEY(session_id) REFERENCES app_clip_sessions(id) ON DELETE CASCADE,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(session_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_injections_session_revision ON injections(session_id, revision DESC);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata_json TEXT,
  request_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS login_rate_limits (
  rate_key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  window_started_at TEXT NOT NULL,
  blocked_until TEXT
);
