-- D1 Database Schema for Cap CF

-- Keys table
CREATE TABLE IF NOT EXISTS keys (
  site_key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  jwt_secret TEXT NOT NULL,
  config TEXT NOT NULL, -- JSON string
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  hash TEXT PRIMARY KEY,
  data TEXT NOT NULL, -- JSON string {created, expires}
  expires_at INTEGER NOT NULL
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Index for cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Cache table (used when CACHE_BACKEND=d1)
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);
