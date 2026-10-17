//! SQL schema. These strings are equivalent to the TS `MAJIKAH_SQL_SCHEMA_MAJIK_KEYS` /
//! `MAJIKAH_SQL_SCHEMA_MAJIK_CLIENT_STATE` constants (table names resolved). Both are
//! `IF NOT EXISTS`, so running them against a database created by the TS adapters is a no-op.

pub const TABLE_MAJIK_KEYS: &str = "majik_keys";
pub const TABLE_CLIENT_STATE: &str = "majik_client_state";

pub const SCHEMA_MAJIK_CLIENT_STATE: &str = "
CREATE TABLE IF NOT EXISTS majik_client_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now'))
);
";

pub const SCHEMA_MAJIK_KEYS: &str = "
CREATE TABLE IF NOT EXISTS majik_keys (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  public_key TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_majik_keys_timestamp
ON majik_keys(timestamp);

CREATE INDEX IF NOT EXISTS idx_majik_keys_public_key
ON majik_keys(public_key);
";
