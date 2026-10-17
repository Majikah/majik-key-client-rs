//! SQLite repositories over a shared `rusqlite::Connection`.
//!
//! The connection is shared with the rest of the app (your existing `sqlite_call` /
//! `sqlite_batch` commands can keep using the same handle), so SQLCipher keying etc. stays the
//! app's responsibility. This crate depends on plain `rusqlite = "0.40"`; the app enables
//! `bundled-sqlcipher-vendored-openssl` and Cargo unifies the features.
//!
//! All queries are synchronous. From async Tauri commands, call into the client through
//! `tauri::async_runtime::spawn_blocking` (SQLite and Argon2id both block).

use std::sync::{Arc, Mutex, MutexGuard};

use majik_key::MajikKeyJson;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{KeyClientError, Result};
use crate::schema::{SCHEMA_MAJIK_CLIENT_STATE, SCHEMA_MAJIK_KEYS};
use crate::storage::{ClientStateEntry, ClientStateRepo, KeystoreRepo};

pub type SharedConnection = Arc<Mutex<Connection>>;

fn lock(conn: &SharedConnection) -> Result<MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| KeyClientError::Storage("SQLite connection mutex poisoned".into()))
}

/// Idempotent. Creates the `majik_keys` and `majik_client_state` tables if missing.
pub fn init_schema(conn: &SharedConnection) -> Result<()> {
    let guard = lock(conn)?;
    guard.execute_batch(SCHEMA_MAJIK_KEYS)?;
    guard.execute_batch(SCHEMA_MAJIK_CLIENT_STATE)?;
    Ok(())
}

/// Equivalent of the TS `db.vacuum()` + `db.optimize()` run at the end of `resetData()`.
pub fn run_maintenance(conn: &SharedConnection) -> Result<()> {
    let guard = lock(conn)?;
    guard.execute_batch("VACUUM; PRAGMA optimize;")?;
    Ok(())
}

// ─── Keystore ────────────────────────────────────────────────────────────────

pub struct SqliteKeystoreRepo {
    conn: SharedConnection,
}

impl SqliteKeystoreRepo {
    pub fn new(conn: SharedConnection) -> Self {
        Self { conn }
    }
}

fn upsert_key(conn: &Connection, key: &MajikKeyJson) -> Result<()> {
    let json = serde_json::to_string(key)?;
    conn.execute(
        "INSERT OR REPLACE INTO majik_keys (id, json, timestamp, public_key) \
         VALUES (?1, ?2, ?3, ?4)",
        params![key.id, json, key.timestamp, key.public_key],
    )?;
    Ok(())
}

fn parse_key_row(id: &str, json: &str) -> Result<MajikKeyJson> {
    serde_json::from_str::<MajikKeyJson>(json)
        .map_err(|e| KeyClientError::Storage(format!("Malformed key row \"{id}\": {e}")))
}

impl KeystoreRepo for SqliteKeystoreRepo {
    fn save(&self, key: &MajikKeyJson) -> Result<()> {
        let guard = lock(&self.conn)?;
        upsert_key(&guard, key)
    }

    fn get_by_id(&self, id: &str) -> Result<Option<MajikKeyJson>> {
        let guard = lock(&self.conn)?;
        let row: Option<String> = guard
            .query_row(
                "SELECT json FROM majik_keys WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match row {
            Some(json) => Ok(Some(parse_key_row(id, &json)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<MajikKeyJson>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard.prepare("SELECT id, json FROM majik_keys ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_key_row(&id, &json)?);
        }
        Ok(out)
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let n = guard.execute("DELETE FROM majik_keys WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    fn clear(&self) -> Result<()> {
        let guard = lock(&self.conn)?;
        guard.execute("DELETE FROM majik_keys", [])?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let guard = lock(&self.conn)?;
        let n: i64 = guard.query_row("SELECT COUNT(*) FROM majik_keys", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let found: Option<i64> = guard
            .query_row("SELECT 1 FROM majik_keys WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(found.is_some())
    }

    fn bulk_save(&self, keys: &[MajikKeyJson]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction()?;
        for key in keys {
            upsert_key(&tx, key)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM majik_keys WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ─── Client state ────────────────────────────────────────────────────────────

pub struct SqliteClientStateRepo {
    conn: SharedConnection,
}

impl SqliteClientStateRepo {
    pub fn new(conn: SharedConnection) -> Self {
        Self { conn }
    }
}

fn upsert_state(conn: &Connection, entry: &ClientStateEntry) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO majik_client_state (key, value, updated_at) \
         VALUES (?1, ?2, datetime('now'))",
        params![entry.id, entry.value],
    )?;
    Ok(())
}

fn state_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ClientStateEntry> {
    Ok(ClientStateEntry {
        id: r.get::<_, String>(0)?,
        value: r.get::<_, String>(1)?,
        updated_at: r.get::<_, Option<String>>(2)?,
    })
}

impl ClientStateRepo for SqliteClientStateRepo {
    fn save(&self, entry: &ClientStateEntry) -> Result<()> {
        let guard = lock(&self.conn)?;
        upsert_state(&guard, entry)
    }

    fn bulk_save(&self, entries: &[ClientStateEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction()?;
        for entry in entries {
            upsert_state(&tx, entry)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let n = guard.execute("DELETE FROM majik_client_state WHERE key = ?1", params![id])?;
        Ok(n > 0)
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut guard = lock(&self.conn)?;
        let tx = guard.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM majik_client_state WHERE key = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let guard = lock(&self.conn)?;
        guard.execute("DELETE FROM majik_client_state", [])?;
        Ok(())
    }

    fn get_by_id(&self, id: &str) -> Result<Option<ClientStateEntry>> {
        let guard = lock(&self.conn)?;
        let entry = guard
            .query_row(
                "SELECT key, value, updated_at FROM majik_client_state WHERE key = ?1",
                params![id],
                state_from_row,
            )
            .optional()?;
        Ok(entry)
    }

    fn list(&self) -> Result<Vec<ClientStateEntry>> {
        let guard = lock(&self.conn)?;
        let mut stmt = guard.prepare("SELECT key, value, updated_at FROM majik_client_state")?;
        let rows = stmt.query_map([], state_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn count(&self) -> Result<usize> {
        let guard = lock(&self.conn)?;
        let n: i64 =
            guard.query_row("SELECT COUNT(*) FROM majik_client_state", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let guard = lock(&self.conn)?;
        let found: Option<i64> = guard
            .query_row(
                "SELECT 1 FROM majik_client_state WHERE key = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }
}
