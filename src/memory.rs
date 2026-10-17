//! In-memory repositories (tests, and the TS `InMemory*Adapter` equivalent).

use std::sync::{Mutex, MutexGuard};

use majik_key::MajikKeyJson;

use crate::error::{KeyClientError, Result};
use crate::storage::{ClientStateEntry, ClientStateRepo, KeystoreRepo};

fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| KeyClientError::Storage("in-memory store mutex poisoned".into()))
}

#[derive(Default)]
pub struct MemoryKeystoreRepo {
    rows: Mutex<Vec<MajikKeyJson>>,
}

impl MemoryKeystoreRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeystoreRepo for MemoryKeystoreRepo {
    fn save(&self, key: &MajikKeyJson) -> Result<()> {
        let mut rows = lock(&self.rows)?;
        // INSERT OR REPLACE semantics: a replaced row moves to the end.
        rows.retain(|k| k.id != key.id);
        rows.push(key.clone());
        Ok(())
    }

    fn get_by_id(&self, id: &str) -> Result<Option<MajikKeyJson>> {
        Ok(lock(&self.rows)?.iter().find(|k| k.id == id).cloned())
    }

    fn list(&self) -> Result<Vec<MajikKeyJson>> {
        Ok(lock(&self.rows)?.clone())
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = lock(&self.rows)?;
        let before = rows.len();
        rows.retain(|k| k.id != id);
        Ok(rows.len() != before)
    }

    fn clear(&self) -> Result<()> {
        lock(&self.rows)?.clear();
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        Ok(lock(&self.rows)?.len())
    }

    fn exists(&self, id: &str) -> Result<bool> {
        Ok(lock(&self.rows)?.iter().any(|k| k.id == id))
    }

    fn bulk_save(&self, keys: &[MajikKeyJson]) -> Result<()> {
        for key in keys {
            self.save(key)?;
        }
        Ok(())
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.remove(id)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryClientStateRepo {
    rows: Mutex<Vec<ClientStateEntry>>,
}

impl MemoryClientStateRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClientStateRepo for MemoryClientStateRepo {
    fn save(&self, entry: &ClientStateEntry) -> Result<()> {
        let mut rows = lock(&self.rows)?;
        rows.retain(|e| e.id != entry.id);
        rows.push(entry.clone());
        Ok(())
    }

    fn bulk_save(&self, entries: &[ClientStateEntry]) -> Result<()> {
        for entry in entries {
            self.save(entry)?;
        }
        Ok(())
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = lock(&self.rows)?;
        let before = rows.len();
        rows.retain(|e| e.id != id);
        Ok(rows.len() != before)
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.remove(id)?;
        }
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        lock(&self.rows)?.clear();
        Ok(())
    }

    fn get_by_id(&self, id: &str) -> Result<Option<ClientStateEntry>> {
        Ok(lock(&self.rows)?.iter().find(|e| e.id == id).cloned())
    }

    fn list(&self) -> Result<Vec<ClientStateEntry>> {
        Ok(lock(&self.rows)?.clone())
    }

    fn count(&self) -> Result<usize> {
        Ok(lock(&self.rows)?.len())
    }

    fn exists(&self, id: &str) -> Result<bool> {
        Ok(lock(&self.rows)?.iter().any(|e| e.id == id))
    }
}
