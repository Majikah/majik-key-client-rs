//! Repository traits. These replace the TS `MajikStorageAdapter<T>` (+ memory / IDB / SQL
//! variants). Tauri only needs SQLite and in-memory (tests), so IDB is intentionally absent.
//!
//! The TS adapters' dynamic `query({ where, orderBy, ... })` is not ported: nothing in the
//! key client uses it, and building SQL from caller-supplied column names is not something to
//! carry over.

use majik_key::MajikKeyJson;

use crate::error::Result;

pub trait KeystoreRepo: Send + Sync {
    fn save(&self, key: &MajikKeyJson) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<MajikKeyJson>>;
    /// Insertion order (matches SQLite rowid order, which is what the TS adapter observes).
    fn list(&self) -> Result<Vec<MajikKeyJson>>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn clear(&self) -> Result<()>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
    fn bulk_save(&self, keys: &[MajikKeyJson]) -> Result<()>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStateEntry {
    pub id: String,
    pub value: String,
    pub updated_at: Option<String>,
}

pub trait ClientStateRepo: Send + Sync {
    fn save(&self, entry: &ClientStateEntry) -> Result<()>;
    fn bulk_save(&self, entries: &[ClientStateEntry]) -> Result<()>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
    fn clear(&self) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<ClientStateEntry>>;
    fn list(&self) -> Result<Vec<ClientStateEntry>>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
}
