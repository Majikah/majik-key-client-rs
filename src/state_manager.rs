//! Persisted client state: a small string key/value store with a read-through cache.
//! Port of `MajikKeyClientStateManager`. Subclass-specific keys (e.g. the signature client's
//! app preferences) are just more keys in the same store; wrap this type in the higher-level
//! client instead of inheriting.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::storage::{ClientStateEntry, ClientStateRepo};

pub const STATE_KEY_ACCOUNT_ORDER: &str = "user_account_order";

pub struct ClientStateManager {
    cache: BTreeMap<String, String>,
    repo: Box<dyn ClientStateRepo>,
}

impl ClientStateManager {
    pub fn new(repo: Box<dyn ClientStateRepo>) -> Self {
        Self {
            cache: BTreeMap::new(),
            repo,
        }
    }

    pub fn hydrate(&mut self) -> Result<()> {
        let entries = self.repo.list()?;
        self.cache.clear();
        for entry in entries {
            self.cache.insert(entry.id, entry.value);
        }
        Ok(())
    }

    pub fn get(&mut self, id: &str) -> Result<Option<String>> {
        if let Some(v) = self.cache.get(id) {
            return Ok(Some(v.clone()));
        }
        match self.repo.get_by_id(id)? {
            Some(entry) => {
                self.cache.insert(id.to_string(), entry.value.clone());
                Ok(Some(entry.value))
            }
            None => Ok(None),
        }
    }

    pub fn set(&mut self, id: &str, value: &str) -> Result<()> {
        self.repo.save(&ClientStateEntry {
            id: id.to_string(),
            value: value.to_string(),
            updated_at: None,
        })?;
        self.cache.insert(id.to_string(), value.to_string());
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<bool> {
        let removed = self.repo.remove(id)?;
        self.cache.remove(id);
        Ok(removed)
    }

    pub fn clear(&mut self) -> Result<()> {
        self.repo.clear()?;
        self.cache.clear();
        Ok(())
    }

    pub fn has_cached(&self, id: &str) -> bool {
        self.cache.contains_key(id)
    }

    pub fn exists(&self, id: &str) -> Result<bool> {
        if self.cache.contains_key(id) {
            return Ok(true);
        }
        self.repo.exists(id)
    }

    pub fn list_cached_entries(&self) -> Vec<ClientStateEntry> {
        self.cache
            .iter()
            .map(|(id, value)| ClientStateEntry {
                id: id.clone(),
                value: value.clone(),
                updated_at: None,
            })
            .collect()
    }

    pub fn bulk_set(&mut self, entries: &[ClientStateEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        self.repo.bulk_save(entries)?;
        for e in entries {
            self.cache.insert(e.id.clone(), e.value.clone());
        }
        Ok(())
    }

    pub fn count(&self) -> Result<usize> {
        self.repo.count()
    }

    // ── Account order ────────────────────────────────────────────────────────

    /// A malformed stored value is discarded (returns `None`), same as the TS client.
    pub fn get_account_order(&mut self) -> Result<Option<Vec<String>>> {
        let Some(raw) = self.get(STATE_KEY_ACCOUNT_ORDER)? else {
            return Ok(None);
        };
        Ok(serde_json::from_str::<Vec<String>>(&raw).ok())
    }

    pub fn set_account_order(&mut self, order: &[String]) -> Result<()> {
        let raw = serde_json::to_string(order)?;
        self.set(STATE_KEY_ACCOUNT_ORDER, &raw)
    }

    pub fn remove_account_order(&mut self) -> Result<()> {
        self.remove(STATE_KEY_ACCOUNT_ORDER)?;
        Ok(())
    }
}
