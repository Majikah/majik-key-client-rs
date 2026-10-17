//! Keystore manager: owns every loaded `MajikKey` (the unlocked-key cache) and persists the
//! encrypted JSON through a `KeystoreRepo`. Port of `MajikKeyManager`.
//!
//! Keys live here, in Rust memory, and never cross the IPC boundary. Unlocked secrets are held
//! by `majik-key`'s own zeroizing types.

use majik_key::{
    MajikKey, MajikKeyCreateOptions, MajikKeyJson, MnemonicLanguage, SerializedIdentity,
};

use crate::error::{KeyClientError, Result};
use crate::storage::KeystoreRepo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedItem {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationResult {
    pub success: bool,
    pub message: String,
}

pub struct KeyManager {
    /// Insertion-ordered, like the TS `Map`. Account counts are tiny, so linear lookup is fine.
    cache: Vec<MajikKey>,
    repo: Box<dyn KeystoreRepo>,
}

impl KeyManager {
    pub fn new(repo: Box<dyn KeystoreRepo>) -> Self {
        Self {
            cache: Vec::new(),
            repo,
        }
    }

    // ── Stateless constructors (no persistence) ──────────────────────────────

    pub fn generate_mnemonic(strength: u32, language: MnemonicLanguage) -> Result<String> {
        Ok(MajikKey::generate_mnemonic(strength, language)?)
    }

    pub fn create_key(
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        language: MnemonicLanguage,
    ) -> Result<MajikKey> {
        let options = MajikKeyCreateOptions {
            mnemonic_language: Some(language),
            ..Default::default()
        };
        Ok(MajikKey::create(mnemonic, passphrase, label, &options)?)
    }

    /// Derive a key from a mnemonic backup WITHOUT saving it. The client uses this so it can
    /// reject a duplicate account before anything is written. (The TS manager saved first, so a
    /// rejected duplicate import had already overwritten the stored key.)
    pub fn import_backup(
        backup: &str,
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        language: MnemonicLanguage,
    ) -> Result<MajikKey> {
        let options = MajikKeyCreateOptions {
            mnemonic_language: Some(language),
            ..Default::default()
        };
        Ok(MajikKey::import_from_mnemonic_backup(
            backup, mnemonic, passphrase, label, &options,
        )?)
    }

    /// Build a (locked, PBKDF2) key from a pre-registry `SerializedIdentity`.
    pub fn key_from_legacy_identity(si: &SerializedIdentity) -> Result<MajikKey> {
        if si.id.is_empty() || si.public_key.is_empty() || si.fingerprint.is_empty() {
            return Err(KeyClientError::Invalid(
                "Invalid legacy SerializedIdentity: missing required fields".into(),
            ));
        }
        let json = MajikKeyJson {
            id: si.id.clone(),
            label: String::new(),
            public_key: si.public_key.clone(),
            fingerprint: si.fingerprint.clone(),
            salt: si.salt.clone().unwrap_or_default(),
            backup: "_LEGACY".to_string(),
            timestamp: jiff::Timestamp::now().to_string(),
            // 1 = legacy PBKDF2 (see `MajikKeyJson::kdf_version`).
            kdf_version: Some(1),
            encrypted_private_key: Some(si.encrypted_private_key.clone().unwrap_or_default()),
            ..Default::default()
        };
        Ok(MajikKey::from_json(&json)?)
    }

    // ── Cache helpers ────────────────────────────────────────────────────────

    fn position(&self, id_or_fingerprint: &str) -> Option<usize> {
        self.cache
            .iter()
            .position(|k| k.id() == id_or_fingerprint)
            .or_else(|| {
                self.cache
                    .iter()
                    .position(|k| k.fingerprint() == id_or_fingerprint)
            })
    }

    fn upsert_cache(&mut self, key: MajikKey) {
        match self.cache.iter().position(|k| k.id() == key.id()) {
            Some(i) => self.cache[i] = key,
            None => self.cache.push(key),
        }
    }

    /// Cache-first lookup by exact id, falling back to the repository.
    fn load_index(&mut self, id: &str) -> Result<Option<usize>> {
        if let Some(i) = self.cache.iter().position(|k| k.id() == id) {
            return Ok(Some(i));
        }
        let Some(json) = self.repo.get_by_id(id)? else {
            return Ok(None);
        };
        let key = MajikKey::from_json(&json)?;
        let key_id = key.id().to_string();
        self.upsert_cache(key);
        Ok(self.cache.iter().position(|k| k.id() == key_id))
    }

    fn require_index(&mut self, id: &str) -> Result<usize> {
        self.load_index(id)?
            .ok_or_else(|| KeyClientError::AccountNotFound(id.to_string()))
    }

    fn persist_at(&self, index: usize) -> Result<()> {
        self.repo.save(&self.cache[index].to_json())
    }

    // ── Hydration / persistence ──────────────────────────────────────────────

    /// Reload every stored key into the cache. Malformed keys are skipped and reported
    /// (the TS version only `console.warn`ed). Returns `(loaded, skipped)`.
    pub fn hydrate(&mut self) -> Result<(usize, Vec<SkippedItem>)> {
        self.cache.clear();
        let mut loaded = 0usize;
        let mut skipped = Vec::new();
        for json in self.repo.list()? {
            match MajikKey::from_json(&json) {
                Ok(key) => {
                    self.upsert_cache(key);
                    loaded += 1;
                }
                Err(e) => skipped.push(SkippedItem {
                    id: json.id.clone(),
                    reason: e.to_string(),
                }),
            }
        }
        Ok((loaded, skipped))
    }

    /// The stored (encrypted) JSON for every account, straight from the repository.
    pub fn to_json(&self) -> Result<Vec<MajikKeyJson>> {
        self.repo.list()
    }

    pub fn bulk_restore_from_json(&mut self, data: &[MajikKeyJson]) -> Result<()> {
        self.repo.bulk_save(data)?;
        self.hydrate()?;
        Ok(())
    }

    /// Persist then cache. Takes ownership of the key.
    pub fn save(&mut self, key: MajikKey) -> Result<()> {
        self.repo.save(&key.to_json())?;
        self.upsert_cache(key);
        Ok(())
    }

    pub fn get_account(&mut self, id: &str) -> Result<&MajikKey> {
        let i = self.require_index(id)?;
        Ok(&self.cache[i])
    }

    /// Cache every stored key not already loaded, then return all cached keys.
    pub fn load_all(&mut self) -> Result<&[MajikKey]> {
        for json in self.repo.list()? {
            if self.cache.iter().any(|k| k.id() == json.id) {
                continue;
            }
            if let Ok(key) = MajikKey::from_json(&json) {
                self.upsert_cache(key);
            }
        }
        Ok(&self.cache)
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.repo.remove(id)?;
        self.cache.retain(|k| k.id() != id);
        Ok(())
    }

    /// Remove every stored key and empty the cache.
    pub fn clear(&mut self) -> Result<()> {
        self.repo.clear()?;
        self.cache.clear();
        Ok(())
    }

    pub fn has(&self, id_or_fingerprint: &str) -> Result<bool> {
        if self.position(id_or_fingerprint).is_some() {
            return Ok(true);
        }
        Ok(self
            .repo
            .list()?
            .iter()
            .any(|j| j.id == id_or_fingerprint || j.fingerprint == id_or_fingerprint))
    }

    // ── Reads from the cache ─────────────────────────────────────────────────

    pub fn get(&self, id_or_fingerprint: &str) -> Option<&MajikKey> {
        self.position(id_or_fingerprint).map(|i| &self.cache[i])
    }

    pub fn get_mut(&mut self, id_or_fingerprint: &str) -> Option<&mut MajikKey> {
        let i = self.position(id_or_fingerprint)?;
        Some(&mut self.cache[i])
    }

    pub fn list(&self) -> &[MajikKey] {
        &self.cache
    }

    // ── Lock / unlock ────────────────────────────────────────────────────────

    pub fn unlock(&mut self, id: &str, passphrase: &str) -> Result<()> {
        let i = self.require_index(id)?;
        let key = &mut self.cache[i];
        if key.is_unlocked() {
            return Ok(());
        }
        key.unlock(passphrase)?;
        Ok(())
    }

    pub fn lock(&mut self, id: &str) {
        if let Some(key) = self.cache.iter_mut().find(|k| k.id() == id) {
            key.lock();
        }
    }

    pub fn lock_all(&mut self) {
        for key in self.cache.iter_mut() {
            key.lock();
        }
    }

    /// `Ok(())` if the account is loaded and unlocked, `UnlockRequired` if it is locked.
    /// Never prompts: the UI collects the passphrase and calls `unlock`.
    pub fn ensure_unlocked(&mut self, id: &str) -> Result<()> {
        let index = match self.position(id) {
            Some(i) => Some(i),
            None => self.load_index(id)?,
        };
        let i = index.ok_or_else(|| KeyClientError::AccountNotFound(id.to_string()))?;
        if self.cache[i].is_unlocked() {
            Ok(())
        } else {
            Err(KeyClientError::UnlockRequired(id.to_string()))
        }
    }

    // ── Passphrase / label ───────────────────────────────────────────────────

    pub fn is_passphrase_valid(&mut self, id: &str, passphrase: &str) -> Result<bool> {
        match self.load_index(id)? {
            Some(i) => Ok(self.cache[i].verify(passphrase)),
            None => Ok(false),
        }
    }

    /// The key must be unlocked (enforced by `majik-key`).
    pub fn update_passphrase(&mut self, id: &str, current: &str, new: &str) -> Result<()> {
        let i = self.require_index(id)?;
        self.cache[i].update_passphrase(current, new)?;
        self.persist_at(i)
    }

    /// Recover an account whose passphrase is lost: re-derive from `backup` + `mnemonic` under a
    /// new passphrase. The re-derived fingerprint must match the stored account. Returns the id.
    ///
    /// Saves the new key BEFORE removing the old row (they usually share an id, so this is a
    /// single atomic replace), where the TS version removed first.
    pub fn replace_passphrase(
        &mut self,
        backup: &str,
        mnemonic: &str,
        new_passphrase: &str,
        expected_id: &str,
        label: Option<&str>,
        language: Option<MnemonicLanguage>,
    ) -> Result<String> {
        if backup.trim().is_empty() {
            return Err(KeyClientError::Invalid(
                "replacePassphrase: backup is required".into(),
            ));
        }
        if mnemonic.trim().is_empty() {
            return Err(KeyClientError::Invalid(
                "replacePassphrase: mnemonic is required".into(),
            ));
        }
        if new_passphrase.trim().is_empty() {
            return Err(KeyClientError::Invalid(
                "replacePassphrase: newPassphrase is required".into(),
            ));
        }

        let i = self.load_index(expected_id)?.ok_or_else(|| {
            KeyClientError::Invalid(format!(
                "replacePassphrase: no stored account found with id \"{expected_id}\""
            ))
        })?;
        let existing_id = self.cache[i].id().to_string();
        let existing_fingerprint = self.cache[i].fingerprint().to_string();
        let resolved_label = label
            .map(str::to_string)
            .unwrap_or_else(|| self.cache[i].label().to_string());
        let resolved_language = language.unwrap_or_else(|| self.cache[i].mnemonic_language());

        let label_opt = if resolved_label.is_empty() {
            None
        } else {
            Some(resolved_label.as_str())
        };
        let fresh = Self::import_backup(
            backup,
            mnemonic,
            new_passphrase,
            label_opt,
            resolved_language,
        )?;

        if fresh.fingerprint() != existing_fingerprint {
            return Err(KeyClientError::Invalid(format!(
                "replacePassphrase: fingerprint mismatch -- backup fingerprint \"{}\" does not \
                 match stored account \"{}\"",
                fresh.fingerprint(),
                existing_fingerprint
            )));
        }

        let fresh_id = fresh.id().to_string();
        self.repo.save(&fresh.to_json())?;
        if existing_id != fresh_id {
            self.repo.remove(&existing_id)?;
            self.cache.retain(|k| k.id() != existing_id);
        }
        self.upsert_cache(fresh);
        Ok(fresh_id)
    }

    pub fn update_label(&mut self, id: &str, new_label: &str) -> Result<()> {
        let i = self
            .position(id)
            .ok_or_else(|| KeyClientError::AccountNotFound(id.to_string()))?;
        self.cache[i].update_label(new_label)?;
        self.persist_at(i)
    }

    // ── Backups ──────────────────────────────────────────────────────────────

    /// The account must be unlocked (enforced by `majik-key`).
    pub fn export_mnemonic_backup(&self, id: &str, mnemonic: &str) -> Result<String> {
        let key = self
            .cache
            .iter()
            .find(|k| k.id() == id)
            .ok_or_else(|| KeyClientError::AccountNotFound(id.to_string()))?;
        Ok(key.export_mnemonic_backup(mnemonic)?)
    }

    // ── Legacy migration ─────────────────────────────────────────────────────

    pub fn migrate(&mut self, identity: &SerializedIdentity) -> MigrationResult {
        let outcome = (|| -> Result<MigrationResult> {
            if self.repo.exists(&identity.id)? {
                return Ok(MigrationResult {
                    success: true,
                    message: format!("Already migrated: {}", identity.id),
                });
            }
            let key = Self::key_from_legacy_identity(identity)?;
            self.save(key)?;
            Ok(MigrationResult {
                success: true,
                message: format!("Successfully migrated {}", identity.id),
            })
        })();
        match outcome {
            Ok(r) => r,
            Err(e) => MigrationResult {
                success: false,
                message: format!("Failed to migrate legacy account {}: {e}", identity.id),
            },
        }
    }

    /// Returns `(migrated, skipped)`.
    pub fn migrate_all(&mut self, identities: &[SerializedIdentity]) -> (usize, usize) {
        let mut migrated = 0;
        let mut skipped = 0;
        for identity in identities {
            if self.migrate(identity).success {
                migrated += 1;
            } else {
                skipped += 1;
            }
        }
        (migrated, skipped)
    }
}
