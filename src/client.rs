//! `KeyClient`: the root of every Majikah app client. Port of the TS abstract `MajikKeyClient`.
//!
//! Rust has no inheritance, so the TS "abstract hooks" become the [`AccountHooks`] trait and the
//! TS subclasses (`MajikSignatureClient`, ...) become structs that OWN a `KeyClient<TheirHooks>`
//! (composition). Everything here is synchronous: SQLite and Argon2id both block, so the Tauri
//! layer wraps calls in `spawn_blocking` behind a `Mutex<KeyClient<_>>`.
//!
//! Accounts are real `majik-contact` [`MajikContact`]s, built by `MajikKey::to_contact`.
//!
//! Behaviour changes versus the TS client (all deliberate):
//!  * No prompting. `ensure_identity_unlocked` returns `UnlockRequired`; the UI prompts.
//!  * Account order is persisted immediately instead of after a 300 ms debounce (one tiny row).
//!  * Importing/creating an account whose id already exists is rejected BEFORE anything is
//!    written (TS saved first, silently overwriting the stored key's passphrase).
//!  * `replace_account_from_mnemonic_backup` refreshes the stored account entry (TS kept a stale
//!    label when the id was unchanged).
//!  * A failing `on_account_registered` hook rolls the in-memory registration back.
//!  * Persisting the account order can fail loudly via an `error` event instead of `console.warn`.

use std::collections::HashMap;
use std::sync::Arc;

use majik_key::{
    KeyId, MajikContact, MajikContactMeta, MajikKey, MajikKeyJson, MnemonicLanguage,
    SerializedIdentity, SerializedMajikContact,
};
use serde::Serialize;

use crate::error::{KeyClientError, Result};
use crate::events::{ClientEvent, EventBus, EventListener, ListenerId};
use crate::key_manager::{KeyManager, SkippedItem};
use crate::memory::{MemoryClientStateRepo, MemoryKeystoreRepo};
use crate::sqlite::{
    init_schema, run_maintenance, SharedConnection, SqliteClientStateRepo, SqliteKeystoreRepo,
};
use crate::state_manager::ClientStateManager;
use crate::storage::{ClientStateRepo, KeystoreRepo};

// ─── Hooks (the TS abstract methods) ─────────────────────────────────────────

/// Subclass extension points. Hooks run synchronously and in order, which an event bus cannot
/// guarantee (e.g. the contact must exist before the account becomes active).
pub trait AccountHooks: Send {
    /// TS `_buildOwnAccountContact`. The default is `key.to_contact(meta)`.
    ///
    /// `to_contact` needs the key's ML-KEM-768 public key; a legacy (pre-registry, PBKDF2-only)
    /// key without one fails here. During `hydrate` that account is reported in
    /// `HydrateReport::accounts_failed` rather than silently dropped.
    fn build_own_account(
        &self,
        key: &MajikKey,
        meta: Option<MajikContactMeta>,
    ) -> Result<MajikContact> {
        Ok(key.to_contact(meta)?)
    }

    /// TS `_onAccountRegistered`.
    fn on_account_registered(&mut self, _account: &MajikContact) -> Result<()> {
        Ok(())
    }

    /// TS `_onAccountRemoved`.
    fn on_account_removed(&mut self, _id: &str) -> Result<()> {
        Ok(())
    }

    /// TS `_onResetKeyData`. Runs first during `reset_data`.
    fn on_reset_key_data(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Hooks that do nothing: a plain key client.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHooks;
impl AccountHooks for NoHooks {}

// ─── Results ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAccount {
    pub id: String,
    pub fingerprint: String,
    pub backup: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedAccount {
    pub id: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HydrateReport {
    pub keys_loaded: usize,
    pub keys_skipped: Vec<SkippedItemJson>,
    pub accounts_failed: Vec<SkippedItemJson>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationSummary {
    pub migrated: usize,
    pub skipped: usize,
    /// Migrated keys that could not be registered as accounts (e.g. legacy keys without ML-KEM).
    pub accounts_failed: Vec<SkippedItemJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedItemJson {
    pub id: String,
    pub reason: String,
}

impl From<SkippedItem> for SkippedItemJson {
    fn from(s: SkippedItem) -> Self {
        Self {
            id: s.id,
            reason: s.reason,
        }
    }
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct KeyClient<H: AccountHooks = NoHooks> {
    hooks: H,
    keys: KeyManager,
    state: ClientStateManager,
    own_accounts: HashMap<String, MajikContact>,
    /// The first entry is the active account.
    own_order: Vec<String>,
    events: EventBus,
    /// Only used for the VACUUM/optimize pass in `reset_data`.
    db: Option<SharedConnection>,
    hydrated: bool,
}

impl<H: AccountHooks> KeyClient<H> {
    // ── Construction ─────────────────────────────────────────────────────────

    pub fn new(
        hooks: H,
        keystore: Box<dyn KeystoreRepo>,
        client_state: Box<dyn ClientStateRepo>,
    ) -> Self {
        Self {
            hooks,
            keys: KeyManager::new(keystore),
            state: ClientStateManager::new(client_state),
            own_accounts: HashMap::new(),
            own_order: Vec::new(),
            events: EventBus::new(),
            db: None,
            hydrated: false,
        }
    }

    /// Volatile client for tests.
    pub fn in_memory(hooks: H) -> Self {
        Self::new(
            hooks,
            Box::new(MemoryKeystoreRepo::new()),
            Box::new(MemoryClientStateRepo::new()),
        )
    }

    /// SQLite-backed client over the app's shared connection. Creates the two tables if needed.
    /// Call [`hydrate`](Self::hydrate) afterwards.
    pub fn with_sqlite(hooks: H, conn: SharedConnection) -> Result<Self> {
        init_schema(&conn)?;
        let mut client = Self::new(
            hooks,
            Box::new(SqliteKeystoreRepo::new(Arc::clone(&conn))),
            Box::new(SqliteClientStateRepo::new(Arc::clone(&conn))),
        );
        client.db = Some(conn);
        Ok(client)
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    pub fn hooks(&self) -> &H {
        &self.hooks
    }
    pub fn hooks_mut(&mut self) -> &mut H {
        &mut self.hooks
    }
    pub fn key_manager(&self) -> &KeyManager {
        &self.keys
    }
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.keys
    }
    pub fn state(&self) -> &ClientStateManager {
        &self.state
    }
    pub fn state_mut(&mut self) -> &mut ClientStateManager {
        &mut self.state
    }

    // ── Events ───────────────────────────────────────────────────────────────

    pub fn subscribe(&mut self, listener: EventListener) -> ListenerId {
        self.events.subscribe(listener)
    }

    pub fn unsubscribe(&mut self, id: ListenerId) -> bool {
        self.events.unsubscribe(id)
    }

    fn emit(&self, event: ClientEvent) {
        self.events.emit(&event);
    }

    /// Runs `f`; on failure emits an `error` event (TS: `_emitBase("error", err, { context })`)
    /// and returns the error unchanged.
    fn with_error_event<T>(
        &mut self,
        context: &str,
        id: Option<&str>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        match f(self) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.emit(ClientEvent::Error {
                    message: e.to_string(),
                    context: context.to_string(),
                    id: id.map(str::to_string),
                });
                Err(e)
            }
        }
    }

    // ── Hydration ────────────────────────────────────────────────────────────

    pub fn hydrate(&mut self) -> Result<HydrateReport> {
        let (keys_loaded, keys_skipped) = self.keys.hydrate()?;
        self.state.hydrate()?;
        let accounts_failed = self.hydrate_own_accounts();
        self.restore_account_order();
        self.hydrated = true;
        Ok(HydrateReport {
            keys_loaded,
            keys_skipped: keys_skipped.into_iter().map(Into::into).collect(),
            accounts_failed,
        })
    }

    /// True once `hydrate` has run. IPC layers use this so a second window (or a webview reload)
    /// does not re-hydrate, which would re-lock every key.
    pub fn is_hydrated(&self) -> bool {
        self.hydrated
    }

    /// Replace everything in the keystore with `keys` (encrypted JSON rows), then rebuild the
    /// account registry from them. Existing accounts are announced to the hooks as removed first.
    pub fn restore_keystore_from_json(&mut self, keys: &[MajikKeyJson]) -> Result<HydrateReport> {
        self.with_error_event("restoreKeystore", None, |c| {
            let existing: Vec<String> = c.own_accounts.keys().cloned().collect();
            for id in &existing {
                c.hooks.on_account_removed(id)?;
            }
            c.own_accounts.clear();
            c.own_order.clear();
            c.keys.bulk_restore_from_json(keys)?;
            let report = c.hydrate()?;
            c.emit(ClientEvent::RestoreBackup);
            let active = c.active_account_json();
            c.emit(ClientEvent::ActiveAccountChange {
                active,
                previous: None,
            });
            Ok(report)
        })
    }

    /// Import pre-registry `SerializedIdentity` records and register what can be registered.
    /// Unlike `hydrate`, this does not reload the key cache, so unlocked keys stay unlocked.
    pub fn migrate_legacy_identities(
        &mut self,
        identities: &[SerializedIdentity],
    ) -> Result<MigrationSummary> {
        let (migrated, skipped) = self.keys.migrate_all(identities);
        let accounts_failed = self.hydrate_own_accounts();
        self.restore_account_order();
        Ok(MigrationSummary {
            migrated,
            skipped,
            accounts_failed,
        })
    }

    /// Replace the stored own-account contact, e.g. after a higher-level contact directory edited
    /// it. No hooks run and no events are emitted. Returns `false` if `account` is not an own
    /// account.
    pub fn refresh_own_account(&mut self, account: MajikContact) -> bool {
        if self.own_accounts.contains_key(account.id()) {
            self.own_accounts.insert(account.id().to_string(), account);
            true
        } else {
            false
        }
    }

    pub fn is_account_unlocked(&self, id: &str) -> bool {
        self.keys.get(id).map(|k| k.is_unlocked()).unwrap_or(false)
    }

    fn hydrate_own_accounts(&mut self) -> Vec<SkippedItemJson> {
        let mut failed = Vec::new();
        for key in self.keys.list() {
            if self.own_accounts.contains_key(key.id()) {
                continue;
            }
            let id = key.id().to_string();
            let built = self.hooks.build_own_account(key, None).and_then(|account| {
                self.hooks.on_account_registered(&account)?;
                Ok(account)
            });
            match built {
                Ok(account) => {
                    self.own_accounts.insert(id.clone(), account);
                    if !self.own_order.contains(&id) {
                        self.own_order.push(id);
                    }
                }
                Err(e) => failed.push(SkippedItemJson {
                    id,
                    reason: e.to_string(),
                }),
            }
        }
        failed
    }

    fn restore_account_order(&mut self) {
        let Ok(Some(saved)) = self.state.get_account_order() else {
            return;
        };
        let valid: Vec<String> = saved
            .into_iter()
            .filter(|id| self.own_accounts.contains_key(id))
            .collect();
        let appended: Vec<String> = self
            .own_order
            .iter()
            .filter(|id| !valid.contains(id))
            .cloned()
            .collect();
        self.own_order = valid.into_iter().chain(appended).collect();
    }

    fn persist_account_order(&mut self) {
        if let Err(e) = self.state.set_account_order(&self.own_order) {
            self.emit(ClientEvent::Error {
                message: e.to_string(),
                context: "persistAccountOrder".to_string(),
                id: None,
            });
        }
    }

    // ── Mnemonic / account lifecycle ─────────────────────────────────────────

    pub fn generate_mnemonic(&self, strength: u32, language: MnemonicLanguage) -> Result<String> {
        KeyManager::generate_mnemonic(strength, language)
    }

    pub fn create_account(
        &mut self,
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        meta: Option<MajikContactMeta>,
        language: MnemonicLanguage,
    ) -> Result<CreatedAccount> {
        self.with_error_event("createAccount", None, |c| {
            let key = KeyManager::create_key(mnemonic, passphrase, label, language)?;
            if c.own_accounts.contains_key(key.id()) {
                return Err(KeyClientError::DuplicateAccount);
            }
            let account = c.hooks.build_own_account(&key, meta)?;
            let created = CreatedAccount {
                id: key.id().to_string(),
                fingerprint: key.fingerprint().to_string(),
                backup: key.backup().to_string(),
            };
            c.keys.save(key)?;
            c.register_own_account(account.clone())?;
            c.emit(ClientEvent::NewAccount(account.to_json()));
            Ok(created)
        })
    }

    pub fn import_account_from_mnemonic_backup(
        &mut self,
        backup: &str,
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        meta: Option<MajikContactMeta>,
        language: MnemonicLanguage,
    ) -> Result<ImportedAccount> {
        self.with_error_event("importAccountFromMnemonicBackup", None, |c| {
            let key = KeyManager::import_backup(backup, mnemonic, passphrase, label, language)?;
            if c.own_accounts.contains_key(key.id()) {
                return Err(KeyClientError::DuplicateAccount);
            }
            let account = c.hooks.build_own_account(&key, meta)?;
            let result = ImportedAccount {
                id: key.id().to_string(),
                fingerprint: key.fingerprint().to_string(),
            };
            c.keys.save(key)?;
            c.register_own_account(account.clone())?;
            c.emit(ClientEvent::NewAccount(account.to_json()));
            Ok(result)
        })
    }

    /// Swap the active account for the one in `backup` (or refresh it, if it is the same account).
    pub fn replace_account_from_mnemonic_backup(
        &mut self,
        backup: &str,
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        meta: Option<MajikContactMeta>,
        language: MnemonicLanguage,
    ) -> Result<ImportedAccount> {
        self.with_error_event("replaceAccountFromMnemonicBackup", None, |c| {
            let current_id = c.own_order.first().cloned();
            let current_label = current_id
                .as_ref()
                .and_then(|id| c.own_accounts.get(id))
                .and_then(|a| a.meta.label.clone());
            let final_label = label
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .or(current_label);

            let key = KeyManager::import_backup(
                backup,
                mnemonic,
                passphrase,
                final_label.as_deref(),
                language,
            )?;
            let new_id = key.id().to_string();
            if c.own_accounts.contains_key(&new_id)
                && current_id.as_deref() != Some(new_id.as_str())
            {
                return Err(KeyClientError::DuplicateAccount);
            }

            let account = c.hooks.build_own_account(&key, meta)?;
            let result = ImportedAccount {
                id: new_id.clone(),
                fingerprint: key.fingerprint().to_string(),
            };
            c.keys.save(key)?;
            if let Some(cur) = current_id.as_deref() {
                if cur != new_id {
                    c.remove_own_account(cur)?;
                }
            }
            c.register_own_account(account.clone())?;
            c.set_active_account(&new_id, true)?;
            c.emit(ClientEvent::NewAccount(account.to_json()));
            Ok(result)
        })
    }

    /// The account must be unlocked.
    pub fn export_account_mnemonic_backup(&self, id: &str, mnemonic: &str) -> Result<String> {
        self.keys.export_mnemonic_backup(id, mnemonic)
    }

    /// Register a pre-built account (TS `addOwnAccount`).
    pub fn add_own_account(&mut self, account: MajikContact) -> Result<()> {
        self.register_own_account(account.clone())?;
        self.emit(ClientEvent::NewAccount(account.to_json()));
        Ok(())
    }

    pub fn remove_own_account(&mut self, id: &str) -> Result<bool> {
        if !self.own_accounts.contains_key(id) {
            return Ok(false);
        }
        self.hooks.on_account_removed(id)?;
        self.keys.delete(id)?;
        self.own_accounts.remove(id);
        self.own_order.retain(|x| x != id);
        self.persist_account_order();
        self.emit(ClientEvent::RemovedAccount(id.to_string()));
        Ok(true)
    }

    pub fn update_account_label(&mut self, id: &str, new_label: &str) -> Result<()> {
        self.keys.update_label(id, new_label)?;
        let updated = self.own_accounts.get_mut(id).map(|account| {
            account.update_label(new_label);
            account.to_json()
        });
        if let Some(account) = updated {
            self.emit(ClientEvent::UpdatedAccount(account));
        }
        Ok(())
    }

    fn register_own_account(&mut self, account: MajikContact) -> Result<()> {
        let had_active = self.get_active_account().is_some();
        let id = account.id().to_string();
        let is_new = !self.own_accounts.contains_key(&id);

        self.own_accounts.insert(id.clone(), account.clone());
        if is_new && had_active {
            self.own_order.push(id.clone());
            self.persist_account_order();
        }

        if let Err(e) = self.hooks.on_account_registered(&account) {
            if is_new {
                self.own_accounts.remove(&id);
                self.own_order.retain(|x| x != &id);
            }
            return Err(e);
        }

        if !had_active {
            self.set_active_account(&id, true)?;
        }
        Ok(())
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    pub fn get_own_account_by_id(&self, id: &str) -> Option<&MajikContact> {
        self.own_accounts.get(id)
    }

    pub fn get_active_account(&self) -> Option<&MajikContact> {
        self.own_order
            .first()
            .and_then(|id| self.own_accounts.get(id))
    }

    pub fn get_active_account_key(&self) -> Option<&MajikKey> {
        self.own_order.first().and_then(|id| self.keys.get(id))
    }

    pub fn is_account_active(&self, id: &str) -> bool {
        self.own_accounts.contains_key(id) && self.own_order.first().map(String::as_str) == Some(id)
    }

    pub fn list_own_accounts(&self) -> Vec<&MajikContact> {
        self.own_order
            .iter()
            .filter_map(|id| self.own_accounts.get(id))
            .collect()
    }

    /// Wire form for IPC (`MajikContact` itself is not `Serialize`).
    pub fn list_own_accounts_json(&self) -> Vec<SerializedMajikContact> {
        self.list_own_accounts()
            .into_iter()
            .map(|a| a.to_json())
            .collect()
    }

    pub fn active_account_json(&self) -> Option<SerializedMajikContact> {
        self.get_active_account().map(|a| a.to_json())
    }

    pub fn has_signing_capability(&self, account_id: Option<&str>) -> bool {
        let id = match account_id {
            Some(id) => id,
            None => match self.get_active_account() {
                Some(a) => a.id(),
                None => return false,
            },
        };
        self.keys
            .get(id)
            .map(|k| k.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]))
            == Some(true)
    }

    // ── Active account ───────────────────────────────────────────────────────

    /// Move `id` to the front of the order. Unless `bypass_identity` is set, the account must
    /// already be unlocked; otherwise `Ok(false)` is returned (TS behaviour when the unlock
    /// prompt failed or was cancelled).
    pub fn set_active_account(&mut self, id: &str, bypass_identity: bool) -> Result<bool> {
        if !self.own_accounts.contains_key(id) {
            return Ok(false);
        }
        if !bypass_identity && self.keys.ensure_unlocked(id).is_err() {
            return Ok(false);
        }

        let previous = self.own_order.first().cloned();
        self.own_order.retain(|x| x != id);
        self.own_order.insert(0, id.to_string());
        self.persist_account_order();

        if previous.as_deref() != Some(id) {
            let active = self.own_accounts.get(id).map(|a| a.to_json());
            self.emit(ClientEvent::ActiveAccountChange { active, previous });
        }
        Ok(true)
    }

    // ── Lock / unlock / passphrase ───────────────────────────────────────────

    pub fn unlock_account(&mut self, id: &str, passphrase: &str) -> Result<()> {
        self.with_error_event("unlockAccount", Some(id), |c| {
            c.keys.unlock(id, passphrase)?;
            c.emit(ClientEvent::Unlock(id.to_string()));
            Ok(())
        })
    }

    pub fn lock_account(&mut self, id: &str) {
        self.keys.lock(id);
        self.emit(ClientEvent::Lock(id.to_string()));
    }

    pub fn lock_all_accounts(&mut self) {
        self.keys.lock_all();
        for id in &self.own_order {
            self.emit(ClientEvent::Lock(id.clone()));
        }
    }

    pub fn verify_passphrase(&mut self, id: &str, passphrase: &str) -> Result<bool> {
        self.keys.is_passphrase_valid(id, passphrase)
    }

    /// Verify against `id`, or the active account when `id` is `None`.
    pub fn is_passphrase_valid(&mut self, passphrase: &str, id: Option<&str>) -> Result<bool> {
        let target = match id {
            Some(id) => self.own_accounts.get(id).map(|a| a.id().to_string()),
            None => self.get_active_account().map(|a| a.id().to_string()),
        };
        match target {
            Some(id) => self.keys.is_passphrase_valid(&id, passphrase),
            None => Ok(false),
        }
    }

    pub fn update_passphrase(&mut self, id: &str, current: &str, new: &str) -> Result<()> {
        self.with_error_event("updatePassphrase", Some(id), |c| {
            c.keys.update_passphrase(id, current, new)
        })
    }

    /// Recover an account from its backup + mnemonic under a new passphrase. Returns the id.
    pub fn replace_passphrase(
        &mut self,
        backup: &str,
        mnemonic: &str,
        new_passphrase: &str,
        id: &str,
        label: Option<&str>,
    ) -> Result<String> {
        self.with_error_event("replacePassphrase", Some(id), |c| {
            c.keys
                .replace_passphrase(backup, mnemonic, new_passphrase, id, label, None)
        })
    }

    /// `Ok(())` if unlocked, else `UnlockRequired` (the UI prompts and calls `unlock_account`).
    pub fn ensure_identity_unlocked(&mut self, id: &str) -> Result<()> {
        self.keys.ensure_unlocked(id)
    }

    // ── Reset ────────────────────────────────────────────────────────────────

    pub fn reset_data(&mut self) -> Result<()> {
        self.reset_inner()
            .map_err(|e| KeyClientError::Reset(e.to_string()))?;
        self.own_accounts.clear();
        self.own_order.clear();
        self.emit(ClientEvent::ActiveAccountChange {
            active: None,
            previous: None,
        });
        Ok(())
    }

    fn reset_inner(&mut self) -> Result<()> {
        self.hooks.on_reset_key_data()?;
        self.keys.clear()?;
        self.state.clear()?;
        if let Some(db) = &self.db {
            run_maintenance(db)?;
        }
        Ok(())
    }
}
