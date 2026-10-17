//! Transport-agnostic IPC surface for `KeyClient`.
//!
//! This module has no Tauri dependency. It defines the wire DTOs (camelCase JSON, exactly what the
//! TypeScript layer sends and receives) and one generic function per operation. The Tauri plugin
//! is a thin shell that locks a `KeyClient`, calls these functions and returns their results, so
//! any other client built on `KeyClient<H>` (e.g. the signature client's `KeyClient<SigHooks>`)
//! can expose the identical command set by calling the same functions.
//!
//! Secrets: argument structs that carry a mnemonic or passphrase zeroize them on drop and do not
//! implement `Debug`. Private keys and mnemonics-at-rest never leave Rust; the only secrets that
//! cross the boundary are the ones the user types (passphrase, mnemonic) on the way in.

use majik_key::{
    MajikContact, MajikContactMeta, MajikKeyJson, MnemonicLanguage, SerializedIdentity,
    SerializedMajikContact,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::client::{
    AccountHooks, CreatedAccount, HydrateReport, ImportedAccount, KeyClient, MigrationSummary,
};
use crate::error::Result;

/// Event channel the plugin emits on. Payload: `{ "type": "...", "payload": ... }`.
pub const EVENT_CHANNEL: &str = "majik-key-client:event";

// ─── Arguments ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountArgs {
    pub mnemonic: String,
    pub passphrase: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub label: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    pub meta: Option<MajikContactMeta>,
    /// Defaults to English.
    #[serde(default)]
    #[zeroize(skip)]
    pub language: Option<MnemonicLanguage>,
}

/// Used by both `import_account_from_mnemonic_backup` and `replace_account_from_mnemonic_backup`.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct BackupAccountArgs {
    pub backup: String,
    pub mnemonic: String,
    pub passphrase: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub label: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    pub meta: Option<MajikContactMeta>,
    #[serde(default)]
    #[zeroize(skip)]
    pub language: Option<MnemonicLanguage>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ReplacePassphraseArgs {
    pub backup: String,
    pub mnemonic: String,
    pub new_passphrase: String,
    #[zeroize(skip)]
    pub id: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub label: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePassphraseArgs {
    #[zeroize(skip)]
    pub id: String,
    pub current_passphrase: String,
    pub new_passphrase: String,
}

// ─── Results ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub id: String,
    pub unlocked: bool,
    /// The account holds the Ed25519 + ML-DSA-87 signing keys (true for locked accounts too).
    pub can_sign: bool,
}

/// Everything the TS read-model needs for synchronous getters. `accounts` is in account order,
/// so `accounts[0]` is the active account.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub accounts: Vec<SerializedMajikContact>,
    pub active_account_id: Option<String>,
    pub status: Vec<AccountStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedSession {
    /// `Some` only for the call that actually hydrated; `None` if the session was already open.
    pub report: Option<HydrateReport>,
    pub snapshot: Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateEntryDto {
    pub id: String,
    pub value: String,
}

// ─── Operations ──────────────────────────────────────────────────────────────

pub fn snapshot<H: AccountHooks>(c: &KeyClient<H>) -> Snapshot {
    let accounts = c.list_own_accounts_json();
    let status = accounts
        .iter()
        .map(|a| AccountStatus {
            id: a.id.clone(),
            unlocked: c.is_account_unlocked(&a.id),
            can_sign: c.has_signing_capability(Some(&a.id)),
        })
        .collect();
    Snapshot {
        accounts,
        active_account_id: c.get_active_account().map(|a| a.id().to_string()),
        status,
    }
}

/// Hydrate on first call only; later calls (other windows, webview reloads) just snapshot.
pub fn open_session<H: AccountHooks>(c: &mut KeyClient<H>) -> Result<OpenedSession> {
    let report = if c.is_hydrated() {
        None
    } else {
        Some(c.hydrate()?)
    };
    Ok(OpenedSession {
        report,
        snapshot: snapshot(c),
    })
}

/// Force a reload from storage. This re-locks every key.
pub fn hydrate<H: AccountHooks>(c: &mut KeyClient<H>) -> Result<HydrateReport> {
    c.hydrate()
}

pub fn generate_mnemonic<H: AccountHooks>(
    c: &KeyClient<H>,
    strength: u32,
    language: Option<MnemonicLanguage>,
) -> Result<String> {
    c.generate_mnemonic(strength, language.unwrap_or_default())
}

pub fn create_account<H: AccountHooks>(
    c: &mut KeyClient<H>,
    args: &CreateAccountArgs,
) -> Result<CreatedAccount> {
    c.create_account(
        &args.mnemonic,
        &args.passphrase,
        args.label.as_deref(),
        args.meta.clone(),
        args.language.unwrap_or_default(),
    )
}

pub fn import_account_from_mnemonic_backup<H: AccountHooks>(
    c: &mut KeyClient<H>,
    args: &BackupAccountArgs,
) -> Result<ImportedAccount> {
    c.import_account_from_mnemonic_backup(
        &args.backup,
        &args.mnemonic,
        &args.passphrase,
        args.label.as_deref(),
        args.meta.clone(),
        args.language.unwrap_or_default(),
    )
}

pub fn replace_account_from_mnemonic_backup<H: AccountHooks>(
    c: &mut KeyClient<H>,
    args: &BackupAccountArgs,
) -> Result<ImportedAccount> {
    c.replace_account_from_mnemonic_backup(
        &args.backup,
        &args.mnemonic,
        &args.passphrase,
        args.label.as_deref(),
        args.meta.clone(),
        args.language.unwrap_or_default(),
    )
}

/// The account must be unlocked.
pub fn export_account_mnemonic_backup<H: AccountHooks>(
    c: &KeyClient<H>,
    id: &str,
    mnemonic: &str,
) -> Result<String> {
    c.export_account_mnemonic_backup(id, mnemonic)
}

pub fn add_own_account<H: AccountHooks>(
    c: &mut KeyClient<H>,
    account: SerializedMajikContact,
) -> Result<()> {
    c.add_own_account(MajikContact::from_json(account)?)
}

pub fn remove_own_account<H: AccountHooks>(c: &mut KeyClient<H>, id: &str) -> Result<bool> {
    c.remove_own_account(id)
}

pub fn update_account_label<H: AccountHooks>(
    c: &mut KeyClient<H>,
    id: &str,
    label: &str,
) -> Result<()> {
    c.update_account_label(id, label)
}

pub fn set_active_account<H: AccountHooks>(
    c: &mut KeyClient<H>,
    id: &str,
    bypass_identity: bool,
) -> Result<bool> {
    c.set_active_account(id, bypass_identity)
}

pub fn unlock_account<H: AccountHooks>(
    c: &mut KeyClient<H>,
    id: &str,
    passphrase: &str,
) -> Result<()> {
    c.unlock_account(id, passphrase)
}

pub fn lock_account<H: AccountHooks>(c: &mut KeyClient<H>, id: &str) {
    c.lock_account(id);
}

pub fn lock_all_accounts<H: AccountHooks>(c: &mut KeyClient<H>) {
    c.lock_all_accounts();
}

pub fn verify_passphrase<H: AccountHooks>(
    c: &mut KeyClient<H>,
    id: &str,
    passphrase: &str,
) -> Result<bool> {
    c.verify_passphrase(id, passphrase)
}

/// Verify against `id`, or the active account when `id` is `None`.
pub fn is_passphrase_valid<H: AccountHooks>(
    c: &mut KeyClient<H>,
    passphrase: &str,
    id: Option<&str>,
) -> Result<bool> {
    c.is_passphrase_valid(passphrase, id)
}

pub fn update_passphrase<H: AccountHooks>(
    c: &mut KeyClient<H>,
    args: &UpdatePassphraseArgs,
) -> Result<()> {
    c.update_passphrase(&args.id, &args.current_passphrase, &args.new_passphrase)
}

pub fn replace_passphrase<H: AccountHooks>(
    c: &mut KeyClient<H>,
    args: &ReplacePassphraseArgs,
) -> Result<String> {
    c.replace_passphrase(
        &args.backup,
        &args.mnemonic,
        &args.new_passphrase,
        &args.id,
        args.label.as_deref(),
    )
}

/// `Ok(())` if unlocked; `UnlockRequired` otherwise (the TS layer prompts and retries).
pub fn ensure_identity_unlocked<H: AccountHooks>(c: &mut KeyClient<H>, id: &str) -> Result<()> {
    c.ensure_identity_unlocked(id)
}

pub fn has_signing_capability<H: AccountHooks>(c: &KeyClient<H>, id: Option<&str>) -> bool {
    c.has_signing_capability(id)
}

pub fn reset_data<H: AccountHooks>(c: &mut KeyClient<H>) -> Result<()> {
    c.reset_data()
}

// ── Client state (generic key/value; higher clients keep their preferences here) ──

pub fn state_get<H: AccountHooks>(c: &mut KeyClient<H>, key: &str) -> Result<Option<String>> {
    c.state_mut().get(key)
}

pub fn state_set<H: AccountHooks>(c: &mut KeyClient<H>, key: &str, value: &str) -> Result<()> {
    c.state_mut().set(key, value)
}

pub fn state_remove<H: AccountHooks>(c: &mut KeyClient<H>, key: &str) -> Result<bool> {
    c.state_mut().remove(key)
}

pub fn state_list<H: AccountHooks>(c: &KeyClient<H>) -> Vec<StateEntryDto> {
    c.state()
        .list_cached_entries()
        .into_iter()
        .map(|e| StateEntryDto {
            id: e.id,
            value: e.value,
        })
        .collect()
}

// ── Keystore backup / migration ──

/// The stored rows: encrypted key material only, safe to hand to the UI for a file backup.
pub fn keystore_export<H: AccountHooks>(c: &KeyClient<H>) -> Result<Vec<MajikKeyJson>> {
    c.key_manager().to_json()
}

pub fn keystore_restore<H: AccountHooks>(
    c: &mut KeyClient<H>,
    keys: Vec<MajikKeyJson>,
) -> Result<HydrateReport> {
    c.restore_keystore_from_json(&keys)
}

pub fn migrate_legacy_identities<H: AccountHooks>(
    c: &mut KeyClient<H>,
    identities: Vec<SerializedIdentity>,
) -> Result<MigrationSummary> {
    c.migrate_legacy_identities(&identities)
}
