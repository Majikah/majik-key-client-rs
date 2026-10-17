//! # majik-key-client
//!
//! Account/session client for [`majik-key`](https://crates.io/crates/majik-key): the Rust port of
//! the TS `MajikKeyClient` (+ `MajikKeyManager`, `MajikKeyClientStateManager` and the keystore /
//! client-state adapters).
//!
//! Higher-level clients (signature, buwiz, ...) own a `KeyClient<TheirHooks>` and implement
//! [`AccountHooks`] to keep their own directories in sync.

pub mod client;
pub mod error;
pub mod events;
pub mod ipc;
pub mod key_manager;
pub mod memory;
pub mod schema;
pub mod sqlite;
pub mod state_manager;
pub mod storage;

pub use client::{
    AccountHooks, CreatedAccount, HydrateReport, ImportedAccount, KeyClient, MigrationSummary,
    NoHooks, SkippedItemJson,
};
pub use error::{KeyClientError, Result};
pub use events::{ClientEvent, EventBus, EventListener, ListenerId};
pub use key_manager::{KeyManager, MigrationResult, SkippedItem};
/// Re-exported from `majik-key` so every crate in the stack shares one `majik-contact` version.
pub use majik_key::{
    MajikContact, MajikContactMeta, MajikKeyJson, MnemonicLanguage, SerializedIdentity,
    SerializedMajikContact,
};
pub use memory::{MemoryClientStateRepo, MemoryKeystoreRepo};
pub use sqlite::{
    init_schema, run_maintenance, SharedConnection, SqliteClientStateRepo, SqliteKeystoreRepo,
};
pub use state_manager::{ClientStateManager, STATE_KEY_ACCOUNT_ORDER};
pub use storage::{ClientStateEntry, ClientStateRepo, KeystoreRepo};
