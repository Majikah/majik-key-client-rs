//! Synchronous event bus. Mirrors the TS `on` / `off` / `_emit` API; the Tauri layer subscribes
//! once and forwards every event to the webview.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use majik_key::SerializedMajikContact;
use serde::Serialize;

/// Wire format: `{ "type": "new-account", "payload": ... }` (names match the TS event names).
#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ClientEvent {
    NewAccount(SerializedMajikContact),
    RemovedAccount(String),
    UpdatedAccount(SerializedMajikContact),
    ActiveAccountChange {
        active: Option<SerializedMajikContact>,
        previous: Option<String>,
    },
    Unlock(String),
    Lock(String),
    Error {
        message: String,
        context: String,
        id: Option<String>,
    },
    /// Reserved for backup-restore flows (parity with the TS event list).
    RestoreBackup,
}

impl ClientEvent {
    /// The TS event name, e.g. `"active-account-change"`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::NewAccount(_) => "new-account",
            Self::RemovedAccount(_) => "removed-account",
            Self::UpdatedAccount(_) => "updated-account",
            Self::ActiveAccountChange { .. } => "active-account-change",
            Self::Unlock(_) => "unlock",
            Self::Lock(_) => "lock",
            Self::Error { .. } => "error",
            Self::RestoreBackup => "restore-backup",
        }
    }
}

pub type EventListener = Arc<dyn Fn(&ClientEvent) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerId(u64);

#[derive(Default)]
pub struct EventBus {
    listeners: Vec<(ListenerId, EventListener)>,
    next_id: u64,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&mut self, listener: EventListener) -> ListenerId {
        let id = ListenerId(self.next_id);
        self.next_id += 1;
        self.listeners.push((id, listener));
        id
    }

    pub fn unsubscribe(&mut self, id: ListenerId) -> bool {
        let before = self.listeners.len();
        self.listeners.retain(|(lid, _)| *lid != id);
        self.listeners.len() != before
    }

    /// A panicking listener never breaks the client (same guarantee as the TS try/catch).
    pub fn emit(&self, event: &ClientEvent) {
        for (_, listener) in &self.listeners {
            let _ = catch_unwind(AssertUnwindSafe(|| listener(event)));
        }
    }
}
