//! Error type for the client layer.

use majik_key::majik_contact::MajikContactError;
use majik_key::MajikKeyError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyClientError {
    /// Any error bubbling up from the `majik-key` crate (crypto, validation, bad passphrase...).
    #[error(transparent)]
    Key(#[from] MajikKeyError),

    /// A `majik-contact` error (e.g. an invalid serialized contact passed to `add_own_account`).
    #[error(transparent)]
    Contact(#[from] MajikContactError),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Account with the same ID already exists")]
    DuplicateAccount,

    /// The account exists but is locked. The caller (UI) must collect a passphrase and call
    /// `unlock_account`. This replaces the TS `promptFn` / `onUnlockRequested` / `window.prompt`
    /// flow: Rust never prompts.
    #[error("Account \"{0}\" must be unlocked first")]
    UnlockRequired(String),

    #[error("{0}")]
    Invalid(String),

    #[error("Failed to reset key data: {0}")]
    Reset(String),
}

pub type Result<T> = std::result::Result<T, KeyClientError>;

impl KeyClientError {
    /// Stable machine-readable discriminant for the TS side.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Key(_) => "key",
            Self::Contact(_) => "contact",
            Self::Storage(_) => "storage",
            Self::AccountNotFound(_) => "accountNotFound",
            Self::DuplicateAccount => "duplicateAccount",
            Self::UnlockRequired(_) => "unlockRequired",
            Self::Invalid(_) => "invalid",
            Self::Reset(_) => "reset",
        }
    }
}

impl From<rusqlite::Error> for KeyClientError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for KeyClientError {
    fn from(e: serde_json::Error) -> Self {
        Self::Storage(format!("JSON error: {e}"))
    }
}

/// Serialises as `{ "kind": "...", "message": "..." }` so Tauri commands can return it directly.
impl serde::Serialize for KeyClientError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("KeyClientError", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
