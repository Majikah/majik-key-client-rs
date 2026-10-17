//! Behavioural tests for the key client. Argon2id runs on every create/unlock, so Cargo.toml
//! optimises dependencies even in dev builds; run with `cargo test` as usual.

use std::sync::{Arc, Mutex};

use majik_key::MnemonicLanguage;
use majik_key_client::{
    init_schema, AccountHooks, ClientEvent, KeyClient, KeyClientError, MajikContact,
    MajikContactMeta, NoHooks, SharedConnection,
};
use rusqlite::Connection;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASS: &str = "correct horse battery staple";
const PASS2: &str = "a completely different passphrase";

fn memory_client() -> KeyClient {
    KeyClient::in_memory(NoHooks)
}

fn shared_conn() -> SharedConnection {
    Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))
}

fn sqlite_client(conn: &SharedConnection) -> KeyClient {
    KeyClient::with_sqlite(NoHooks, Arc::clone(conn)).unwrap()
}

fn stored_json(conn: &SharedConnection, id: &str) -> String {
    conn.lock()
        .unwrap()
        .query_row("SELECT json FROM majik_keys WHERE id = ?1", [id], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
}

#[test]
fn create_account_registers_and_activates() {
    let mut c = memory_client();
    let created = c
        .create_account(MNEMONIC, PASS, Some("Main"), None, MnemonicLanguage::En)
        .unwrap();

    assert_eq!(created.id, created.fingerprint);
    assert!(!created.backup.is_empty());

    let active = c.get_active_account().unwrap();
    assert_eq!(active.id(), created.id);
    assert_eq!(active.meta.label.as_deref(), Some("Main"));
    assert_eq!(active.fingerprint(), created.fingerprint);
    assert!(c.is_account_active(&created.id));
    assert!(c.get_active_account_key().unwrap().is_unlocked());
    assert!(c.has_signing_capability(None));
    assert_eq!(c.list_own_accounts().len(), 1);
}

#[test]
fn create_same_mnemonic_twice_is_rejected_without_touching_the_stored_key() {
    let conn = shared_conn();
    let mut c = sqlite_client(&conn);
    let created = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap();
    let before = stored_json(&conn, &created.id);

    let err = c
        .create_account(MNEMONIC, PASS2, None, None, MnemonicLanguage::En)
        .unwrap_err();
    assert!(matches!(err, KeyClientError::DuplicateAccount));
    assert_eq!(stored_json(&conn, &created.id), before);
}

#[test]
fn sqlite_roundtrip_hydrate_unlock_and_wrong_passphrase() {
    let conn = shared_conn();
    let id = {
        let mut c = sqlite_client(&conn);
        c.create_account(MNEMONIC, PASS, Some("Main"), None, MnemonicLanguage::En)
            .unwrap()
            .id
    };

    let mut c2 = sqlite_client(&conn);
    let report = c2.hydrate().unwrap();
    assert_eq!(report.keys_loaded, 1);
    assert!(report.keys_skipped.is_empty());
    assert!(report.accounts_failed.is_empty());

    assert_eq!(c2.get_active_account().unwrap().id(), id);
    assert!(!c2.get_active_account_key().unwrap().is_unlocked());

    assert!(!c2.is_passphrase_valid("wrong passphrase", None).unwrap());
    assert!(c2.is_passphrase_valid(PASS, None).unwrap());

    assert!(c2.unlock_account(&id, "wrong passphrase").is_err());
    assert!(!c2.get_active_account_key().unwrap().is_unlocked());

    c2.unlock_account(&id, PASS).unwrap();
    assert!(c2.get_active_account_key().unwrap().is_unlocked());
    // Unlocking an already-unlocked account is a no-op, not an error (TS parity).
    c2.unlock_account(&id, PASS).unwrap();
}

#[test]
fn ensure_identity_unlocked_never_prompts() {
    let conn = shared_conn();
    let id = {
        let mut c = sqlite_client(&conn);
        c.create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
            .unwrap()
            .id
    };
    let mut c2 = sqlite_client(&conn);
    c2.hydrate().unwrap();

    let err = c2.ensure_identity_unlocked(&id).unwrap_err();
    assert!(matches!(err, KeyClientError::UnlockRequired(_)));
    assert_eq!(err.kind(), "unlockRequired");

    // A locked account cannot be made active unless the caller bypasses the identity check.
    assert!(!c2.set_active_account(&id, false).unwrap());
}

#[test]
fn active_account_and_order_persist_across_restarts() {
    let conn = shared_conn();
    let (a, b) = {
        let mut c = sqlite_client(&conn);
        let a = c
            .create_account(MNEMONIC, PASS, Some("A"), None, MnemonicLanguage::En)
            .unwrap()
            .id;
        let second = c.generate_mnemonic(128, MnemonicLanguage::En).unwrap();
        let b = c
            .create_account(&second, PASS, Some("B"), None, MnemonicLanguage::En)
            .unwrap()
            .id;

        // First account created stays active; the second is appended.
        assert_eq!(c.get_active_account().unwrap().id(), a);
        assert_eq!(c.list_own_accounts()[1].id(), b);

        assert!(c.set_active_account(&b, true).unwrap());
        assert_eq!(c.get_active_account().unwrap().id(), b);
        (a, b)
    };

    let mut c2 = sqlite_client(&conn);
    c2.hydrate().unwrap();
    let order: Vec<String> = c2
        .list_own_accounts()
        .iter()
        .map(|x| x.id().to_string())
        .collect();
    assert_eq!(order, vec![b, a]);
}

#[test]
fn events_fire_in_ts_order() {
    let mut c = memory_client();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    let sub = c.subscribe(Arc::new(move |e: &ClientEvent| {
        sink.lock().unwrap().push(e.name().to_string());
    }));

    let id = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap()
        .id;
    c.lock_account(&id);
    c.unlock_account(&id, PASS).unwrap();
    c.update_account_label(&id, "Renamed").unwrap();
    assert!(c.remove_own_account(&id).unwrap());

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "active-account-change",
            "new-account",
            "lock",
            "unlock",
            "updated-account",
            "removed-account",
        ]
    );

    assert!(c.unsubscribe(sub));
    assert!(!c.unsubscribe(sub));

    // Wire format spot-check.
    let ev = ClientEvent::RemovedAccount("x".into());
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"type":"removed-account","payload":"x"}"#
    );
}

#[test]
fn duplicate_backup_import_is_rejected_before_anything_is_written() {
    let conn = shared_conn();
    let mut c = sqlite_client(&conn);
    let id = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap()
        .id;
    let backup = c.export_account_mnemonic_backup(&id, MNEMONIC).unwrap();
    let before = stored_json(&conn, &id);

    let err = c
        .import_account_from_mnemonic_backup(
            &backup,
            MNEMONIC,
            PASS2,
            None,
            None,
            MnemonicLanguage::En,
        )
        .unwrap_err();
    assert!(matches!(err, KeyClientError::DuplicateAccount));
    assert_eq!(stored_json(&conn, &id), before);
}

#[test]
fn import_into_a_fresh_client_then_replace_passphrase() {
    // Source device.
    let src = shared_conn();
    let mut a = sqlite_client(&src);
    let id = a
        .create_account(MNEMONIC, PASS, Some("Main"), None, MnemonicLanguage::En)
        .unwrap()
        .id;
    let backup = a.export_account_mnemonic_backup(&id, MNEMONIC).unwrap();

    // Fresh device: import from backup.
    let dst = shared_conn();
    let mut b = sqlite_client(&dst);
    let imported = b
        .import_account_from_mnemonic_backup(
            &backup,
            MNEMONIC,
            PASS,
            Some("Imported"),
            None,
            MnemonicLanguage::En,
        )
        .unwrap();
    assert_eq!(imported.id, id);

    // Forgot the passphrase: recover with backup + mnemonic.
    b.lock_account(&id);
    b.replace_passphrase(&backup, MNEMONIC, PASS2, &id, None)
        .unwrap();
    b.lock_account(&id);
    assert!(b.verify_passphrase(&id, PASS2).unwrap());
    assert!(!b.verify_passphrase(&id, PASS).unwrap());
}

#[test]
fn replace_account_refreshes_label_and_keeps_active() {
    let mut c = memory_client();
    let id = c
        .create_account(MNEMONIC, PASS, Some("Old"), None, MnemonicLanguage::En)
        .unwrap()
        .id;
    let backup = c.export_account_mnemonic_backup(&id, MNEMONIC).unwrap();

    let replaced = c
        .replace_account_from_mnemonic_backup(
            &backup,
            MNEMONIC,
            PASS2,
            Some("New"),
            None,
            MnemonicLanguage::En,
        )
        .unwrap();
    assert_eq!(replaced.id, id);
    assert_eq!(c.list_own_accounts().len(), 1);
    assert_eq!(
        c.get_active_account().unwrap().meta.label.as_deref(),
        Some("New")
    );

    c.lock_account(&id);
    assert!(c.verify_passphrase(&id, PASS2).unwrap());
    assert!(!c.verify_passphrase(&id, PASS).unwrap());
}

#[test]
fn update_passphrase_and_label() {
    let mut c = memory_client();
    let id = c
        .create_account(MNEMONIC, PASS, Some("Main"), None, MnemonicLanguage::En)
        .unwrap()
        .id;

    c.update_passphrase(&id, PASS, PASS2).unwrap();
    c.lock_account(&id);
    assert!(c.verify_passphrase(&id, PASS2).unwrap());
    assert!(!c.verify_passphrase(&id, PASS).unwrap());

    c.update_account_label(&id, "Renamed").unwrap();
    assert_eq!(
        c.get_own_account_by_id(&id).unwrap().meta.label.as_deref(),
        Some("Renamed")
    );
    assert_eq!(c.key_manager().get(&id).unwrap().label(), "Renamed");
}

#[test]
fn remove_active_account_promotes_the_next_one() {
    let mut c = memory_client();
    let a = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap()
        .id;
    let second = c.generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let b = c
        .create_account(&second, PASS, None, None, MnemonicLanguage::En)
        .unwrap()
        .id;

    assert!(c.remove_own_account(&a).unwrap());
    assert!(!c.remove_own_account(&a).unwrap());
    assert_eq!(c.get_active_account().unwrap().id(), b);
    assert!(c.key_manager().get(&a).is_none());
}

#[test]
fn reset_data_clears_memory_and_database() {
    let conn = shared_conn();
    let mut c = sqlite_client(&conn);
    c.create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap();

    c.reset_data().unwrap();
    assert!(c.get_active_account().is_none());
    assert!(c.list_own_accounts().is_empty());

    let keys: i64 = conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM majik_keys", [], |r| r.get(0))
        .unwrap();
    let state: i64 = conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM majik_client_state", [], |r| r.get(0))
        .unwrap();
    assert_eq!((keys, state), (0, 0));
}

#[test]
fn schema_init_is_idempotent_and_matches_ts_tables() {
    let conn = shared_conn();
    init_schema(&conn).unwrap();
    init_schema(&conn).unwrap();

    let mut names: Vec<String> = {
        let guard = conn.lock().unwrap();
        let mut stmt = guard
            .prepare("SELECT name FROM sqlite_master WHERE name LIKE 'majik_%' OR name LIKE 'idx_majik_%' ORDER BY name")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    };
    names.sort();
    assert!(names.contains(&"majik_keys".to_string()));
    assert!(names.contains(&"majik_client_state".to_string()));
    assert!(names.contains(&"idx_majik_keys_timestamp".to_string()));
    assert!(names.contains(&"idx_majik_keys_public_key".to_string()));
}

#[test]
fn error_serialises_for_ipc() {
    let e = KeyClientError::UnlockRequired("abc".into());
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"kind":"unlockRequired","message":"Account \"abc\" must be unlocked first"}"#
    );
}

#[test]
fn own_account_is_a_full_majik_contact() {
    let mut c = memory_client();
    let meta = MajikContactMeta {
        notes: Some("hi".into()),
        ..Default::default()
    };
    let created = c
        .create_account(
            MNEMONIC,
            PASS,
            Some("Main"),
            Some(meta),
            MnemonicLanguage::En,
        )
        .unwrap();

    let acct = c.get_own_account_by_id(&created.id).unwrap();
    assert_eq!(acct.fingerprint(), created.fingerprint);
    assert!(!acct.ml_key().is_empty());
    assert!(!acct.ed_public_key_base64().is_empty());
    assert!(!acct.ml_dsa_public_key_base64().is_empty());
    // Label defaults to the key's label; caller-supplied meta fields are kept.
    assert_eq!(acct.meta.label.as_deref(), Some("Main"));
    assert_eq!(acct.meta.notes.as_deref(), Some("hi"));

    // Persistent JSON form round-trips losslessly.
    let round = MajikContact::from_json(acct.to_json()).unwrap();
    assert_eq!(&round, acct);

    // Event payloads use the serialized contact.
    let ev = ClientEvent::NewAccount(acct.to_json());
    let v = serde_json::to_value(&ev).unwrap();
    assert_eq!(v["type"], "new-account");
    assert!(v["payload"]["publicKeyBase64"].is_string());
    assert_eq!(v["payload"]["id"], created.id.as_str());
    assert_eq!(c.list_own_accounts_json().len(), 1);
    assert_eq!(c.active_account_json().unwrap().id, created.id);
}

struct Recorder {
    log: Arc<Mutex<Vec<String>>>,
    fail_register: bool,
}

impl AccountHooks for Recorder {
    fn on_account_registered(&mut self, a: &MajikContact) -> majik_key_client::Result<()> {
        self.log.lock().unwrap().push(format!("reg:{}", a.id()));
        if self.fail_register {
            return Err(KeyClientError::Invalid("boom".into()));
        }
        Ok(())
    }
    fn on_account_removed(&mut self, id: &str) -> majik_key_client::Result<()> {
        self.log.lock().unwrap().push(format!("rm:{id}"));
        Ok(())
    }
    fn on_reset_key_data(&mut self) -> majik_key_client::Result<()> {
        self.log.lock().unwrap().push("reset".into());
        Ok(())
    }
}

#[test]
fn hooks_run_in_order() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut c = KeyClient::in_memory(Recorder {
        log: Arc::clone(&log),
        fail_register: false,
    });
    let id = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap()
        .id;
    assert!(c.remove_own_account(&id).unwrap());
    c.reset_data().unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![format!("reg:{id}"), format!("rm:{id}"), "reset".to_string()]
    );
}

#[test]
fn failing_registration_hook_rolls_back_the_in_memory_account() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut c = KeyClient::in_memory(Recorder {
        log,
        fail_register: true,
    });
    let err = c
        .create_account(MNEMONIC, PASS, None, None, MnemonicLanguage::En)
        .unwrap_err();
    assert!(matches!(err, KeyClientError::Invalid(_)));
    assert!(c.list_own_accounts().is_empty());
    assert!(c.get_active_account().is_none());
}
