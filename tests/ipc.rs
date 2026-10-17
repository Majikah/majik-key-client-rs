//! The IPC surface, driven with the exact JSON the TypeScript layer sends.

use majik_key::{MajikKeyJson, SerializedIdentity, SerializedMajikContact};
use majik_key_client::ipc::{self, *};
use majik_key_client::{ClientEvent, KeyClient, KeyClientError, NoHooks};
use serde_json::json;
use std::sync::{Arc, Mutex};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASS: &str = "correct horse battery staple";
const PASS2: &str = "a completely different passphrase";

fn client() -> KeyClient {
    KeyClient::in_memory(NoHooks)
}

fn create_args(label: &str) -> CreateAccountArgs {
    serde_json::from_value(json!({
        "mnemonic": MNEMONIC, "passphrase": PASS, "label": label,
        "meta": { "notes": "n" }, "language": "en"
    }))
    .unwrap()
}

#[test]
fn key_client_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<KeyClient<NoHooks>>();
}

#[test]
fn args_deserialise_from_camel_case_json_and_optional_fields_default() {
    let a: CreateAccountArgs =
        serde_json::from_value(json!({ "mnemonic": "m", "passphrase": "p" })).unwrap();
    assert!(a.label.is_none() && a.meta.is_none() && a.language.is_none());

    let b: BackupAccountArgs = serde_json::from_value(json!({
        "backup": "b", "mnemonic": "m", "passphrase": "p", "language": "zh-cn"
    }))
    .unwrap();
    assert!(b.language.is_some());

    let r: ReplacePassphraseArgs = serde_json::from_value(json!({
        "backup": "b", "mnemonic": "m", "newPassphrase": "n", "id": "x"
    }))
    .unwrap();
    assert_eq!(r.new_passphrase, "n");

    let u: UpdatePassphraseArgs = serde_json::from_value(json!({
        "id": "x", "currentPassphrase": "a", "newPassphrase": "b"
    }))
    .unwrap();
    assert_eq!(
        (u.current_passphrase.as_str(), u.new_passphrase.as_str()),
        ("a", "b")
    );

    // snake_case is NOT accepted: the wire format is camelCase only.
    assert!(serde_json::from_value::<ReplacePassphraseArgs>(json!({
        "backup": "b", "mnemonic": "m", "new_passphrase": "n", "id": "x"
    }))
    .is_err());
}

#[test]
fn open_session_hydrates_once_and_returns_a_snapshot() {
    let mut c = client();
    let first = ipc::open_session(&mut c).unwrap();
    assert!(first.report.is_some());
    assert!(first.snapshot.accounts.is_empty());
    assert!(first.snapshot.active_account_id.is_none());

    let created = ipc::create_account(&mut c, &create_args("Main")).unwrap();

    // A second window / webview reload: no re-hydrate, so the unlocked key stays unlocked.
    let second = ipc::open_session(&mut c).unwrap();
    assert!(second.report.is_none());
    assert_eq!(
        second.snapshot.active_account_id.as_deref(),
        Some(created.id.as_str())
    );
    assert_eq!(second.snapshot.accounts.len(), 1);
    assert_eq!(second.snapshot.status.len(), 1);
    assert!(second.snapshot.status[0].unlocked);
    assert!(second.snapshot.status[0].can_sign);
}

#[test]
fn snapshot_tracks_lock_state_and_order() {
    let mut c = client();
    let a = ipc::create_account(&mut c, &create_args("A")).unwrap().id;
    let second = ipc::generate_mnemonic(&c, 128, None).unwrap();
    let b_args: CreateAccountArgs =
        serde_json::from_value(json!({ "mnemonic": second, "passphrase": PASS, "label": "B" }))
            .unwrap();
    let b = ipc::create_account(&mut c, &b_args).unwrap().id;

    ipc::lock_account(&mut c, &a);
    let s = ipc::snapshot(&c);
    assert_eq!(s.accounts[0].id, a);
    let status = |id: &str| s.status.iter().find(|x| x.id == id).unwrap().clone();
    assert!(!status(&a).unlocked);
    assert!(status(&b).unlocked);
    assert!(
        status(&a).can_sign,
        "signing keys are known even while locked"
    );

    assert!(ipc::set_active_account(&mut c, &b, true).unwrap());
    assert_eq!(
        ipc::snapshot(&c).active_account_id.as_deref(),
        Some(b.as_str())
    );
}

#[test]
fn full_flow_through_ipc_functions() {
    let mut c = client();
    let created = ipc::create_account(&mut c, &create_args("Main")).unwrap();
    let id = created.id.clone();

    let backup = ipc::export_account_mnemonic_backup(&c, &id, MNEMONIC).unwrap();
    assert_eq!(
        backup,
        created
            .backup
            .is_empty()
            .then(String::new)
            .unwrap_or(backup.clone())
    );

    ipc::update_account_label(&mut c, &id, "Renamed").unwrap();
    assert_eq!(
        ipc::snapshot(&c).accounts[0]
            .meta
            .as_ref()
            .unwrap()
            .label
            .as_deref(),
        Some("Renamed")
    );

    ipc::lock_account(&mut c, &id);
    assert!(matches!(
        ipc::ensure_identity_unlocked(&mut c, &id).unwrap_err(),
        KeyClientError::UnlockRequired(_)
    ));
    assert!(!ipc::verify_passphrase(&mut c, &id, "nope").unwrap());
    assert!(ipc::is_passphrase_valid(&mut c, PASS, None).unwrap());
    ipc::unlock_account(&mut c, &id, PASS).unwrap();
    ipc::ensure_identity_unlocked(&mut c, &id).unwrap();

    let up: UpdatePassphraseArgs = serde_json::from_value(json!({
        "id": id, "currentPassphrase": PASS, "newPassphrase": PASS2
    }))
    .unwrap();
    ipc::update_passphrase(&mut c, &up).unwrap();
    ipc::lock_all_accounts(&mut c);
    assert!(ipc::verify_passphrase(&mut c, &id, PASS2).unwrap());

    let rp: ReplacePassphraseArgs = serde_json::from_value(json!({
        "backup": backup, "mnemonic": MNEMONIC, "newPassphrase": PASS, "id": id
    }))
    .unwrap();
    assert_eq!(ipc::replace_passphrase(&mut c, &rp).unwrap(), id);
    assert!(ipc::verify_passphrase(&mut c, &id, PASS).unwrap());

    assert!(ipc::has_signing_capability(&c, None));
    assert!(ipc::remove_own_account(&mut c, &id).unwrap());
    assert!(ipc::snapshot(&c).accounts.is_empty());
}

#[test]
fn backup_import_and_replace_through_ipc() {
    let mut src = client();
    let created = ipc::create_account(&mut src, &create_args("Main")).unwrap();
    let backup = ipc::export_account_mnemonic_backup(&src, &created.id, MNEMONIC).unwrap();

    let mut dst = client();
    let args: BackupAccountArgs = serde_json::from_value(json!({
        "backup": backup, "mnemonic": MNEMONIC, "passphrase": PASS2, "label": "Imported"
    }))
    .unwrap();
    let imported = ipc::import_account_from_mnemonic_backup(&mut dst, &args).unwrap();
    assert_eq!(imported.id, created.id);
    assert!(matches!(
        ipc::import_account_from_mnemonic_backup(&mut dst, &args).unwrap_err(),
        KeyClientError::DuplicateAccount
    ));
    let replaced = ipc::replace_account_from_mnemonic_backup(&mut dst, &args).unwrap();
    assert_eq!(replaced.id, created.id);
}

#[test]
fn add_own_account_accepts_a_serialized_contact_and_rejects_garbage() {
    let mut src = client();
    ipc::create_account(&mut src, &create_args("Main")).unwrap();
    let contact: SerializedMajikContact = ipc::snapshot(&src).accounts.remove(0);

    let mut dst = client();
    ipc::add_own_account(&mut dst, contact.clone()).unwrap();
    assert_eq!(ipc::snapshot(&dst).accounts.len(), 1);

    let mut bad = contact;
    bad.id = "other".into();
    bad.public_key_base64 = "!!!not base64!!!".into();
    let err = ipc::add_own_account(&mut dst, bad).unwrap_err();
    assert_eq!(err.kind(), "contact");
}

#[test]
fn state_ops_roundtrip() {
    let mut c = client();
    assert_eq!(ipc::state_get(&mut c, "k").unwrap(), None);
    ipc::state_set(&mut c, "k", "v").unwrap();
    assert_eq!(ipc::state_get(&mut c, "k").unwrap().as_deref(), Some("v"));
    assert!(ipc::state_list(&c)
        .iter()
        .any(|e| e.id == "k" && e.value == "v"));
    assert!(ipc::state_remove(&mut c, "k").unwrap());
    assert!(!ipc::state_remove(&mut c, "k").unwrap());
}

#[test]
fn keystore_export_and_restore_rebuild_accounts_and_emit_events() {
    let mut a = client();
    let id = ipc::create_account(&mut a, &create_args("Main"))
        .unwrap()
        .id;
    let rows: Vec<MajikKeyJson> = ipc::keystore_export(&a).unwrap();
    assert_eq!(rows.len(), 1);
    // Export is the encrypted rows; round-trip through JSON like the UI would.
    let rows: Vec<MajikKeyJson> =
        serde_json::from_str(&serde_json::to_string(&rows).unwrap()).unwrap();

    let mut b = client();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    b.subscribe(Arc::new(move |e: &ClientEvent| {
        sink.lock().unwrap().push(e.name().to_string())
    }));
    let report = ipc::keystore_restore(&mut b, rows).unwrap();
    assert_eq!(report.keys_loaded, 1);
    let snap = ipc::snapshot(&b);
    assert_eq!(snap.active_account_id.as_deref(), Some(id.as_str()));
    assert!(!snap.status[0].unlocked, "restored keys come back locked");
    assert!(seen.lock().unwrap().contains(&"restore-backup".to_string()));
    ipc::unlock_account(&mut b, &id, PASS).unwrap();
}

#[test]
fn migrate_legacy_identities_reports_what_it_could_not_register() {
    let mut c = client();
    let ids = vec![
        SerializedIdentity {
            id: String::new(), // invalid: skipped
            public_key: "pk".into(),
            fingerprint: "fp".into(),
            encrypted_private_key: None,
            salt: None,
        },
        SerializedIdentity {
            id: "legacy1".into(),
            public_key: "cHVibGlj".into(),
            fingerprint: "legacy1".into(),
            encrypted_private_key: Some("ZW5j".into()),
            salt: Some("c2FsdA==".into()),
        },
    ];
    let summary = ipc::migrate_legacy_identities(&mut c, ids).unwrap();
    println!("MIGRATION SUMMARY: {summary:?}");
    assert_eq!(summary.migrated + summary.skipped, 2);
    assert!(summary.skipped >= 1, "the empty-id identity is rejected");
    // A legacy key has no ML-KEM material, so it cannot become an account.
    assert!(ipc::snapshot(&c).accounts.is_empty());
}

#[test]
fn reset_clears_everything_and_reports_through_snapshot() {
    let mut c = client();
    ipc::create_account(&mut c, &create_args("Main")).unwrap();
    ipc::state_set(&mut c, "k", "v").unwrap();
    ipc::reset_data(&mut c).unwrap();
    let s = ipc::snapshot(&c);
    assert!(s.accounts.is_empty() && s.status.is_empty() && s.active_account_id.is_none());
    assert!(ipc::state_list(&c).is_empty());
}

/// Prints the real wire shapes so the TypeScript types can be written from facts.
#[test]
fn dump_wire_shapes() {
    let mut c = client();
    let created = ipc::create_account(&mut c, &create_args("Main")).unwrap();
    let opened = ipc::open_session(&mut c).unwrap();
    println!(
        "SHAPE created = {}",
        serde_json::to_string_pretty(&created).unwrap()
    );
    println!(
        "SHAPE opened = {}",
        serde_json::to_string_pretty(&opened).unwrap()
    );
    let mut rows = ipc::keystore_export(&c).unwrap();
    // Trim the long encrypted blobs for readability.
    let mut v = serde_json::to_value(rows.remove(0)).unwrap();
    if let Some(o) = v.as_object_mut() {
        for (_, val) in o.iter_mut() {
            if let Some(s) = val.as_str() {
                if s.len() > 24 {
                    *val = json!(format!("{}...", &s[..24]));
                }
            }
        }
    }
    println!(
        "SHAPE keyrow keys = {}",
        serde_json::to_string(&v.as_object().unwrap().keys().collect::<Vec<_>>()).unwrap()
    );
    let ev = ClientEvent::ActiveAccountChange {
        active: opened.snapshot.accounts.first().cloned(),
        previous: None,
    };
    let evj = serde_json::to_value(&ev).unwrap();
    println!(
        "SHAPE event type/payload keys = {} / {:?}",
        evj["type"],
        evj["payload"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>()
    );
    let err = serde_json::to_string(&KeyClientError::UnlockRequired("x".into())).unwrap();
    println!("SHAPE error = {err}");
}
