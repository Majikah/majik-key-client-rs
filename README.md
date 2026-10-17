# Majik Key Client (Rust)

Rust port of the TS [`MajikKeyClient`](https://www.npmjs.com/package/@majikah/majik-key-client) (+ `MajikKeyManager`, `MajikKeyClientStateManager`, keystore and
client-state adapters), built on the published [`majik-key`](https://crates.io/crates/majik-key) crate.

```
src/
  error.rs          KeyClientError (+ IPC-friendly Serialize)
  events.rs         ClientEvent + EventBus (names match the TS events)
  schema.rs         majik_keys / majik_client_state DDL (same tables as the TS adapters)
  storage.rs        KeystoreRepo / ClientStateRepo traits
  sqlite.rs         rusqlite repos over Arc<Mutex<Connection>>  (your SQLCipher connection)
  memory.rs         in-memory repos (tests)
  key_manager.rs    KeyManager  - owns the unlocked-key cache
  state_manager.rs  ClientStateManager (+ account order)
  client.rs         KeyClient<H: AccountHooks> - the orchestrator (accounts are majik-contact MajikContacts)
tests/client.rs     17 behavioural tests (real majik-key 1.1.1, real Argon2id/ML-KEM/ML-DSA)
```

Requires `majik-key` 1.1.1 (re-exports `majik-contact` 0.2.0) and a recent stable toolchain (verified on 1.91).

Verify:

```
cargo test
```
