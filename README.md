# Majik Key Client (Rust)

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white&style=for-the-badge)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=for-the-badge&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

[![Crates.io](https://img.shields.io/crates/v/majik-key-client.svg?logo=rust&color=D34516)](https://crates.io/crates/majik-key-client) [![Documentation](https://docs.rs/majik-key-client/badge.svg)](https://docs.rs/majik-key) ![crates downloads](https://img.shields.io/crates/d/majik-key-client?logo=rust&color=D34516) [![License](https://img.shields.io/badge/License-Apache_2.0-D34516.svg)](https://opensource.org/licenses/Apache-2.0) ![Rust](https://img.shields.io/badge/Rust-Ready-D34516) 

**Majik Key Client** is the foundational root class that powers all Majikah application clients. It acts as the central orchestration layer for `@majikah/majik-key`, handling everything from multi-account lifecycle management to client state persistence, so downstream apps (like Majik Signature or Majik Buwiz) get unified, battle-tested cryptographic management out of the box.

Rust port of the TS [`MajikKeyClient`](https://www.npmjs.com/package/@majikah/majik-key-client) (+ `MajikKeyManager`, `MajikKeyClientStateManager`, keystore and
client-state adapters), built on the published [`majik-key`](https://crates.io/crates/majik-key) crate.

---

## Why Majik Key Client?
[![Zenodo](https://img.shields.io/badge/Technical%20Whitepaper-Zenodo-1682D4?style=for-the-badge&logo=zenodo&logoColor=white)](https://doi.org/10.5281/zenodo.23208491) [![Majikah](https://img.shields.io/badge/Read%20the%20Article-Majikah-EA7F05?style=for-the-badge)](https://majikah.solutions/articles/majik-key-whitepaper)



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

---

## License

**License:** [Apache-2.0](LICENSE) — free for personal and commercial use.

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)


**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)

**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)

**Project Repository**: [https://github.com/Majikah/majik-key-client-rs](https://github.com/Majikah/majik-key-client-rs)

**Technical Whitepaper**: [https://zenodo.org/records/23208491](https://zenodo.org/records/23208491)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)