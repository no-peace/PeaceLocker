# PeaceLocker 2.0 (Rust rewrite)

This is the new Rust implementation of PeaceLocker. It is being developed separately from the legacy C++ application.

## Current status

**Phase 2 — encrypted storage and legacy DPAPI/text import implementation committed; validation pending.**

The workspace currently contains:
- A Cargo workspace with application, core, security, monitoring, storage, notifications, and Windows platform crates.
- A minimal egui desktop shell and platform-independent application snapshot.
- Argon2id PIN verifier creation and bounded verification.
- 256-bit CSPRNG data keys with zeroization and one-encryption-per-key enforcement.
- AES-256-GCM authenticated envelopes with associated-data support.
- Current-user DPAPI key wrapping and a combined protected configuration envelope.
- 128-bit single-use recovery codes stored as Argon2id verifiers.
- Versioned encrypted configuration store with fresh DEKs, DPAPI wrapping, atomic replacement, and a validated backup.
- Persisted three-attempt/six-hour lockout policy with clock-rollback handling.
- Read-only importer for non-credential settings from legacy DPAPI-wrapped vaults and text configs; TPM-wrapped files are not yet supported.
- Initial unit and Windows integration tests (not yet run).

These are security and storage primitives, not a completed application security workflow. The GUI is not yet wired to the store or lockout service. Migration preview/confirmation and automatic migration orchestration are not implemented. TPM-wrapped legacy vaults, monitoring, and enforcement are not supported yet.

## Build on Windows

Install the stable Rust toolchain with the `rustfmt` and `clippy` components, then run:

```powershell
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p peacelocker-app
```

## Design and implementation documents

- [Architecture](docs/PEACELOCKER_V2_ARCHITECTURE.md)
- [Security and privacy](docs/PEACELOCKER_V2_SECURITY.md)
- [Implementation roadmap](docs/PEACELOCKER_V2_ROADMAP.md)
- [Phase 1 security foundation](docs/PHASE_1_SECURITY_FOUNDATION.md)
- [Phase 2 storage and migration](docs/PHASE_2_STORAGE_AND_MIGRATION.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)

## Important limitations

The code has not yet been compiled or tested. DPAPI is current-user scoped; TPM protection is not implemented. Argon2id parameters still need hardware benchmarking. PIN lockout and encrypted storage primitives exist but are not wired into the GUI. Legacy TPM-wrapped vault migration, monitoring, and enforcement remain unimplemented. Do not use this branch to protect real data.

The legacy C++ implementation remains in the repository as a reference. Do not remove or overwrite it as part of the Rust rewrite.
