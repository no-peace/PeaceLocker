# PeaceLocker

PeaceLocker is being developed as a Windows desktop privacy and activity-restriction application.

## Project tracks

### Legacy implementation

The original application is implemented in C++ and uses Win32 APIs. Its source remains in the repository as a reference and is not being modified by the Rust rewrite.

### PeaceLocker 2.0 — Rust rewrite

The Rust implementation is being developed on the `rewrite/rust-v2` branch.

**Current status: Phase 2 — encrypted storage and legacy DPAPI/text import implementation committed; validation pending.**

The Rust track currently includes:
- A Cargo workspace split into application, core, security, monitoring, storage, notifications, and Windows platform crates.
- An initial egui desktop shell and platform-independent application state.
- Argon2id PIN verifier primitives with random salts and bounded verifier parameters.
- AES-256-GCM authenticated encryption with a single-use data-key lifecycle.
- Current-user Windows DPAPI key protection and a combined protected configuration envelope.
- 128-bit one-time recovery-code generation and Argon2id verifiers.
- Versioned encrypted configuration storage with fresh DEKs, DPAPI wrapping, atomic replacement, and a validated backup.
- Persisted three-attempt/six-hour lockout policy.
- Read-only legacy DPAPI/text importer for non-credential settings; legacy TPM-wrapped files are not yet supported.
- Initial unit and Windows integration tests (written, not yet executed).

The security, lockout, and encrypted-storage primitives are not yet integrated into the desktop UI. The legacy DPAPI importer is read-only; migration preview/confirmation and TPM-wrapped legacy import remain outstanding. Monitoring and enforcement are not implemented. Compilation, Clippy, tests, Windows runtime behavior, and independent security review are still pending. **Do not use the Rust rewrite to protect real data.**

## Rust development

Install the stable Rust toolchain with `rustfmt` and `clippy`.

From the repository root:

```powershell
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p peacelocker-app
```

## Design documents

- [Rust v2 architecture](docs/PEACELOCKER_V2_ARCHITECTURE.md)
- [Security and privacy specification](docs/PEACELOCKER_V2_SECURITY.md)
- [Implementation roadmap](docs/PEACELOCKER_V2_ROADMAP.md)
- [Phase 1 security foundation](docs/PHASE_1_SECURITY_FOUNDATION.md)
- [Phase 2 storage and migration](docs/PHASE_2_STORAGE_AND_MIGRATION.md)
- [Phase 3 core engine](docs/PHASE_3_CORE_ENGINE.md)
- [Phase 4 monitoring](docs/PHASE_4_MONITORING.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)

## Development policy

- Keep the legacy implementation intact during the rewrite.
- Do not add plaintext fallback for security-sensitive storage.
- Keep unsafe Windows FFI isolated in the Windows platform crate.
- Do not describe best-effort monitoring as filesystem or network access control.
- Do not enable webcam capture or activity telemetry without explicit user opt-in.
- Run formatting, linting, tests, and Windows runtime checks before release.
