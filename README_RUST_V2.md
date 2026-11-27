# PeaceLocker 2.0 — Rust rewrite

The Rust rewrite is developed on `rewrite/rust-v2`. The root [README.md](README.md) is the canonical guide for setup, build commands, current application behavior, and limitations.

> **Development warning:** This is an experimental, unvalidated development build, not a production security product. Do not rely on it to protect real data or block processes, folders, or websites.

## Implemented foundations

- Seven-crate Rust workspace and native egui desktop shell.
- Core state machine, typed commands, validated rules, normalized monitor events, and bounded event queue.
- Rule-management UI for create, edit, enable/disable, and delete (currently in-memory only).
- Argon2id PIN verifier and persisted failed-attempt/lockout policy.
- AES-256-GCM authenticated configuration encryption with a fresh single-use data key per save.
- Current-user Windows DPAPI key protection.
- One-time 128-bit recovery-code generation and verifier storage primitives.
- Versioned encrypted configuration store, atomic replacement, validated backup/restore, typed rule persistence, and no-clobber first-run creation.
- Read-only legacy configuration importer for supported DPAPI-wrapped text configuration; plaintext fallback and TPM-wrapped legacy files are rejected/not supported.
- Opt-in Windows process enumeration, Explorer folder observation, and foreground supported-browser hostname observation.
- Windows PIN-session orchestration API for setup, unlock, persisted lockout, and rule snapshot saves (not yet connected to egui).

## Current application behavior

On Windows, the egui app provides manual Start/Stop controls for process, Explorer, and foreground-browser observers. The Rule management panel currently changes only in-memory core state. Policy matches are informational; no process, folder, or browser enforcement is performed.

The security session and encrypted storage APIs exist, but the app does not yet show PIN setup/unlock screens or load/save rules from the store. The app currently does not create or resolve a secure per-user data directory.

## Outstanding work

- Interactive first-run PIN setup, PIN confirmation, unlock, recovery-code display/acknowledgement, and lock UI.
- Secure per-user data-directory resolution and Windows ACL verification.
- Connect app startup, core state, and rule CRUD to the authenticated encrypted session.
- Recovery-code unlock/consumption and PIN change.
- Durable event history and notification delivery.
- Explicit legacy migration preview and confirmation.
- Windows runtime validation for process, Explorer, and browser monitoring.
- Build, formatting, Clippy, unit/integration tests, and independent security review.
- Any actual process, filesystem, or network enforcement (requires a separate security design and tests).

## Build and validation

Install Rust stable (edition 2024; workspace minimum Rust 1.85), rustfmt, Clippy, Visual Studio Build Tools with Desktop development with C++, and a Windows SDK.

From the repository root in PowerShell:

```powershell
git switch rewrite/rust-v2
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p peacelocker-app
```

**Validation status:** No successful Cargo build/test/format/Clippy run is currently recorded. GitHub Actions checks are unavailable in this working session, and Windows runtime validation has not been completed. See [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) and [README.md](README.md) for the current authoritative status.
