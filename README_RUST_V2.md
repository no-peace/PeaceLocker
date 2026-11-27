# PeaceLocker 2.0 — Rust rewrite

The Rust rewrite is developed on `rewrite/rust-v2`. The root [README.md](README.md) is the canonical guide for setup, build commands, application use, and current limitations.

> **Development warning:** This is an experimental development build. It has not passed a recorded Cargo build/test run, Windows runtime validation, or independent security review. Do not rely on it to protect real data or enforce restrictions.

## Implemented foundations

- Seven-crate Rust workspace and native egui desktop application.
- Interactive ASCII/monospace console with working section navigation.
- First-run PIN/passphrase setup, unlock, persisted lockout, one-time recovery-code display and lock action.
- DPAPI-backed authenticated session and encrypted configuration store.
- Encrypted persistence for rule create/edit/enable/disable/delete operations on Windows.
- Argon2id PIN verifier, AES-256-GCM encryption, fresh single-use data keys, and current-user DPAPI key protection.
- Validated core rule model and process/path/browser-host matching.
- Opt-in read-only Windows process, Explorer and foreground-browser hostname observation.
- Read-only legacy configuration importer for supported DPAPI-wrapped text configuration; plaintext fallback and TPM-wrapped legacy files are rejected/not supported.

## Current application behavior

On Windows, first launch opens the Protection panel for setup. The user creates a passphrase, saves eight one-time recovery codes offline, and acknowledges them. Later launches require the passphrase to unlock the encrypted configuration. Rules are loaded and persisted through the authenticated session.

The Monitoring panel provides manual Start/Stop controls for process, Explorer and foreground-browser observers. Policy matches are informational only: no process is suspended or terminated, no folder access is denied, and no browser navigation is blocked.

## Outstanding work

- Recovery-code unlock/consumption and PIN change.
- Explicit ACL verification, reparse-point hardening and single-instance coordination.
- Durable event history and notification delivery.
- Legacy migration preview and confirmation UI.
- Actual enforcement (requires a separate security design, platform implementation and tests).
- Windows runtime validation, build/test/fmt/Clippy checks, installer, signing and independent security review.

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

**Validation status:** No successful Cargo build/test/format/Clippy run is currently recorded. GitHub Actions checks are unavailable in this working session, and Windows runtime validation has not been completed. See [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) and [README.md](README.md) for the authoritative status.
