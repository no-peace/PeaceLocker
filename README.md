# PeaceLocker

PeaceLocker is being developed as a Windows desktop privacy and activity-restriction application.

## Project tracks

### Legacy implementation

The original application is implemented in C++ and uses Win32 APIs. Its source remains in the repository as a reference and is not being modified by the Rust rewrite.

### PeaceLocker 2.0 — Rust rewrite

The Rust implementation is being developed on the `rewrite/rust-v2` branch.

**Current status: Phase 0 — workspace foundation in progress.**

The Rust track currently includes:
- A Cargo workspace split into application, core, security, monitoring, storage, notifications, and Windows platform crates.
- An initial egui desktop shell.
- A platform-independent application state snapshot.
- Initial core unit tests.
- Windows CI for formatting, Clippy, and tests.

The placeholder crates do not yet implement their named security or platform features. This build does not authenticate users, encrypt files/configuration, monitor activity, capture webcam images, send Discord notifications, or enforce restrictions. Do not use it to protect real data.

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
- [Rust v2 development notes](README_RUST_V2.md)

## Development policy

- Keep the legacy implementation intact during the rewrite.
- Do not add plaintext fallback for security-sensitive storage.
- Keep unsafe Windows FFI isolated in the Windows platform crate.
- Do not describe best-effort monitoring as filesystem or network access control.
- Do not enable webcam capture or activity telemetry without explicit user opt-in.
- Run formatting, linting, and tests before milestone commits.
