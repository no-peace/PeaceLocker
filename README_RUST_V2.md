# PeaceLocker 2.0 (Rust rewrite)

This is the new Rust implementation of PeaceLocker. It is being developed separately from the legacy C++ application.

## Current status

**Phase 0 — workspace foundation (in progress).**

The repository currently contains:
- A Cargo workspace with separated application, core, security, monitoring, storage, notifications, and Windows platform crates.
- A minimal egui desktop shell.
- A platform-independent application snapshot.
- Initial core unit tests.
- Windows GitHub Actions checks for formatting, Clippy, and tests.

The security, monitoring, storage, and notification crates are boundaries only. They do not claim to implement those features yet.

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

## Important limitations

This is an early development build. It does not authenticate users, encrypt configuration, monitor processes or websites, capture webcam images, send Discord notifications, or enforce restrictions. Do not use it to protect real data.

The legacy C++ implementation remains in the repository as a reference. Do not remove or overwrite it as part of the Rust rewrite.
