# PeaceLocker 2.0 — Rust rewrite

The Rust rewrite is developed separately from the legacy C++ application on the `rewrite/rust-v2` branch. The root [README.md](README.md) is the canonical guide for prerequisites, setup, build commands, running the desktop application, checks, current behavior and troubleshooting.

> **Development warning:** this is not a production-ready security product. The GUI currently contains an egui shell and an opt-in, read-only Windows process monitor. Security and encrypted-storage primitives are not yet wired into the UI. Folder/browser monitoring and enforcement are not implemented. Compilation and runtime validation remain outstanding. Do not use this branch to protect real data.

## Implemented foundations

- Seven-crate Cargo workspace and egui desktop shell.
- Platform-independent state, command and snapshot types.
- Typed protection lifecycle and deterministic validated rule matching.
- Normalized monitor event contracts and bounded event queue.
- Argon2id PIN verifier creation/verification with bounded parameters.
- AES-256-GCM authenticated encryption and single-use data-key primitives.
- Current-user Windows DPAPI key protection.
- 128-bit recovery-code generation and Argon2id verifiers.
- Versioned encrypted configuration store with fresh data keys, atomic replacement and validated backup.
- Persisted three-failure/six-hour lockout policy.
- Read-only importer for supported legacy DPAPI-wrapped/text configuration; plaintext fallback is rejected and TPM-wrapped legacy import is not supported.
- Windows process enumeration using documented query APIs.
- Supervised, opt-in process polling connected to the desktop UI and core event evaluation.

## Current application behavior

On Windows, launch the application and use **Start process monitor** in the Process monitoring section. The first successful process snapshot is a baseline; later process starts/exits are sent through the normalized event queue and evaluated against configured core rules.

The current UI has no rule editor, so matches normally remain zero. Process observation is read-only: the app does not suspend, terminate or block a process. The monitor can skip processes it cannot query without elevation.

## Not implemented as user-facing workflows

- PIN setup/unlock/change/recovery UI.
- GUI integration with encrypted storage and persisted lockout.
- Migration preview/confirmation and complete migration orchestration.
- Explorer folder monitoring.
- Browser URL monitoring.
- Rule-management UI and durable event history.
- Process, folder or website enforcement.
- TPM protection, installer, signing and release packaging.

## Build and run

Install Rust stable (workspace minimum 1.85), `rustfmt`, `clippy`, Visual Studio Build Tools with Desktop development with C++, and a Windows SDK.

From the repository root in PowerShell:

```powershell
git switch rewrite/rust-v2
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p peacelocker-app
```

Build an optimized executable:

```powershell
cargo build --release -p peacelocker-app
.\target\release\peacelocker-app.exe
```

See [README.md](README.md) for full setup, troubleshooting, usage details and the complete workspace map.

## Design documents

- [Architecture](docs/PEACELOCKER_V2_ARCHITECTURE.md)
- [Security and privacy](docs/PEACELOCKER_V2_SECURITY.md)
- [Roadmap](docs/PEACELOCKER_V2_ROADMAP.md)
- [Phase 1 — security foundation](docs/PHASE_1_SECURITY_FOUNDATION.md)
- [Phase 2 — storage and migration](docs/PHASE_2_STORAGE_AND_MIGRATION.md)
- [Phase 3 — core engine](docs/PHASE_3_CORE_ENGINE.md)
- [Phase 4 — monitoring](docs/PHASE_4_MONITORING.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)

## Validation

The environment used for this implementation did not have `cargo`/ `rustc`, and GitHub Actions quota was exhausted. Source changes and tests have been reviewed statically, but no successful compile, test, formatting or Clippy run is claimed. Windows runtime validation and independent security review are still required.
