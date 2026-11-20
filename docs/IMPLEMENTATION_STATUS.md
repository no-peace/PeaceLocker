# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone

**Phase 1 — security foundation implementation committed; validation pending.**

Branch: `rewrite/rust-v2`

## Phase 0 — workspace foundation

Implemented:
- [x] Created the Rust rewrite branch without changing `main`.
- [x] Created the Cargo workspace and seven crate boundaries.
- [x] Added the initial egui desktop shell.
- [x] Added a typed, platform-independent application snapshot and initial tests.
- [x] Added Windows GitHub Actions workflow for formatting, Clippy, and tests.
- [x] Added Rust development instructions and corrected the root README for the two-track repository.

Still unverified:
- [ ] Workspace dependency resolution and compilation.
- [ ] Formatting and Clippy.
- [ ] Tests on a Windows runner.
- [ ] Desktop launch and visual inspection on Windows.

## Phase 1 — security foundation

Implementation committed:
- [x] Argon2id PIN verifier with random salt and bounded PHC parameters.
- [x] CSPRNG-generated 256-bit data keys with zeroization.
- [x] Single-use encryption key lifecycle (one encryption per generated key; restored keys are decrypt-only).
- [x] AES-256-GCM authenticated envelope encryption with fixed and external associated data.
- [x] Current-user DPAPI protection using isolated `windows-sys` calls.
- [x] Combined DPAPI-wrapped DEK and authenticated configuration envelope.
- [x] 128-bit single-use recovery-code generation and Argon2id verifiers.
- [x] Unit and Windows integration tests added for the above behavior.
- [x] Phase 1 design and implementation notes added.

Validation pending:
- [ ] Cargo dependency resolution and compilation.
- [ ] Rustfmt and Clippy.
- [ ] Security crate tests executed.
- [ ] Windows DPAPI integration tests executed on Windows.
- [ ] Argon2id parameters benchmarked on minimum supported hardware.

The GitHub Actions quota is currently exhausted, so no CI run was started for Phase 1. The execution environment used for this implementation does not have `rustc` or `cargo`, so no local compile/test result is claimed. Source-level review was performed, but this does not replace toolchain validation.

## Not yet implemented

- PIN setup/unlock UI integration.
- Failed-attempt persistence and the three-attempt/six-hour lockout policy.
- Recovery-code UI, persistence workflow, and regeneration confirmation.
- Atomic configuration file storage, backups, and schema migration.
- Legacy C++ configuration migration.
- TPM-backed key protection.
- Process, browser, or Explorer monitoring.
- Rules engine and enforcement actions.
- Discord notifications or webcam capture.
- Tray, startup registration, and watchdog lifecycle.

## Release warning

The Rust rewrite is not production-ready. The security primitives are implementation work in progress and have not passed compilation, runtime, platform, or independent security review. Do not use this branch to protect real data. The legacy C++ implementation and `main` remain unchanged.
