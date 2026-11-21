# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone

**Phase 2 — encrypted storage and legacy text-import implementation committed; validation pending.**

Branch: `rewrite/rust-v2`

## Phase 0 — workspace foundation

Implemented:
- [x] Created the Rust rewrite branch without changing the legacy baseline.
- [x] Created the Cargo workspace and seven crate boundaries.
- [x] Added the initial egui desktop shell.
- [x] Added typed platform-independent application state and initial tests.
- [x] Added a Windows GitHub Actions workflow for formatting, Clippy, and tests.
- [x] Added Rust development instructions and clarified the two-track repository.

Still unverified:
- [ ] Workspace dependency resolution and compilation.
- [ ] Formatting and Clippy.
- [ ] Tests on a Windows runner.
- [ ] Desktop launch and visual inspection on Windows.

## Phase 1 — security foundation

Implementation committed:
- [x] Argon2id PIN verifier with random salt and bounded PHC parameters.
- [x] CSPRNG-generated 256-bit data keys with zeroization.
- [x] Single-use encryption key lifecycle.
- [x] AES-256-GCM authenticated envelope encryption with associated data.
- [x] Current-user DPAPI protection using isolated windows-sys calls.
- [x] Combined DPAPI-wrapped DEK and authenticated configuration envelope.
- [x] 128-bit single-use recovery-code generation and Argon2id verifiers.
- [x] Unit and Windows integration tests added.

Validation pending:
- [ ] Cargo dependency resolution and compilation.
- [ ] Rustfmt and Clippy.
- [ ] Security tests executed.
- [ ] Windows DPAPI integration tests executed.
- [ ] Argon2id parameters benchmarked on minimum supported hardware.

## Phase 2 — encrypted storage and migration

Implementation committed:
- [x] Versioned configuration document with bounded fields and strict schema validation.
- [x] Persist PIN verifier, recovery verifiers, lockout state, rules, preferences, and webhook configuration inside the encrypted document.
- [x] Platform-neutral KeyProtector abstraction.
- [x] Windows current-user DPAPI KeyProtector adapter.
- [x] Fresh DEK per write and AES-GCM associated-data binding to the protected key blob.
- [x] Bounded encrypted file reads and writes.
- [x] Same-directory temporary-file replacement.
- [x] One validated backup generation and explicit validated restore.
- [x] Refuse to overwrite an existing configuration that fails authentication/validation.
- [x] Three-failure/six-hour PIN lockout policy and clock-rollback handling.
- [x] Read-only parser for the legacy C++ key=value text format.
- [x] Windows DPAPI importer for the legacy PVBIN01 binary container.
- [x] Explicitly reject RAW plaintext fallback and report TPM-wrapped legacy files as unsupported.
- [x] Import only reviewed non-credential settings; require a new Rust PIN.
- [x] Tests added for persistence, tampering, backup/restore, lockout persistence, and legacy parsing.
- [x] Phase 2 design and limitation notes added.

Validation pending:
- [ ] Cargo dependency resolution and compilation.
- [ ] Rustfmt and Clippy.
- [ ] Storage/security tests executed.
- [ ] Windows DPAPI-backed EncryptedStore integration test.
- [ ] Atomic replacement and file ACL behavior verified on supported Windows versions.

Not yet implemented:
- [ ] Application data-directory resolver and ACL verification.
- [ ] Wire the app to load and save ConfigDocument.
- [ ] PIN setup/unlock/recovery UI.
- [ ] Legacy TPM-wrapped vault migration (old persisted TPM key lifecycle needs separate compatibility work).
- [ ] Migration preview UI and explicit confirmation before applying imported settings.
- [ ] Multi-process store locking and single-instance coordination.
- [ ] Schema upgrade framework and multi-generation backup policy.

## Validation environment

The GitHub Actions quota is exhausted, so no CI run was started. The execution environment does not have rustc or cargo, so no local compile/test result is claimed. The source has been reviewed manually, but that does not replace Cargo check, formatting, Clippy, or Windows runtime testing.

## Release warning

The Rust rewrite is not production-ready. The code has not passed compilation, runtime, platform, or independent security review. Do not use this branch to protect real data. The legacy C++ implementation and default branch remain unchanged.
