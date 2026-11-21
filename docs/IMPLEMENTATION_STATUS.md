# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone

**Phase 4 — initial process enumeration and PID-lifetime tracking committed; Explorer/browser monitoring and runtime validation pending.**

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

## Phase 3 — core state, commands, and rules engine

Implementation committed:
- [x] Typed protection lifecycle and deterministic setup/lock/unlock transitions.
- [x] Typed commands, results, errors, and monotonically increasing state revisions.
- [x] Read-only core snapshots containing no credentials or secret material.
- [x] Validated rules for process names, executable paths, and browser hostnames.
- [x] Deterministic, case-insensitive exact matching with Windows path separator normalization.
- [x] Explicit separation between rule decisions and enforcement; no action is executed by the core.
- [x] Typed process, Explorer, and browser monitor source identifiers.
- [x] Monitor health states for not-started, healthy, degraded, and unavailable.
- [x] Normalized monitor event contract with IDs, timestamps, source, and correlation ID.
- [x] Bounded in-memory event queue with drop-oldest overflow accounting and duplicate queued-ID rejection.
- [x] Monitor adapter contract and deterministic fake source for integration tests.
- [x] Unit tests added for transitions, invalid commands, matching, monitor health, queue capacity, and duplicates.

Remaining:
- [ ] Connect core commands and snapshots to the GUI (Phase 6).
- [ ] Persist core state changes through the encrypted store (storage/application integration work).

Validation pending:
- [ ] Cargo dependency resolution and compilation.
- [ ] Rustfmt and Clippy.
- [ ] Core unit tests executed.

## Phase 4 — monitoring sources (partial)

### Process source foundation

Implemented:
- [x] Platform-independent process snapshot and process-lifetime identity types.
- [x] Deterministic snapshot tracker that detects process starts and exits.
- [x] PID reuse detection using the process creation FILETIME, treating a changed creation time as an exit plus a new start.
- [x] Duplicate PID handling within a snapshot is deterministic.
- [x] Windows process enumeration through documented Tool Help APIs.
- [x] Query-only process handles using `PROCESS_QUERY_LIMITED_INFORMATION`; no elevation attempt.
- [x] Process creation-time query via `GetProcessTimes`.
- [x] Executable path query via `QueryFullProcessImageNameW`.
- [x] RAII handle cleanup for snapshot and process handles.
- [x] Inaccessible or unidentifiable processes are counted and skipped rather than assigned an unsafe PID-only identity.
- [x] Unit tests added for starts, exits, unchanged snapshots, duplicate PIDs, and PID reuse.

Remaining:
- [ ] Distinguish access-denied, process-exited-during-query, and other per-process errors using explicit Win32 error codes.
- [ ] Add a supervised polling loop, configurable interval, and backoff.
- [ ] Bridge process changes into normalized core events and rule evaluation.
- [ ] Add Windows integration tests against live processes.
- [ ] Implement Explorer location monitoring with correct COM apartment ownership.
- [ ] Implement browser URL detection and supported-browser UI Automation adapters.
- [ ] Surface source health and diagnostics to the application.

## Validation environment

The GitHub Actions quota is exhausted, so no CI run was started. The execution environment does not have rustc or cargo, so no local compile/test result is claimed. The source has been reviewed manually, but that does not replace Cargo check, formatting, Clippy, or Windows runtime testing.

## Release warning

The Rust rewrite is not production-ready. The code has not passed compilation, runtime, platform, or independent security review. Do not use this branch to protect real data. The legacy C++ implementation and default branch remain unchanged.
