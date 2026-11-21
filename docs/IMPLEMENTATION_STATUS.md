# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone
**Phase 4 — supervised process polling foundation committed; Windows integration, Explorer/browser sources, and runtime validation pending.**

Branch: `rewrite/rust-v2`

## Phase 0 — workspace foundation
Implemented: Cargo workspace and seven crate boundaries, initial egui shell, typed initial state, CI workflow, and development documentation.
Validation pending: dependency resolution, compilation, formatting, Clippy, Windows tests, and desktop launch.

## Phase 1 — security foundation
Implemented: Argon2id PIN verifier, bounded PHC validation, CSPRNG data keys, AES-256-GCM authenticated encryption, DPAPI key protection, one-time recovery codes, and tests.
Validation pending: compilation, formatting, Clippy, security tests, DPAPI integration tests, and parameter benchmarking.

## Phase 2 — encrypted storage and migration
Implemented: versioned encrypted configuration document, fresh DEK per write, DPAPI-protected key, authenticated envelope, bounded I/O, atomic replacement, validated backup/restore, lockout state, read-only legacy text parser, DPAPI legacy importer, and rejection of plaintext fallback.
Remaining: application data-directory/ACL handling, app/store integration, PIN and recovery UI, TPM legacy migration, migration preview, single-instance coordination, schema upgrades, and stronger anti-rollback lockout persistence.

## Phase 3 — core state, commands, and rules engine
Implemented: typed protection lifecycle, commands and revisions, immutable snapshots, validated process/path/host rules, deterministic matching, monitor health and event contracts, bounded event queue, fake adapter, and tests.
Remaining: connect core commands/snapshots to GUI and persist state changes through encrypted storage.

## Phase 4 — monitoring sources (partial)
Implemented:
- [x] Platform-independent process identity and snapshot tracker.
- [x] PID reuse detection using process creation FILETIME.
- [x] Windows process enumeration using documented Tool Help and query APIs.
- [x] Query-only handles and RAII cleanup.
- [x] Supervised polling worker with configurable interval.
- [x] Cancellation-aware shutdown and worker join.
- [x] Exponential retry backoff with configured cap.
- [x] Explicit healthy, degraded, process-change, and stopped messages.
- [x] Typed monitor event kinds for process lifecycle, browser navigation, and Explorer changes.
- [x] Tests added for tracker behavior, polling, cancellation, retry reporting, and backoff.

Remaining:
- [ ] Classify per-process Win32 errors precisely.
- [ ] Connect Windows enumeration to the worker in the app composition root.
- [ ] Convert process messages into normalized core events and evaluate rules.
- [ ] Add live Windows integration tests.
- [ ] Implement Explorer monitoring with COM ownership.
- [ ] Implement browser URL monitoring/UI Automation.
- [ ] Surface source health and diagnostics in the UI.

## Validation environment
The GitHub Actions quota is exhausted, so no CI run was started. The execution environment does not have rustc or cargo, so no local compile/test result is claimed. The source has been reviewed manually, but this does not replace Cargo check, formatting, Clippy, or Windows runtime testing.

## Release warning
The Rust rewrite is not production-ready. It has not passed compilation, runtime, platform, or independent security review. Do not use this branch to protect real data. The legacy C++ implementation and default branch remain unchanged.
