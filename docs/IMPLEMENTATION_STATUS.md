# Rust v2 implementation status

Last updated: 2026-11-27

## Current milestone

**Phase 8 — Interactive ASCII desktop UI, PIN setup/unlock, encrypted rule persistence, and monitoring controls are connected; build and runtime validation remain pending.**

Merged to `main` via PR #1; ongoing UI work is on `rewrite/rust-v2`.

## Phase 0 — workspace foundation

Implemented: Cargo workspace and seven crate boundaries, initial egui shell, typed initial state, CI workflow, and development documentation.

Validation pending: dependency resolution, compilation, formatting, Clippy, Windows tests, and desktop launch.

## Phase 1 — security foundation

Implemented: Argon2id PIN verifier, bounded PHC validation, CSPRNG data keys, AES-256-GCM authenticated encryption, DPAPI key protection, one-time recovery codes, and tests.

Validation pending: compilation, formatting, Clippy, security tests, DPAPI integration tests, and parameter benchmarking.

## Phase 2 — encrypted storage and migration

Implemented: versioned encrypted configuration document, fresh DEK per write, DPAPI-protected key, authenticated envelope, bounded I/O, atomic replacement, validated backup/restore, lockout state, typed validated rule collection with backward-compatible default for older schema-v1 files, read-only legacy text parser, DPAPI legacy importer, and rejection of plaintext fallback.

Implemented additionally: Windows DPAPI-backed PIN session orchestration for first-run setup and unlock, persisted failed-attempt/lockout transitions, one-time recovery-code generation, and authenticated rule-snapshot persistence API.

Remaining: explicit Windows ACL/reparse-point verification, recovery-code unlock/consumption, PIN change, TPM legacy migration, migration preview, single-instance coordination, schema upgrades, and stronger anti-rollback lockout persistence.

## Phase 3 — core state, commands, and rules engine

Implemented: typed protection lifecycle, commands and revisions, immutable snapshots, validated process/path/host rules, deterministic matching, monitor health and event contracts, bounded event queue, fake adapter, and tests.

Remaining: durable event history and a formal persisted application lifecycle model.

## Phase 4 — monitoring sources (partial)

Implemented:
- [x] Platform-independent process identity and snapshot tracker.
- [x] PID-reuse detection using process creation FILETIME.
- [x] Windows process enumeration using documented Tool Help and query APIs.
- [x] Query-only handles and RAII cleanup.
- [x] Supervised polling worker with cancellation and joined shutdown.
- [x] Capped exponential retry backoff and explicit degraded health messages.
- [x] Initial snapshot treated as baseline, avoiding false process-start events.
- [x] Windows enumeration connected to opt-in desktop worker.
- [x] Process lifecycle changes converted into normalized events.
- [x] Core engine evaluates process-start events against configured rules.
- [x] UI displays monitor health and offers explicit start/stop controls.
- [x] No enforcement action is taken by process rule matches.
- [x] Reviewed the legacy Explorer-folder observation behavior and identified its COM/UI-threading and title-fallback limitations before porting.
- [x] Implement Explorer COM STA polling adapter and UI Start/Stop integration.
- [x] Match canonical filesystem paths only; ignore title-derived folder names.
- [x] Add bounded polling, cancellation, explicit health/error reporting and deterministic shutdown for Explorer monitoring.
- [x] Implement read-only foreground browser URL observation through UI Automation for Chrome, Edge, Firefox, Brave, Vivaldi and Opera address-bar identifiers.
- [x] Normalize browser observations to hostnames only; discard URL paths, queries and fragments before events enter the core.
- [x] Add browser host-change tracking, supervised STA polling, duplicate suppression and UI Start/Stop controls.

Remaining:
- [ ] Validate Explorer COM enumeration, path conversion, and shutdown on supported Windows versions.
- [ ] Classify per-process Win32 errors precisely.
- [ ] Add cancellation/timeouts for slow or stuck Windows queries.
- [ ] Add live Windows integration tests.
- [ ] Validate address-bar AutomationIds and UI Automation behavior on supported browser versions.
- [x] Add rule-management UI for process names, executable paths, folder paths and browser hostnames; support create, edit, enable/disable and delete through validated core commands.
- [x] Add typed, bounded rule records to the encrypted configuration document; validate each rule and reject duplicate IDs.
- [x] Add Windows PIN-session orchestration over the DPAPI encrypted store, with persisted lockout state and authenticated rule-snapshot save API.
- [x] Build interactive ASCII/monospace egui navigation and section panels.
- [x] Add Windows first-run PIN/passphrase setup, unlock, lock action, one-time recovery-code display and acknowledgement.
- [x] Resolve the configuration path under the current user's LOCALAPPDATA.
- [x] Load stored rules after authentication and persist add/edit/enable/disable/delete changes through the encrypted session.
- [ ] Add recovery-code unlock/consumption and PIN change workflows.
- [ ] Verify Windows directory ACLs and add single-instance coordination.
- [ ] Add durable event history.

## Documentation

The root [README.md](../README.md) now documents prerequisites, branch setup, build/run commands, checks, current usage, workspace layout, known limitations and troubleshooting. [README_RUST_V2.md](../README_RUST_V2.md) is the Rust-track overview.

## Validation environment

No workflow run or status check is recorded for the current branch head. The connected local terminal was unavailable and the execution environment has no rustc or cargo, so no local compile/test result is claimed. Source review does not replace Cargo check, formatting, Clippy, or Windows runtime testing.

## Release warning

The Rust rewrite is not production-ready. It has not passed compilation, runtime, platform, or independent security review. Do not use it to protect real data. The legacy C++ source files remain in the repository, while `main` now includes the experimental Rust rewrite.
