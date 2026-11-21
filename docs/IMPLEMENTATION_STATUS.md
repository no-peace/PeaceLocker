# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone
**Phase 4 — Windows process monitoring connected to the desktop UI and core rule evaluation; Explorer/browser sources and runtime validation pending.**

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
- [x] Supervised polling worker with cancellation and joined shutdown.
- [x] Capped exponential retry backoff and explicit degraded health messages.
- [x] Initial snapshot treated as baseline, avoiding false process-start events.
- [x] Windows enumeration connected to opt-in desktop worker.
- [x] Process lifecycle changes converted into normalized events.
- [x] Core engine evaluates process-start events against configured rules.
- [x] UI displays monitor health and offers explicit start/stop controls.
- [x] No enforcement action is taken by process rule matches.

Remaining:
- [ ] Classify per-process Win32 errors precisely.
- [ ] Add cancellation/timeouts for slow or stuck Windows queries.
- [ ] Add live Windows integration tests.
- [ ] Implement Explorer monitoring with COM ownership.
- [ ] Implement browser URL monitoring/UI Automation.
- [ ] Add rule-management UI and durable event history.

## Validation environment
No CI run was started because GitHub Actions quota is exhausted. The execution environment has no rustc or cargo, so no local compile/test result is claimed. Source review does not replace Cargo check, formatting, Clippy, or Windows runtime testing.

## Release warning
The Rust rewrite is not production-ready. It has not passed compilation, runtime, platform, or independent security review. Do not use this branch to protect real data. The legacy C++ implementation and default branch remain unchanged.
