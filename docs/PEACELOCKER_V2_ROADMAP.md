# Phase 4 — Monitoring sources

## Process monitoring

- [x] Platform-independent process identity and snapshot tracker.
- [x] PID-reuse detection using process creation FILETIME.
- [x] Windows process enumeration through documented Tool Help and query APIs.
- [x] RAII ownership for Windows process handles.
- [x] Supervised process polling worker with cancellation and joined shutdown.
- [x] Configurable polling interval and capped exponential retry backoff.
- [x] Typed process lifecycle messages and monitor event kinds.
- [x] Treat first successful snapshot as baseline (no false "new process" events).
- [x] Connect Windows enumeration to supervised worker in desktop app.
- [x] Convert process changes into normalized core events and evaluate matching rules.
- [x] Add explicit UI controls and monitor health display.

## Explorer folder monitoring

- [x] Inspect legacy behavior and identify the supported semantics to preserve.
- [x] Implement Explorer window discovery and canonical current-folder path lookup.
- [x] Run COM automation on a dedicated STA worker; initialize, use and release every COM interface on that same thread.
- [x] Match canonical paths with component-boundary checks; do not trust ambiguous window-title substring matches as canonical paths.
- [x] Add supervised polling, cancellation, backoff and health reporting.
- [x] Normalize folder-navigation events and route them through the bounded event queue.
- [x] Add platform-independent tests for path normalization, child-folder matching, sibling-prefix collisions and window identity changes; Windows runtime validation remains pending.

## Remaining monitoring work

- [ ] Classify per-process Win32 errors (access denied, process exited during query, other).
- [ ] Add cancellation/timeouts for slow or stuck Windows queries.
- [ ] Add live Windows process-monitor integration tests.
- [x] Browser URL detection and supported-browser UI Automation adapters (runtime/browser-version validation pending).
- [x] In-memory rule-management UI for create, edit, enable/disable and delete.
- [x] Extend the encrypted configuration document with typed, validated, bounded rule records; retain compatibility with older schema-v1 documents that omit the new field.
- [ ] Wire desktop startup and rule mutations to the encrypted store after PIN setup/unlock is available.
- [ ] Durable event history.

The process monitor is opt-in and read-only. Rule matches are decisions only;
no process suspension, termination, or filesystem blocking is implemented.


## Phase 5 — Rule management

- [x] Add validated core commands to replace rules and toggle enabled state.
- [x] Add desktop editor for process-name, executable-path, folder-path and browser-host rules.
- [x] Support create, edit, enable/disable and delete operations.
- [x] Allocate non-zero rule IDs and handle ID-space exhaustion.
- [x] Add core tests for rule replacement, enabled-state changes and no-op revisions.
- [ ] Connect rule changes to the encrypted configuration store so they survive restart.
- [ ] Add rule conflict/duplicate-target guidance and richer validation feedback.
- [ ] Add durable event history and notification delivery.

The editor is a management interface only. `Block` is currently a stored policy action and is not enforced by the operating system or application.


## Phase 7 — PIN session foundation

- [x] Add Windows `SecuritySession` orchestration over the encrypted configuration store and current-user DPAPI.
- [x] Add first-run PIN verifier and one-time recovery-code setup API.
- [x] Refuse to overwrite an existing configuration during setup.
- [x] Persist failed PIN attempts and lockout state before returning authentication outcomes.
- [x] Ensure failed or locked-out authentication never returns an authenticated session.
- [x] Add an authenticated rule-snapshot persistence API that preserves unrelated settings.
- [ ] Build egui first-run setup, PIN confirmation, unlock and recovery-code screens.
- [ ] Resolve and secure the per-user data directory and verify Windows ACLs.
- [ ] Connect app startup and rule CRUD to the authenticated session.
- [ ] Implement recovery-code consumption and PIN change workflows.
- [ ] Validate compilation, tests and Windows DPAPI runtime behavior.


## Phase 8 — Interactive desktop integration

- [x] Replace the placeholder dashboard with a dark monospace ASCII-console UI.
- [x] Add functional section navigation and interactive status panels.
- [x] Add first-run PIN/passphrase setup, confirmation, unlock and explicit lock screens.
- [x] Display one-time recovery codes and require in-app acknowledgement before locking.
- [x] Zeroize PIN input and recovery-code buffers when cleared and on app exit.
- [x] Resolve the encrypted store beneath the current user's LOCALAPPDATA.
- [x] Load persisted rules after successful authentication.
- [x] Persist rule create/edit/enable/disable/delete changes through the authenticated session.
- [ ] Implement recovery-code unlock/consumption and PIN change.
- [ ] Verify data-directory ACLs and reparse-point behavior; implement single-instance coordination.
- [ ] Persist durable event history and connect remaining settings.
- [ ] Run Cargo check, rustfmt, Clippy, workspace tests, and Windows runtime validation.
