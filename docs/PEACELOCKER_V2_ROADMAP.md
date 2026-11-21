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
- [ ] Implement Explorer window discovery and canonical current-folder path lookup.
- [ ] Run COM automation on a dedicated STA worker; initialize, use and release every COM interface on that same thread.
- [ ] Match canonical paths with component-boundary checks; do not trust ambiguous window-title substring matches as canonical paths.
- [ ] Add supervised polling, cancellation, backoff and health reporting.
- [ ] Normalize folder-navigation events and route them through the bounded event queue.
- [ ] Add tests for path normalization, child-folder matching, sibling-prefix collisions, window identity changes and Explorer shutdown.

## Remaining monitoring work

- [ ] Classify per-process Win32 errors (access denied, process exited during query, other).
- [ ] Add cancellation/timeouts for slow or stuck Windows queries.
- [ ] Add live Windows process-monitor integration tests.
- [ ] Browser URL detection and supported-browser UI Automation adapters.
- [ ] Durable event history and rule-management UI.

The process monitor is opt-in and read-only. Rule matches are decisions only;
no process suspension, termination, or filesystem blocking is implemented.
