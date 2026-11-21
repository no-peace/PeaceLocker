# Phase 4 — Monitoring sources

- [x] Platform-independent process identity and snapshot tracker.
- [x] PID-reuse detection using process creation FILETIME.
- [x] Windows process enumeration through documented Tool Help and query APIs.
- [x] RAII ownership for Windows process handles.
- [x] Supervised process polling worker with cancellation and joined shutdown.
- [x] Configurable polling interval and capped exponential retry backoff.
- [x] Typed process lifecycle messages and monitor event kinds.
- [x] Connect Windows enumeration to supervised worker in desktop app.
- [x] Convert process changes into normalized core events and evaluate matching rules.
- [x] Add explicit UI controls and monitor health display.
- [ ] Classify per-process Win32 errors (access denied, process exited during query, other).
- [ ] Add live Windows process-monitor integration tests.
- [ ] Explorer folder monitoring with COM apartment ownership.
- [ ] Browser URL detection and supported-browser UI Automation adapters.
- [ ] Surface durable event history and rule-management UI.

The process monitor is opt-in and read-only. Rule matches are decisions only;
no process suspension, termination, or filesystem blocking is implemented.
