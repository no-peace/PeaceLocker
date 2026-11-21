# Phase 4 — Monitoring sources

- [x] Platform-independent process identity and snapshot tracker.
- [x] PID-reuse detection using process creation FILETIME.
- [x] Windows process enumeration through documented Tool Help and query APIs.
- [x] RAII ownership for Windows process handles.
- [x] Supervised process polling worker with cancellation and joined shutdown.
- [x] Configurable polling interval and capped exponential retry backoff.
- [x] Typed process lifecycle messages and monitor event kinds.
- [ ] Classify per-process Win32 errors (access denied, process exited during query, other).
- [ ] Wire Windows enumeration into the worker in the application composition root.
- [ ] Bridge process lifecycle messages into core event queue and rule matching.
- [ ] Add live Windows process-monitor integration tests.
- [ ] Explorer folder monitoring with COM apartment ownership.
- [ ] Browser URL detection and supported-browser UI Automation adapters.
- [ ] Surface monitor health and diagnostics in the application UI.

The process polling worker is an infrastructure component, not an enforcement
mechanism. No process suspension, termination, or filesystem blocking is
implemented by Phase 4.
