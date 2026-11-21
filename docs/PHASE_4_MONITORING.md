# Phase 4 — Monitoring Sources (Supervised Process Polling)

## Scope
This iteration adds a reusable supervised polling worker around the platform-independent process tracker. It remains only the process-monitoring slice of Phase 4.

## Process polling worker
The monitor crate now provides a configurable non-zero polling interval, capped exponential retry backoff, a named worker thread, cancellation via condition variable, joined shutdown, and explicit messages for process changes, healthy snapshots, degraded polling, and shutdown. The worker accepts a polling closure so it can be tested without Win32 dependencies; the Windows adapter can supply `enumerate_processes()`.

## Event contract
Normalized events now carry a typed `MonitorEventKind` for ordinary observations, process starts/exits, browser navigation, and Explorer changes. Process lifecycle messages are not yet converted into queued core events or rule decisions.

## Safety boundaries
- The worker observes process metadata only; it does not suspend, terminate, or modify processes.
- Cancellation and thread joining are explicit.
- Failed polls are reported as degraded and retried, not treated as empty healthy snapshots.
- Retry delay is capped.
- Health diagnostics must not contain raw paths or secrets.

## Remaining Phase 4 work
- Classify Win32 errors (access denied, process-exit races, other).
- Connect Windows enumeration to the worker in the application composition root.
- Convert process changes into normalized core events and evaluate rules.
- Add timestamp/ID provider and bounded event bridge.
- Implement Explorer monitoring with correct COM apartment ownership.
- Implement supported-browser URL detection and UI Automation adapters.
- Surface monitor health and diagnostics in the UI.

## Validation
Tests have been added but not run. Rust compilation, formatting, Clippy, and Windows runtime checks remain outstanding because the current environment has no Rust toolchain and GitHub Actions quota is exhausted.
