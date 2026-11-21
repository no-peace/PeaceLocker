# Phase 4 — Windows process monitoring integration

## Implemented in this increment

- The Windows process enumerator is now supplied to the supervised polling service by the desktop application.
- The desktop UI has explicit Start/Stop controls; monitoring does not start automatically.
- Process start/exit changes are converted into normalized core events with process-name and, when available, executable-path targets.
- Events enter a bounded core event queue and are evaluated against configured rules in stable rule-ID order.
- Core evaluation only reports policy matches. It does not suspend, terminate, or block processes.
- The UI reports monitor health, inaccessible-process count, latest event, and number of policy matches.

## Rule evaluation semantics

Only process-start events are considered actionable policy observations. Process-exit events are retained as lifecycle information but do not produce block/notify matches. Rule matching is exact and case-insensitive for process names and normalized Windows paths for executable paths.

## Safety boundaries

- Process polling is opt-in via the UI and has an explicit stop control.
- Windows process handles are query-only.
- No elevation is requested.
- The app does not take enforcement action based on a matching rule.
- No raw paths are written into monitor diagnostic error codes.

## Remaining Phase 4 work

- Classify Win32 errors precisely (access denied, process-exit races, other).
- Improve event queue draining and event history presentation.
- Add rule-management UI and persist rule configuration.
- Implement Explorer folder monitoring with COM apartment ownership.
- Implement supported-browser URL detection and UI Automation adapters.
- Add live Windows integration tests and validate cancellation under slow API calls.

## Validation

Tests are added but not run. Compilation, formatting, Clippy, and Windows runtime checks remain outstanding because the environment has no Rust toolchain and the GitHub Actions quota is exhausted.
