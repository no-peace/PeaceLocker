# Phase 4 — Windows monitoring

## Process monitoring integration

- The Windows process enumerator is supplied to the supervised polling service by the desktop application.
- The desktop UI has explicit Start/Stop controls; monitoring does not start automatically.
- The first successful process snapshot establishes a baseline. Processes already running when monitoring starts are not falsely reported as newly launched.
- Subsequent process start/exit changes are converted into normalized core events with process-name and, when available, executable-path targets.
- Events enter the bounded core event queue and are evaluated against configured rules in stable rule-ID order.
- Core evaluation only reports policy matches. It does not suspend, terminate, or block processes.
- The UI reports monitor health, inaccessible-process count, latest event, and number of policy matches.

## Process rule evaluation

Only process-start events are considered actionable policy observations. Process-exit events are retained as lifecycle information but do not produce block/notify matches. Rule matching is exact and case-insensitive for process names and normalized Windows paths for executable paths.

## Explorer monitoring implementation

- A dedicated worker initializes COM as an STA and balances it with CoUninitialize on the same thread.
- The worker enumerates IShellWindows, filters Explorer HWNDs by CabinetWClass/ExploreWClass, reads LocationURL, and accepts only file URLs that convert to local paths.
- COM interfaces remain on the worker thread. Only owned path strings and scalar window/process identities cross to the UI.
- HWND, process ID, and process creation time identify each window instance.
- The UI has opt-in Start/Stop controls. Polling uses bounded exponential backoff and joined shutdown.
- The first successful snapshot establishes a baseline; subsequent window/folder changes become normalized ExplorerChanged events and are evaluated against folder rules.
- Virtual shell locations are ignored rather than inferred from titles. No enforcement is performed.

## Legacy Explorer behavior reviewed

The legacy `monitor.cpp` implementation enumerates visible top-level Explorer windows with class names `CabinetWClass` and `ExploreWClass`. It initializes COM as a single-threaded apartment in its folder-monitor worker, creates `IShellWindows`, matches each shell browser object to the enumerated HWND, and reads its `LocationURL`. It converts file URLs to local paths where possible. If that lookup fails, it falls back to the Explorer window title.

The legacy rule test first uses a path-prefix comparison and then falls back to a folder-name substring search. That fallback can produce false positives (for example, similarly named sibling folders or unrelated titles). The legacy worker also owns COM state in a detached thread and uses polling/sleep loops; the rewrite must not copy those lifetime and cancellation weaknesses.

## Explorer implementation requirements

The Rust implementation must (the current adapter follows these constraints):

1. Run all COM initialization, interface creation, calls, and interface release on one dedicated STA worker thread. Do not pass COM interface pointers to the egui/UI thread or another worker.
2. Pair successful COM initialization with `CoUninitialize` on the same thread, including error and shutdown paths.
3. Identify Explorer windows by HWND and process identity; handle windows closing or being replaced between enumeration and COM lookup.
4. Prefer a canonical local filesystem path derived from the shell browser's current location. URI decoding and path conversion failures must be reported as unavailable observations, not silently treated as paths.
5. Normalize paths consistently and compare directory components with a separator boundary. A path such as `C:\\Data\\Private2` must not match a protected `C:\\Data\\Private` rule.
6. Avoid treating a window-title or folder-name substring as a verified path. If a compatibility title heuristic is ever added, it must be explicitly labeled lower-confidence and separately configurable.
7. Use a supervised worker with bounded polling, cooperative cancellation, bounded retry/backoff, explicit health messages and joined shutdown.
8. Emit normalized folder-navigation observations through the existing bounded event queue. Observation is not enforcement.

## Safety boundaries

- Process polling is opt-in via the UI and has an explicit stop control.
- Windows process handles are query-only.
- No elevation is requested.
- The app does not take enforcement action based on a matching rule.
- Cancellation wakes polling workers between polls. An in-progress Win32 or COM call must return before joined shutdown completes; the current implementation does not impose a hard timeout on a stuck OS/COM call.

## Remaining Phase 4 work

- Platform-independent Explorer window identity and folder-change tracker added; folder rule matching uses directory boundaries.
- Windows COM adapter and UI Start/Stop integration implemented; Windows runtime validation remains outstanding.
- Classify Win32 process-query errors precisely (access denied, process-exit races, other).
- Add timeouts or cancellation strategy for slow/stuck OS queries.
- Improve event history presentation and rule-management UI.
- Persist rule configuration.
- Implement supported-browser URL detection and UI Automation adapters.
- Add live Windows integration tests.

## Validation

Tests are added but not run. Compilation, formatting, Clippy, and Windows runtime checks remain outstanding because the environment has no Rust toolchain and the GitHub Actions quota is exhausted.
