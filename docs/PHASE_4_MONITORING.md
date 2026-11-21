# Phase 4 — Monitoring Sources (Initial Process Work)

## Scope

This commit starts Phase 4 with the process source. It does not claim the
entire monitoring milestone is complete.

## Platform-independent process tracking

The monitoring crate now defines:

- `ProcessIdentity`: PID plus process creation FILETIME.
- `ProcessSnapshot`: identity, executable name, and optional executable path.
- `ProcessChange`: started or exited observation.
- `ProcessTracker`: deterministic diffing between snapshots.

A PID alone is not a process identity because Windows reuses PIDs. If the same
PID appears with a different creation timestamp, the tracker emits an exit for
the previous lifetime followed by a start for the new lifetime.

The tracker retains the first entry for duplicate PIDs in one snapshot to
ensure deterministic behavior. Its tests cover initial starts, unchanged
snapshots, exits, PID reuse, and duplicate entries.

## Windows enumeration adapter

The Windows crate now exposes `enumerate_processes()`, implemented using
documented Win32 APIs:

- `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW`
  enumerate process IDs and executable names.
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` opens query-only handles.
- `GetProcessTimes` obtains the creation timestamp used for lifetime identity.
- `QueryFullProcessImageNameW` obtains the executable path where permitted.

Snapshot and process handles use RAII cleanup. The adapter does not request
administrator privileges or attempt to inspect protected process memory.
Processes that cannot be assigned a stable creation-time identity are skipped
and counted in `inaccessible_count`. An unavailable executable path does not
invalidate an otherwise stable process identity.

## Limitations and next work

- The enumeration adapter is a one-shot snapshot, not a supervised polling
  service. Sampling interval, backoff, cancellation, and worker supervision
  remain to be implemented.
- Per-process failures are currently counted together. The next iteration
  should distinguish access denied, process exit races, and other errors.
- Process changes are not yet bridged into core monitor events or rule
  evaluation.
- Explorer folder monitoring and browser URL detection are not implemented.
- No process suspension or other enforcement is performed.

## Validation status

Unit tests for the platform-independent tracker are committed but not run.
The Windows adapter has not been compiled or exercised on Windows. The current
environment has no Rust toolchain and GitHub Actions quota is exhausted.
