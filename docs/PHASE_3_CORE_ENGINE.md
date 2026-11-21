# Phase 3 — Core State, Commands, and Rules Engine

## Scope

Phase 3 introduces the platform-independent domain engine. It is deliberately
independent of egui, Windows APIs, DPAPI, process inspection, browser UI
Automation, and enforcement mechanisms.

## Implemented contracts

### Application state and commands

- `CoreEngine` owns the current protection lifecycle, monitoring toggle,
  rules, monitor health, and a monotonically increasing revision.
- State is changed only through typed `Command` values.
- Commands return typed results or typed validation/state-transition errors.
- Snapshots clone presentation-safe state. They contain no PIN, recovery code,
  webhook URL, encryption key, or other credential material.
- Invalid transitions are rejected. Setup moves from not-configured to
  unlocked; lock and unlock are valid only from their corresponding states.
- Revision exhaustion is checked before a state mutation is applied.

### Rules

Rules support three target kinds:

- Process name
- Executable path
- Browser hostname

Matching is exact after normalization. Names and hosts are compared
case-insensitively. Windows path separators are normalized before comparison.
Rule IDs are non-zero and unique within the engine. Labels and target strings
have bounded lengths and basic type-specific validation.

A rule action is a decision label (`Block` or `Notify`). **The core does not
execute either action.** In particular, a matching `Block` rule does not
suspend a process, deny filesystem access, close a browser tab, or prevent
navigation. Enforcement requires later, separately reviewed platform
adapters.

Browser rules contain hostnames, not arbitrary URL expressions. Browser
adapters must normalize an observed URL and provide the hostname as the
observed target. This phase does not implement URL parsing or browser access.

### Monitor health and events

Monitor sources are typed as process, Explorer, or browser. Health is explicit:
not-started, healthy, degraded, or unavailable. A source failure must be
reported as degraded/unavailable rather than silently represented as healthy.

Normalized events carry:
- A source-generated event ID
- Unix timestamp in milliseconds
- A typed monitor source
- Optional correlation ID
- A normalized target kind and value

The in-memory event queue has a fixed capacity. When full, it drops the oldest
queued event and increments a dropped-event counter. Duplicate IDs are ignored
while the matching event remains queued; this is not a durable global
idempotency guarantee.

A monitor adapter trait and deterministic fake adapter are provided for tests.
No real monitoring source is active in this phase.

## Tests added

- Valid and invalid protection-state transitions
- Duplicate and invalid rule commands
- Exact, case-insensitive process-name matching
- Windows executable-path separator/case normalization
- Target-kind isolation and disabled-rule behavior
- Stable rule-match ordering
- Explicit unavailable monitor health
- Bounded queue overflow and dropped-event accounting
- Duplicate queued event rejection
- Fake monitor adapter health and event draining

## Not included

- Connecting the core to the GUI
- Loading or saving the core state through the encrypted store
- PIN authentication or recovery workflow
- Real process, Explorer, or browser monitoring
- Process suspension, filesystem enforcement, or browser blocking
- Background worker supervision and notification delivery

These remain later integration milestones. The application must not claim
protection is active merely because the core engine or a rule exists.

## Validation status

Source-level implementation and tests are committed. Compilation, rustfmt,
Clippy, test execution, and Windows runtime behavior remain unverified because
the current environment has no Rust toolchain and the GitHub Actions quota is
exhausted.
