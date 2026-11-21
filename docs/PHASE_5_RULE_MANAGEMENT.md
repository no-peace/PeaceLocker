# Phase 5 — Rule management

## Implemented

- Desktop UI can create, edit, enable/disable and delete rules.
- Supported targets: process name, executable path, Explorer folder path and browser hostname.
- Rule creation and replacement use `Rule::new` validation and core commands.
- Core commands reject duplicate IDs, reject edits to missing rules, and avoid revision increments for no-op enable/disable requests.
- Rule IDs are assigned from the current in-memory maximum and checked for integer exhaustion.
- Core tests cover replacement, enable/disable and no-op revision behavior.

## Current behavior and limitations

- Rules are held in the in-memory `CoreEngine`; they are lost when the application exits.
- The editor does not yet load or save rules through the encrypted configuration store.
- `Block` and `Notify` are policy labels only. A match increments the informational match counter; no process is suspended or terminated, no folder access is denied, and no browser navigation is blocked.
- The UI and Windows monitoring adapters still require compilation and runtime validation on supported Windows versions.

## Next work

1. Connect core snapshots and rule commands to the encrypted configuration store.
2. Add durable event history and notification delivery.
3. Implement enforcement only after explicit security design, threat-model review, and platform-specific testing.
