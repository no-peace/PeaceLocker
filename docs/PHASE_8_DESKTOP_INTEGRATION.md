# Phase 8 — Interactive ASCII desktop and authenticated app integration

## Implemented

- Replaced the placeholder dashboard with a dark green, monospace ASCII-console presentation.
- Added working left-side navigation for Overview, Protection, Monitoring, Rules, Activity, Security, Notifications and Settings.
- Added terminal-style status panels, ASCII header art, and interactive quick-navigation controls.
- Added first-run Windows PIN/passphrase setup with confirmation and a 6–128 byte UI policy.
- Added unlock UI with rejected-attempt and lockout feedback.
- Added an explicit lock action that drops the authenticated session and clears in-memory rules.
- Displays the eight one-time recovery codes after setup, makes their text selectable, and requires acknowledgement before the in-app lock action is enabled.
- Zeroizes PIN/passphrase input buffers and recovery-code strings when cleared or when the app exits.
- Resolves the encrypted configuration path under the current user's `LOCALAPPDATA\PeaceLocker\config.enc`.
- Loads persisted rules into the core engine after successful authentication.
- Persists rule create, edit, enable/disable and delete operations through the authenticated encrypted session before applying the corresponding core command.
- Keeps monitoring opt-in and read-only; no enforcement was introduced.

## Behavior and limitations

- On Windows, the Rules panel remains locked until PIN authentication succeeds. Rule changes are persisted to the encrypted configuration.
- On non-Windows targets, the security workflow is unavailable and rule edits remain in memory only.
- The configuration directory inherits the current user's profile ACLs. The application does not yet verify or explicitly set ACLs, defend against reparse-point attacks, or enforce single-instance operation.
- Recovery codes are displayed once and are not recoverable from the UI after acknowledgement. Recovery-code unlock/consumption and PIN change are not implemented.
- Closing the app drops the in-memory session and zeroizes the currently held PIN/recovery-code buffers; the next launch starts locked.
- Monitor workers are independent of the PIN session and remain running if the user locks the app. While locked, the core rules are cleared, so no policy rules are evaluated.

## Validation

No Rust compiler or Cargo toolchain was available in this implementation environment. The UI and Windows integration have not been compiled, formatted, linted, or runtime-tested. The Windows DPAPI, UI Automation, COM and file-permission behavior must be validated on supported Windows versions before release. The app remains experimental and does not enforce process, folder or browser restrictions.
