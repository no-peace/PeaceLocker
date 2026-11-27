# Phase 7 — PIN session and DPAPI-backed configuration access

## Implemented in this phase

- Added a Windows-only `SecuritySession` orchestration layer over the existing encrypted store and current-user DPAPI key protector.
- First-run setup creates an Argon2id PIN verifier and eight one-time recovery codes. Only the recovery-code verifiers are stored in the encrypted configuration. Plaintext recovery codes are returned once to the caller.
- Setup refuses to overwrite an existing configuration file, including a corrupt one.
- Unlock loads and authenticates the encrypted configuration before checking the PIN.
- Failed PIN attempts and lockout transitions are persisted before the result is returned.
- The API returns an authenticated session only after successful PIN verification. Rejected and locked-out outcomes do not expose a session.
- Added a rule-snapshot save method that preserves unrelated configuration fields and only updates rules, revision and timestamp.

## Security model

The PIN is an application authentication gate. The data-encryption key remains protected by Windows current-user DPAPI, and the configuration payload remains AES-256-GCM encrypted. This design does not claim that the PIN is a second factor or that it cryptographically derives the data-encryption key.

There is no default PIN, plaintext fallback, or automatic overwrite/reinitialization of an existing store.

## Not yet implemented

- Recovery-code unlock/consumption and PIN change workflows.
- Explicit Windows ACL/reparse-point verification for the LOCALAPPDATA configuration directory.
- Single-instance coordination and automatic lock-on-inactivity policy.
- Durable event history and broader configuration settings integration.
- PIN change and anti-rollback protection stronger than the existing persisted lockout state.

## Validation

No Rust compiler or Cargo toolchain was available in the implementation environment. The new code has not been compiled or tested, and DPAPI behavior requires Windows runtime validation. Do not treat source review as a passing build or security review.
