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

- egui first-run setup and unlock screens, including PIN confirmation and recovery-code presentation/acknowledgement.
- A secure per-user application data-directory resolver and Windows ACL verification.
- App startup integration, authenticated-session lifecycle and lock action.
- Connecting editor CRUD to `SecuritySession::save_rules`.
- Recovery-code unlock and single-use recovery-code consumption flow.
- PIN change flow and anti-rollback protection stronger than the existing persisted lockout state.

## Validation

No Rust compiler or Cargo toolchain was available in the implementation environment. The new code has not been compiled or tested, and DPAPI behavior requires Windows runtime validation. Do not treat source review as a passing build or security review.
