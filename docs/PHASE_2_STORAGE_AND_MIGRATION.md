# Phase 2 — Encrypted storage and legacy import

**Status:** Core implementation committed; compilation and platform validation pending.

## Implemented

### Versioned configuration document

Schema version 1 stores:
- Argon2id PIN verifier.
- Argon2id recovery-code verifiers (never the plaintext recovery codes).
- Persisted failed-attempt and lockout state.
- Startup and Explorer shell-integration preferences.
- Activity-logging preference (disabled by default).
- Optional HTTPS webhook URL.
- Bounded blocked-item rules.
- Revision and creation/update timestamps.

Unknown fields are rejected. The document validates schema, timestamps, field lengths, collection bounds, HTTPS webhook scheme, and lockout-state invariants before save and after load.

### Encrypted store

- Platform-neutral storage API uses a KeyProtector boundary.
- Every save generates a fresh random 256-bit DEK.
- The platform adapter wraps the DEK with current-user DPAPI.
- The protected DEK blob is included in AES-256-GCM associated data.
- The document is serialized, encrypted, and only the encrypted envelope is written.
- File and metadata sizes are bounded.
- Plaintext serialization buffers use zeroizing storage.
- A same-directory temporary file is flushed and atomically persisted.
- One validated previous generation is retained as a backup.
- Existing primary data must authenticate before it can be overwritten.
- Backup restore requires successful decryption and schema validation; it is never silently selected.

The store creates a new DEK on each write because the security crate deliberately makes each generated AES-GCM key single-use.

### PIN lockout

- Three consecutive incorrect PINs trigger a six-hour lockout.
- A successful PIN resets the failed-attempt counter.
- Invalid PIN input and malformed stored verifiers are not treated as ordinary incorrect attempts.
- Persisted timestamps are checked for backward clock movement; detected rollback fails closed with a six-hour lockout from the last observed timestamp.
- Lockout state is serializable and is stored inside the encrypted configuration document.

The caller must save the updated document after each authentication result. This phase supplies the policy and persistence primitive; the desktop UI has not yet been wired to it.

### Legacy text import

The read-only parser recognizes the legacy C++ key=value text format:
- startup preference;
- Explorer shell-integration preference;
- activity-logging preference;
- HTTPS webhook URL;
- blocked-item records.

It deliberately ignores legacy credential material:
- SHA-256/PBKDF2 PIN verifier fields;
- legacy pepper and DPAPI/TPM blobs;
- legacy recovery hashes;
- legacy HMAC.

A new Rust PIN must be established. The parser does not trust the legacy hardcoded-key HMAC as an authenticity boundary and does not modify or delete the source file. The import report identifies ignored credential fields and requires credential reset when legacy credential data is present.

## Tests added (not yet executed)

- Encrypted store round-trip.
- Backup rotation and backup restore.
- Ciphertext tampering rejection.
- Refusal to overwrite an invalid primary configuration.
- Lockout state round-trip through encrypted persistence.
- Invalid schema rejection.
- Legacy settings import and credential exclusion.
- HTTP webhook omission.
- Malformed blocked item and oversized input rejection.
- Security crate lockout tests for threshold, expiry, success reset, and clock rollback.

The storage unit tests use a test-only key protector. It intentionally does not provide real at-rest key protection; Windows integration must use DpapiKeyProtector.

## Not implemented in this phase

- Application data-directory resolver and Windows ACL verification.
- GUI PIN setup, unlock, and recovery screens.
- Wiring the app to load/save the ConfigDocument.
- Automatic migration of legacy encrypted vault_data.bin files.
- TPM-wrapped legacy secret migration (old TPM key lifecycle is incompatible and must be treated separately).
- Legacy PIN verifier migration; user must set a new PIN.
- Migration preview UI and explicit user confirmation.
- Concurrent-process locking / single-instance coordination.
- Multi-generation backup retention and backup rotation UI.
- Schema migration from future versions.

## Validation status

No GitHub Actions run was started. The available execution environment does not contain rustc or cargo, so no local compilation or tests are claimed. Source-level review was performed; Cargo check, formatting, Clippy, and Windows DPAPI/runtime tests remain required before this code can be relied on.

**Do not use this branch as a production security product yet.**
