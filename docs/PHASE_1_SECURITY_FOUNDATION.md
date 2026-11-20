# Phase 1 — Security foundation implementation

**Branch:** `rewrite/rust-v2`  
**Status:** Implementation committed; compilation and runtime validation pending.

## Implemented

### PIN verifier

- Argon2id PHC verifier using a fresh random salt for each PIN.
- Initial parameters: 19 MiB memory, 2 iterations, 1 lane, 32-byte output.
- PHC input is length-limited and its algorithm/version and cost parameters are checked before verification.
- Accepted verification bounds: 8 MiB–256 MiB memory, 1–10 iterations, 1–8 lanes.
- The PIN is not returned, serialized, or logged by this crate.

These are initial parameters, not final release settings. Benchmark on the minimum supported Windows hardware and adjust before release. A short numeric PIN remains low entropy.

### Data-encryption key

- A 256-bit key is generated from the operating-system CSPRNG.
- Key bytes are held in a non-Clone, non-Debug wrapper and zeroized on drop.
- A generated key may encrypt exactly one envelope.
- A key restored from DPAPI is decrypt-only. Configuration rewrites must generate and wrap a new key.

### Authenticated encryption

- AES-256-GCM with a 96-bit random nonce and 128-bit authentication tag.
- Fixed format context and caller-supplied metadata are authenticated as associated data.
- The Windows envelope binds the DPAPI-protected key blob into AEAD associated data, preventing protected-key blob substitution.
- Payloads are limited to 16 MiB and external authenticated metadata to 64 KiB.
- Unsupported versions, malformed envelopes, and authentication failures are rejected without returning plaintext.

The one-encryption-per-generated-key rule is the nonce-uniqueness strategy for this envelope API. Do not reuse or reconstruct an encryption-capable key for another write.

### Windows DPAPI

- Uses current-user DPAPI scope by default.
- No static optional entropy, embedded key, or plaintext fallback.
- DPAPI output is copied and its allocated memory is cleared and released.
- Windows API failures are surfaced to the caller.
- A combined envelope API creates a fresh DEK, protects it with DPAPI, and encrypts the payload.

This is DPAPI user-scope protection. TPM-backed protection is not implemented and must not be claimed.

### Recovery codes

- Generates up to 16 recovery codes, each with 128 bits of random entropy.
- Plaintext codes are returned once to the caller.
- Only Argon2id verifier strings are retained by the recovery-code set.
- Successful use removes a code; reuse fails.
- Regeneration requires replacing the old verifier set in the caller's persisted state.

## Tests added (not yet executed)

- Argon2id PIN success/failure, unique salts, malformed/high-cost verifier rejection.
- CSPRNG key size/distinctness and decrypt-only restored keys.
- AES-GCM round trip, ciphertext tampering, wrong-key rejection, unsupported version, authenticated metadata tampering, and one-encryption-per-key enforcement.
- Recovery-code one-time use, regeneration isolation, and count bounds.
- Windows DPAPI envelope round trip and protected-key substitution rejection.

## Not implemented in this phase

- Persistent file storage, atomic replacement, backups, and schema migration.
- PIN setup/unlock UI integration.
- Failed-attempt counters, three-attempt/six-hour lockout, restart/clock-change handling.
- Recovery-code persistence and UI display/confirmation workflow.
- Legacy C++ configuration migration.
- TPM provider support.
- Security audit or release certification.

## Validation status

No GitHub Actions run was started for this phase. The current execution environment also has no Rust compiler or Cargo installed, so the workspace could not be compiled or tested locally here. The code and dependency/API choices were reviewed against the Rust crate and Windows API documentation, but that is not a substitute for `cargo check`, formatting, Clippy, and Windows runtime tests.

**Do not use this branch as a production security product yet.**
