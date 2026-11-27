# PeaceLocker 2.0 — Security and Privacy Specification

**Status:** Proposed security baseline  
**Applies to:** Rust rewrite and all persistent data, authentication, monitoring, and notification features

## 1. Security objectives

PeaceLocker 2.0 should protect application configuration and discourage unauthorized casual access to its own interface and configured workflows.

The security design must be honest about Windows privilege boundaries. A desktop application running in a user's session cannot guarantee protection against a local administrator, kernel-level malware, or an attacker who fully controls that session.

### 1.1 Security goals

- Verify a user-provided PIN without storing the PIN.
- Protect sensitive configuration at rest.
- Detect unauthorized modification of encrypted configuration.
- Protect encryption keys using Windows user-bound protection.
- Provide a controlled recovery process.
- Avoid insecure fallback behavior.
- Minimize collection of sensitive activity data.
- Keep security events auditable without logging secrets.
- Fail visibly and safely when security-critical operations fail.

### 1.2 Explicit non-goals

Unless a separate privileged component and security review are added, PeaceLocker does not guarantee:

- Protection against local administrators.
- Protection against kernel-mode malware.
- Protection against a compromised Windows account.
- Filesystem access control merely by monitoring Explorer.
- Universal website blocking merely by observing browser UI.
- Tamper-proof watchdog or process enforcement.
- Secure deletion from SSDs, backups, cloud sync, or forensic images.

The product UI and README must not imply these guarantees.

## 2. Threat model

| Attacker / failure | Expected response |
|---|---|
| Casual user opens PeaceLocker | PIN gate and lockout policy |
| User guesses PIN repeatedly | Rate limiting and lockout |
| Attacker copies encrypted config | DEK remains protected by DPAPI; ciphertext remains authenticated |
| Attacker edits encrypted config | AEAD authentication failure; reject file |
| Config is truncated or malformed | Reject and offer validated backup recovery |
| DPAPI unprotect fails | Fail closed; no plaintext fallback |
| Standard user attempts to read another user's protected data | Rely on Windows account and ACL boundaries; test deployment assumptions |
| Local administrator modifies executable or process | Not guaranteed to be prevented |
| Malware executes in the same user session | Not guaranteed to be prevented |
| Discord unavailable | Queue/retry within bounds; monitoring continues |
| Monitor source becomes unavailable | Show unhealthy/unknown state, never report false protection |

Threats must be reviewed again before introducing a Windows service, kernel driver, filesystem minifilter, network filter, or other privileged component.

## 3. PIN authentication

### 3.1 Verifier format

Use Argon2id from a maintained Rust cryptography crate. Store:

- Format version.
- Algorithm identifier.
- Argon2 version.
- Memory cost.
- Iteration/time cost.
- Parallelism.
- Unique random salt.
- Derived verifier bytes.

The parameters must be benchmarked on supported hardware and chosen to make guessing expensive without making legitimate unlock unusable. Store parameters with the verifier so future versions can upgrade them after successful authentication.

Do not invent or hardcode a global salt.

### 3.2 PIN entropy

A numeric PIN has limited entropy. Argon2id slows offline guessing but does not make a short PIN equivalent to a high-entropy password. The setup UI should encourage a longer PIN or passphrase where product requirements allow it.

### 3.3 Memory handling

- Do not persist or log the raw PIN.
- Keep the input lifetime as short as practical.
- Avoid unnecessary copies.
- Clear mutable secret buffers when practical, understanding that compiler/runtime copies cannot always be guaranteed erased.
- Do not retain the PIN in GUI state after verification.
- Never include the PIN in crash reports or diagnostic exports.

### 3.4 Timing and comparison

Use the cryptographic library's verification API or a constant-time comparison implementation. Do not write ad hoc string comparison for verifier bytes.

## 4. Failed attempts and lockout

Initial product policy carried forward from the legacy app:

- Three consecutive failed attempts.
- Six-hour lockout.
- Recovery through a valid single-use recovery code.

These are initial UX/security policy values, not a guarantee against local tampering.

Implementation requirements:

1. Track attempts in a versioned state record.
2. Persist state atomically.
3. Use a monotonic clock for in-process intervals and carefully handle restart/persisted timestamps.
4. Handle system clock changes explicitly.
5. Avoid indefinite lockout caused by corrupted state.
6. Keep recovery separate from ordinary PIN verification.
7. Record successful and failed recovery events without storing the submitted code.

Do not make lockout the only protection. A local attacker with write access or administrative privileges may modify local application state.

## 5. Recovery codes

Generate recovery codes using a cryptographically secure random generator with sufficient entropy.

Requirements:

- Display once at generation time.
- Store only a verifier or keyed verifier protected by a per-installation secret.
- Each code is single-use.
- Regeneration invalidates all previous codes.
- Do not log or transmit codes.
- Do not include codes in backups in recoverable plaintext form.
- Require explicit confirmation before replacing the recovery set.
- Record recovery events without recording the code.

If the user loses both the PIN and all recovery methods, the product must explain what data can and cannot be recovered. Do not invent a hidden bypass.

## 6. Key hierarchy and encryption at rest

### 6.1 Recommended key hierarchy

1. Generate a random 256-bit data-encryption key (DEK) per installation.
2. Use the DEK with authenticated encryption for the serialized configuration payload.
3. Protect the DEK with Windows DPAPI, scoped to the intended Windows user by default.
4. Optionally support TPM-backed key protection through a verified Windows cryptographic provider when available.
5. Record the protection mode and format version, not secret material.

The DEK is not derived from the PIN. This separates local authentication from encryption-key management and avoids turning a low-entropy PIN into the sole encryption key.

### 6.2 Authenticated encryption

Use a maintained implementation of AES-256-GCM or another reviewed AEAD construction supported by the selected platform/library.

Requirements:

- Unique nonce for every encryption under the same key.
- Correct nonce size for the selected implementation.
- Authentication tag verification before plaintext is used.
- Associated data binds format version and relevant metadata.
- Reject malformed, truncated, unsupported, or unauthenticated envelopes.
- Never continue with partially decrypted data.
- Do not implement AES, GCM, HMAC, or key derivation manually.

If AES-GCM nonce uniqueness cannot be guaranteed by the storage design, stop and redesign the nonce strategy before release.

### 6.3 Envelope format

Illustrative logical envelope:

```json
{
  "format_version": 1,
  "cipher": "AES-256-GCM",
  "key_protection": "DPAPI_CURRENT_USER",
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "protected_dek": "<base64>"
}
```

This is a logical example. The implementation must define exact binary/text encoding, field limits, nonce/tag representation, canonical associated data, and version migration.

### 6.4 DPAPI behavior

- Use DPAPI with the intended user scope.
- Use optional entropy only if its lifecycle and storage are well defined; do not embed a static value and call it secret.
- Check all Windows API return codes.
- Correctly free DPAPI-allocated output buffers.
- Do not log plaintext or key bytes.
- Explain that DPAPI user-scope protection depends on the Windows user profile and account context.
- Test behavior after account password changes, profile restoration, reinstall, and migration as applicable.

### 6.5 TPM support

TPM support is optional, not assumed.

- Detect actual provider/key capabilities.
- Do not label DPAPI fallback as TPM protection.
- Report the active protection mode accurately.
- Handle missing or reset TPM, changed hardware, and unavailable providers.
- Provide a documented recovery path.
- Do not silently weaken protection when TPM operations fail.

## 7. Legacy cryptography and migration

The C++ implementation contains a hardcoded HMAC key string, and a plaintext-style fallback path was identified in the legacy secret handling. Neither should be carried into Rust v2.

Migration requirements:

- Do not trust a hardcoded legacy key as secret material.
- Do not preserve a legacy MAC design whose key is embedded in the executable.
- Do not import plaintext secrets into the new store.
- Inspect exact legacy data formats before writing an importer.
- Back up the original configuration before conversion.
- Prefer resetting PIN/recovery credentials if verifier compatibility cannot be demonstrated.
- Re-encrypt imported settings under a newly generated DEK.
- Verify the new file can be reopened before marking migration complete.
- Keep the original backup until the user confirms successful operation.

## 8. Storage integrity and recovery

- Validate schema and field limits before use.
- Authenticate encrypted data before deserialization.
- Reject unknown mandatory versions.
- Use atomic replacement and retain a bounded backup.
- Avoid following unexpected symlinks/reparse points where relevant to the chosen storage path.
- Restrict file permissions to the intended user where practical.
- Handle disk-full, permission, and interrupted-write cases.
- Never overwrite the only valid backup with an invalid or unverified state.

A corrupt configuration should lead to a clear recovery screen, not an unhandled crash or automatic plaintext reconstruction.

## 9. Windows privilege and process boundaries

The app should initially run as a normal user process unless a clearly justified feature requires elevation.

- Do not request administrator privileges by default.
- Keep elevated operations separate and narrowly scoped if ever added.
- Treat mutexes, process ACLs, watchdogs, and startup entries as reliability/UX controls, not tamper-proof security boundaries.
- Avoid undocumented NT APIs as core enforcement mechanisms.
- Do not use process suspension as a substitute for access control.
- Document that a local administrator can generally stop, modify, inspect, or replace a user-mode application.

A Windows service, driver, minifilter, or network filter would require a separate threat model, signed deployment strategy, least-privilege review, and independent testing.

## 10. Monitoring data and privacy

### 10.1 Data minimization

Collect only fields required to evaluate a configured rule or produce an explicitly requested notification.

Avoid retaining full command lines, window titles, URLs, or file paths unless the feature needs them and the user has enabled the relevant behavior.

### 10.2 Webcam capture

- Disabled by default.
- Separate explicit opt-in.
- Clear trigger description.
- Clear local retention and remote transmission controls.
- Visible status and test action.
- No capture on ordinary app startup.
- No hidden activation after migration or update.

### 10.3 Foreground activity logging

- Disabled by default.
- Separate from security alert settings.
- Explain what is recorded and where it is sent.
- Provide a disable and clear-history path.
- Apply redaction/minimization where possible.

### 10.4 Discord webhooks

Treat webhook URLs as credentials.

- Store webhook configuration protected at rest.
- Never log full webhook URLs.
- Use HTTPS, request timeouts, bounded retries, and rate limits.
- Do not transmit PINs, recovery codes, keys, or full diagnostic dumps.
- Make outbound content visible/configurable.
- Provide a webhook test action that does not expose secrets in UI or logs.

## 11. Logging and diagnostics

Use structured tracing. Redact:

- PINs and password-like inputs.
- Recovery codes.
- DEKs and derived keys.
- Protected-key blobs where unnecessary.
- Discord webhook URLs.
- Sensitive URL/path/activity payloads unless explicitly required for a local audit event.

Diagnostic export should be user-initiated, previewable, and sanitized. Never automatically upload logs.

## 12. Security test requirements

### Authentication
- Correct PIN verifies.
- Incorrect PIN fails.
- Unique salts are generated.
- Verifier parameters are parsed and bounded.
- Parameter upgrade works.
- Malformed verifier is rejected.

### Encryption and key protection
- Round-trip encrypt/decrypt succeeds.
- Modified ciphertext fails authentication.
- Modified nonce/tag/associated data fails.
- Truncated envelope is rejected.
- Unsupported version is rejected.
- Missing or inaccessible DPAPI key fails closed.
- No plaintext fallback path exists.
- Nonce uniqueness strategy is tested.

### Recovery and lockout
- Recovery code works once.
- Reuse fails.
- Regeneration invalidates prior codes.
- Lockout threshold and duration behave as specified.
- Clock changes and restart behavior are tested.
- Corrupt lockout state has a documented recovery path.

### Privacy and notifications
- Webcam remains disabled by default.
- Activity logging remains disabled by default.
- Webhook secret is redacted from logs.
- Network timeout does not block monitoring.
- Queue capacity and retry bounds are enforced.

## 13. Security release gate

Do not ship a release if any of these are true:

- Plaintext fallback exists.
- Hardcoded cryptographic key exists.
- Secrets appear in logs or diagnostics.
- AEAD tampering tests fail.
- DPAPI failures are ignored.
- Recovery codes are reusable.
- Privacy-sensitive collection is enabled without explicit consent.
- A monitor reports healthy when its source failed.
- Documentation claims filesystem or website protection that the implementation does not provide.

## 14. Security decisions requiring ADRs

Record decisions for:

1. Argon2id parameter calibration and upgrade policy.
2. AEAD crate/API and nonce strategy.
3. DPAPI user scope and optional entropy policy.
4. TPM provider support and recovery behavior.
5. Credential reset versus legacy verifier migration.
6. Lockout persistence and clock-change handling.
7. Diagnostic retention and privacy defaults.
8. Whether any future component requires elevation.

Security review is continuous. Any change to key handling, authentication, monitoring enforcement, telemetry, or privilege requirements must update this document and its tests.
