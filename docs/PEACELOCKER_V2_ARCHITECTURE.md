# PeaceLocker 2.0 — Architecture Specification

**Status:** Proposed baseline for the complete Rust rewrite  
**Target platform:** Windows 10/11, x64 initially  
**Application model:** Native desktop application with a managed background core  
**GUI:** egui/eframe  
**Primary language:** Rust (2024 edition)

## 1. Purpose and scope

PeaceLocker 2.0 is a Windows desktop security and activity-restriction application. It provides local authentication, configurable monitoring rules, security-event handling, notifications, and Windows integration.

The existing C++ application includes PIN authentication, process monitoring, browser URL detection through UI Automation, Explorer location monitoring, Discord notifications, optional webcam capture, DPAPI/TPM-related key protection, startup integration, a tray interface, and watchdog behavior.

The rewrite is a redesign, not a line-by-line translation. Existing behavior is a reference; implementation details are not requirements when they are insecure, undocumented, fragile, or difficult to test.

### 1.1 Product boundaries

The first Rust release focuses on **activity monitoring and application-level restrictions**.

Explorer location monitoring is observational. It does not prevent arbitrary programs from accessing a folder. Browser URL detection through UI Automation is best-effort and is not equivalent to network-level website blocking. Process detection or suspension is not a security boundary.

A true encrypted file vault is a separate future capability with its own threat model, file format, recovery design, and testing requirements. Do not describe monitored folders as encrypted or access-controlled.

### 1.2 Design principles

1. Security-sensitive operations belong in dedicated modules, not the GUI.
2. No hardcoded cryptographic secrets.
3. No plaintext fallback when secure storage fails.
4. Use documented Windows APIs wherever practical.
5. Keep platform-specific code behind narrow interfaces.
6. Use managed tasks, bounded queues, cancellation, and explicit shutdown.
7. Make privacy-sensitive collection opt-in and visible.
8. Treat monitoring as fallible; expose health and failure states.
9. Version persistent formats and support controlled migration.
10. Test security and core behavior independently of the GUI.

## 2. System architecture

The application is divided into presentation, application core, domain services, persistence, and Windows platform integration.

```text
┌──────────────────────────────────────────────────────────┐
│ Presentation: egui / eframe                              │
│ Dashboard · Protection · Monitoring · Activity · Config │
└───────────────────────────┬──────────────────────────────┘
                            │ commands / state snapshots
┌───────────────────────────▼──────────────────────────────┐
│ Application core                                         │
│ App state · Command handlers · Event bus · Rules engine  │
└──────────────┬─────────────┬────────────┬─────────────────┘
               │             │            │
       ┌───────▼──────┐ ┌────▼─────┐ ┌────▼──────────┐
       │ Security     │ │ Monitor  │ │ Notifications │
       │ Auth / keys  │ │ Sources  │ │ Discord/local │
       └───────┬──────┘ └────┬─────┘ └────┬──────────┘
               │             │            │
       ┌───────▼─────────────▼────────────▼───────────┐
       │ Storage and platform abstractions           │
       │ Encrypted config · DPAPI · CNG · Win32 · COM │
       └─────────────────────────────────────────────┘
```

### 2.1 Dependency rules

- The GUI depends on application-facing interfaces and view models. It must not call DPAPI, registry, process enumeration, or HTTP APIs directly.
- The core owns application state, command orchestration, event routing, and rule evaluation.
- Domain crates expose narrow interfaces and typed errors.
- Windows-specific implementations live in the Windows platform crate.
- Storage owns serialization, schema validation, encryption-envelope persistence, atomic writes, and migration.
- Notifications consume explicit notification events. They must not independently inspect arbitrary application state.
- Avoid circular crate dependencies. Shared domain types should live in the core or a small dedicated types crate if the workspace grows.

## 3. Cargo workspace

Recommended initial workspace:

```text
PeaceLocker/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── README.md
├── docs/
├── crates/
│   ├── peacelocker-app/
│   ├── peacelocker-core/
│   ├── peacelocker-security/
│   ├── peacelocker-monitor/
│   ├── peacelocker-storage/
│   ├── peacelocker-notifications/
│   └── peacelocker-windows/
├── assets/
├── scripts/
└── tests/
```

Crate responsibilities:

| Crate | Responsibility |
|---|---|
| `peacelocker-app` | Entry point, startup orchestration, egui shell, app composition |
| `peacelocker-core` | Domain types, application state, commands, events, rules, orchestration |
| `peacelocker-security` | PIN verifier, recovery codes, key-management contracts, crypto envelope |
| `peacelocker-monitor` | Monitor lifecycle, event normalization, adapters, rule evaluation |
| `peacelocker-storage` | Config schema, encrypted persistence, atomic writes, backup, migration |
| `peacelocker-notifications` | Notification queue, Discord sender, local notification policy, optional capture workflow |
| `peacelocker-windows` | Win32, DPAPI, CNG/NCrypt, COM/UIA, registry, tray, startup integration |

Start with these boundaries, but do not split every small module into a separate crate prematurely. Keep module boundaries stable even if a couple of crates are temporarily combined.

### 3.1 Module outline

`peacelocker-core`:

- `state.rs`: authoritative runtime state and state transitions.
- `commands.rs`: user/application commands and validation.
- `events.rs`: typed domain events.
- `rules.rs`: rule model and deterministic evaluation.
- `dispatcher.rs`: event routing and action orchestration.
- `errors.rs`: core error types.

`peacelocker-security`:

- `authentication.rs`: PIN setup and verification.
- `hashing.rs`: Argon2id verifier format and parameter policy.
- `encryption.rs`: authenticated encryption envelope.
- `key_manager.rs`: data-key lifecycle contracts.
- `recovery.rs`: single-use recovery code lifecycle.

`peacelocker-monitor`:

- `engine.rs`: start/stop and monitor supervision.
- `process.rs`: process source interface and normalization.
- `website.rs`: browser adapter interface and URL normalization.
- `explorer.rs`: Explorer location source interface.
- `scheduler.rs`: configurable polling/backoff where event-driven APIs are unavailable.

`peacelocker-storage`:

- `config.rs`: versioned configuration schema.
- `encrypted_store.rs`: encrypt/decrypt and persistence boundary.
- `migration.rs`: legacy and schema-version migration.
- `backup.rs`: validated backup/restore.

`peacelocker-windows`:

- `dpapi.rs`: DPAPI protect/unprotect.
- `cng.rs`: Windows cryptographic provider integration where required.
- `process.rs`: documented process APIs.
- `ui_automation.rs`: COM/UI Automation wrappers.
- `registry.rs`: startup registration and supported shell integration.
- `tray.rs`: notification-area integration.
- `watchdog.rs`: optional health supervision, not a security boundary.

## 4. Runtime model and concurrency

Use Tokio for asynchronous I/O and managed background tasks. Do not create detached threads for routine work.

Recommended runtime responsibilities:

- GUI event loop remains responsive and does not await network calls or blocking monitor operations.
- Long-running monitor tasks are supervised by a central lifecycle manager.
- Windows APIs that block or require specific COM apartment behavior run on appropriately managed threads.
- Every worker has a cancellation path and reports termination/failure.
- Queues have explicit capacity and overflow policy.
- Network operations use timeouts, bounded retries, and rate limits.
- Application shutdown signals cancellation, drains critical events within a bounded period, and joins tasks.

Do not assume every Windows COM or UI Automation interface is safe to call from arbitrary Tokio worker threads. Initialize COM in the correct apartment on the thread that uses it and keep interface lifetimes within that apartment.

A useful abstraction is:

```rust
pub trait MonitorSource: Send {
    fn name(&self) -> &'static str;
    // Concrete async/event interface can be selected during implementation.
}
```

The final trait design must account for COM thread affinity and should not force non-Send COM interfaces across threads.

### 4.1 Event model

Normalize platform observations into typed events before rule evaluation. Initial examples:

```rust
pub enum MonitorEvent {
    ProcessStarted { pid: u32, name: String },
    ProcessExited { pid: u32 },
    WebsiteDetected { browser: String, url: String },
    ExplorerLocationChanged { path: String },
    SourceHealthChanged { source: String, healthy: bool },
}
```

Add event IDs, timestamps, source identity, and correlation IDs as needed. Avoid placing unnecessary sensitive data in event payloads or logs.

### 4.2 Command model

GUI actions become commands such as:

- `UnlockWithPin`
- `AddMonitoringRule`
- `RemoveMonitoringRule`
- `SetMonitoringEnabled`
- `UpdatePrivacySettings`
- `TestDiscordWebhook`
- `ExportDiagnostics`

Commands are validated by the core. The GUI receives a result and updated state; it does not mutate persistent state directly.

## 5. Monitoring and enforcement boundaries

### 5.1 Process monitoring

Use documented Windows process APIs through the `windows` crate where possible. Track PID plus process creation identity/lifetime; PID alone can be reused. Distinguish access denied, process exited, and query failure.

Prefer event-based notifications where reliable and supported. Use bounded polling only where necessary, with configurable intervals and backoff. Do not use window titles as authoritative process identity.

The current C++ implementation uses `NtSuspendProcess`. This is an undocumented NT API and must not be a core dependency. If process suspension remains as an experimental action, isolate it behind an explicitly unsafe/unsupported platform adapter, document its limitations, and test resume/failure behavior. Detection and enforcement must remain separate.

### 5.2 Website monitoring

Browser URL detection through UI Automation is best-effort. Implement browser-specific adapters and test each supported browser/version. Normalize URLs before rule matching, and clearly show when a source is unavailable.

Do not claim universal website blocking. Background tabs, browser UI changes, browser version differences, permissions, and accessibility-tree changes can prevent reliable detection. Stronger enforcement requires a separate design based on supported browser policy or a dedicated networking component.

### 5.3 Explorer monitoring

Explorer location monitoring observes locations exposed by Explorer windows. It does not enforce filesystem access restrictions and does not stop access through command-line tools, other applications, APIs, or alternate paths.

Use precise UI labels and documentation: “Explorer location monitoring”, not “folder encryption” or “folder access control”.

### 5.4 Rules engine

Rules should be declarative, validated, versioned, and deterministic. Each rule should include:

- Stable ID.
- Rule type and target.
- Enabled state.
- Action policy.
- Creation/update metadata.
- Optional schedule or scope.
- Validation errors when a target is invalid.

Separate detection from action policy. A matched rule can produce an event, a local warning, or a supported restriction action. Every action should be explicit and auditable.

## 6. Modern GUI

Use egui/eframe for the first modern desktop interface.

Design direction:

- Dark charcoal base.
- Restrained green accent.
- Clear status hierarchy and readable typography.
- Minimal animation and no decorative data.
- Consistent spacing, keyboard navigation, and accessible contrast.
- UI state derived from core state snapshots/events.

Navigation:

1. Overview
2. Protection
3. Monitoring
4. Activity
5. Security
6. Notifications
7. Settings
8. Help & About

The Overview page should show protection state, authentication state, monitor health, active rule count, recent security events, last successful save, and notification status.

Suggested UI modules:

```text
ui/
├── app.rs
├── theme.rs
├── components/
│   ├── sidebar.rs
│   ├── topbar.rs
│   ├── status_card.rs
│   ├── event_row.rs
│   └── modal.rs
├── pages/
│   ├── overview.rs
│   ├── protection.rs
│   ├── monitoring.rs
│   ├── activity.rs
│   ├── security.rs
│   ├── notifications.rs
│   └── settings.rs
└── dialogs/
    ├── pin_setup.rs
    ├── pin_unlock.rs
    ├── recovery.rs
    └── confirmation.rs
```

Use view models or immutable snapshots for rendering. Do not hold locks across expensive rendering work. UI callbacks submit commands; they do not call Windows APIs directly.

## 7. Notifications and privacy

Discord notifications must use a bounded queue, request timeouts, rate limits, bounded retries, and cancellation. A network outage must not block monitoring or the GUI.

Webcam capture and foreground application logging are privacy-sensitive features:

- Disabled by default.
- Explicitly enabled through separate settings.
- Trigger conditions and data sent must be described clearly.
- Provide a visible test/preview path.
- Avoid collecting or transmitting unrelated information.
- Never transmit PINs, recovery codes, or cryptographic keys.
- Keep local retention and remote transmission settings distinct.

## 8. Persistence and data model

Use a versioned configuration schema with strict validation. Serialize domain configuration using Serde, then encrypt the serialized bytes before writing them to disk.

The encrypted envelope should include a format version, algorithm identifier, nonce, ciphertext, authentication tag (if not included in the AEAD output), and protected data key or key reference. The exact encoding must be specified by the implementation and tested against tampering and truncation.

Use authenticated encryption such as AES-256-GCM through a maintained cryptographic library or supported Windows CNG implementation. Do not implement cryptographic primitives manually.

Use a random per-installation data-encryption key (DEK). Protect the DEK using DPAPI. TPM-backed protection may be an optional capability when correctly supported by the Windows cryptographic provider. Clearly report the actual protection mode in use.

Write configuration atomically: write a temporary file, flush as appropriate, validate the written representation, then replace the target. Maintain a recoverable backup. Never silently downgrade to plaintext when encryption or key protection fails.

## 9. Windows integration

Keep platform-specific operations behind the Windows crate.

- DPAPI: user-scoped protection by default; document profile and account implications.
- CNG/NCrypt: use only where a supported provider capability is needed.
- Startup: use a documented, user-visible registration method and provide a reliable disable/uninstall path.
- Tray: support hide/show/exit with clear state.
- Single instance: use a named mutex with correct ownership and error handling; do not treat it as a security barrier.
- Explorer integration: install and remove only supported, documented entries.
- Watchdog: use only for reliability/health supervision. Do not describe it as tamper-proof; local administrators can interfere.

## 10. Error handling and observability

Use typed errors at crate boundaries. Add structured tracing with useful context but redact secrets and sensitive payloads.

Recommended error categories:

- Authentication
- Key protection
- Encryption/decryption
- Configuration validation
- Storage I/O
- Monitor source unavailable
- Permission denied
- Notification transport
- Windows integration
- Shutdown/cancellation

Expose monitor health in the UI. A monitor that failed to initialize must not appear as active.

## 11. Testing and quality gates

Required automated checks:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Windows CI build for the supported target
- Dependency and license review before releases

Security tests include wrong PIN, salt uniqueness, parameter migration, tampered ciphertext, wrong DPAPI context, missing key, invalid envelope, recovery-code reuse, and lockout behavior.

Monitoring tests use fake sources to test rule matching, duplicate events, process lifetime handling, source failure, and cancellation without requiring live Windows processes.

Integration tests run on Windows for DPAPI, COM/UIA initialization, process queries, tray behavior, startup registration, and installer lifecycle.

## 12. Legacy migration

Keep the C++ implementation intact as a legacy reference while Rust v2 is developed on a separate branch.

Migration process:

1. Detect legacy configuration.
2. Identify and validate its exact format.
3. Back up the source before conversion.
4. Import only compatible, validated settings and rules.
5. Do not trust the legacy hardcoded HMAC key as a secret.
6. Do not copy plaintext secrets into the new store.
7. Prefer a new credential setup/recovery flow where legacy verifier compatibility is uncertain.
8. Verify the new encrypted store can be reopened before marking migration complete.
9. Preserve the backup until the user confirms the new version works.

Do not automatically migrate legacy cryptographic material without a verified format and security review.

## 13. Definition of done

The architecture is implemented when:

- The application builds and launches on supported Windows versions.
- UI and core are decoupled.
- PIN authentication and recovery are tested.
- Configuration is authenticated and encrypted.
- DPAPI key protection has no plaintext fallback.
- Monitoring sources report health and limitations.
- Rule evaluation is deterministic and independently testable.
- Notification queues are bounded and cancellable.
- Privacy-sensitive features require explicit opt-in.
- Background tasks shut down cleanly.
- Legacy migration is backed up and tested.
- Installer, uninstaller, documentation, and CI checks are complete.

## 14. Open implementation decisions

Resolve these during the foundation phase and record the decision in an ADR:

1. Minimum supported Windows version (recommend Windows 10 22H2+ initially).
2. Whether the app is per-user only or needs a Windows service.
3. Whether UI Automation runs in a dedicated STA thread.
4. Final cryptographic implementation (Rust AEAD crate versus Windows CNG).
5. Whether the first release includes any process suspension action.
6. Exact legacy config formats and migration compatibility.
7. Installer technology and code-signing plan.

Do not introduce a privileged Windows service until a concrete requirement justifies its attack surface and installation complexity.
