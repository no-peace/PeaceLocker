# PeaceLocker

PeaceLocker is a Windows-focused desktop application project for configurable protection and activity restrictions. The repository currently contains two implementation tracks:

- **Legacy C++ application:** retained as a reference implementation.
- **PeaceLocker 2.0 (Rust):** the active rewrite, developed on `rewrite/rust-v2`.

> [!WARNING]
> **The Rust rewrite is an experimental development build, not a working security product.** It has not been compiled or runtime-tested in this environment or independently security-reviewed. The GUI now provides an interactive ASCII/monospace console, first-run PIN setup and unlock, one-time recovery-code display, encrypted rule persistence, and opt-in read-only Windows process, Explorer and foreground-browser observers. It is still experimental, has not been compile-tested, and does not enforce blocking. Do not rely on this branch to protect files, accounts, or devices.

## Table of contents

- [Current Rust functionality](#current-rust-functionality)
- [What does not work yet](#what-does-not-work-yet)
- [Requirements](#requirements)
- [Get the source](#get-the-source)
- [Build and run](#build-and-run)
- [Run the checks](#run-the-checks)
- [Using the current application](#using-the-current-application)
- [Workspace layout](#workspace-layout)
- [Configuration and data](#configuration-and-data)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Roadmap and documentation](#roadmap-and-documentation)
- [Contributing](#contributing)

## Current Rust functionality

The Rust workspace currently contains these implemented foundations:

| Area | Current implementation |
|---|---|
| Desktop shell | Native egui/eframe application |
| Core engine | Typed application state, protection lifecycle, commands, snapshots and rule evaluation |
| Rules | Validated process-name, executable-path, browser-host and folder-path rules; interactive CRUD UI with encrypted persistence on Windows after unlock |
| Event handling | Typed monitor events and bounded event queue |
| Explorer observation | STA COM worker; filesystem-backed Explorer folder paths only; explicit Start/Stop controls |
| Browser observation | STA UI Automation worker; foreground supported-browser address-bar only; hostname-only events |
| PIN security | Argon2id verifier, first-run setup/unlock UI, persisted lockout, and Windows DPAPI-backed session orchestration |
| Secret encryption | AES-256-GCM authenticated encryption and single-use data-key primitives |
| Windows key protection | Current-user DPAPI adapter |
| Recovery | 128-bit recovery-code generation and Argon2id verifiers |
| Encrypted storage | Versioned encrypted configuration envelope, fresh data key per save, atomic create/replace, validated backup and typed rule records |
| Lockout | Persisted three-failure/six-hour lockout policy with clock rollback handling |
| Legacy import | Read-only import of supported legacy DPAPI-wrapped/text configuration; plaintext fallback and TPM-wrapped import are rejected/not supported |
| Process monitoring | Opt-in Windows process enumeration, supervised polling, baseline snapshot and lifecycle events |

These are foundations and are not equivalent to a finished end-user feature. In particular, a rule match is currently a **decision/report only**; it does not suspend, terminate, or block a process.

## What does not work yet

The following are not available as complete application workflows:

- PIN change and recovery-code unlock/consumption workflows.
- Explicit Windows ACL verification for the per-user data directory; the current app uses the current user's LOCALAPPDATA path and inherited permissions.
- Migration preview, confirmation and complete migration orchestration.
- Explorer folder enforcement.
- Browser URL blocking/enforcement. The current observer only reports foreground hostnames.
- Durable event history.
- Process suspension, termination, filesystem access control or network filtering.
- Automatic startup, tray integration, watchdog and Explorer context-menu integration from the legacy app.
- TPM-backed key protection and TPM-wrapped legacy vault migration.
- Release-grade Windows runtime tests, installer, signing and independent security review.

The roadmap is maintained in [docs/PEACELOCKER_V2_ROADMAP.md](docs/PEACELOCKER_V2_ROADMAP.md).

## Requirements

### Supported development environment

The primary target is **64-bit Windows 10/11**.

Install:

1. **Rust stable toolchain** using [rustup](https://rustup.rs/).
2. Rust components `rustfmt` and `clippy`.
3. **Visual Studio 2022 Build Tools** (or Visual Studio) with the *Desktop development with C++* workload and a Windows SDK. These provide the MSVC linker and Windows build tools required by native dependencies.
4. **Git** to clone and update the repository.

The workspace declares Rust edition 2024 and a minimum Rust version of 1.85. A current stable toolchain is recommended.

After installing Rust, open a new PowerShell terminal and verify:

```powershell
rustc --version
cargo --version
rustup component list --installed
```

If the formatting or lint components are missing:

```powershell
rustup component add rustfmt clippy
```

No external API key, cloud account, or hosted service is required to compile the current workspace. Windows DPAPI is an operating-system facility used by the Windows security-session and encrypted-store workflow.

## Get the source

Clone the repository:

```powershell
git clone https://github.com/no-peace/PeaceLocker.git
cd PeaceLocker
```

Switch to the Rust rewrite branch:

```powershell
git switch rewrite/rust-v2
```

If the branch is not present in your local clone yet:

```powershell
git fetch origin
git switch --track origin/rewrite/rust-v2
```

Check that you are on the correct branch before making changes:

```powershell
git branch --show-current
git status
```

The legacy C++ source is kept at the repository root. The Rust implementation is under `crates/`.

## Build and run

Run all commands from the repository root (the directory containing the root `Cargo.toml`).

### 1. Resolve dependencies and check the workspace

```powershell
cargo check --workspace
```

This checks all workspace crates for the current target without producing a release executable.

### 2. Build the desktop application

Debug build:

```powershell
cargo build -p peacelocker-app
```

Optimized release build:

```powershell
cargo build --release -p peacelocker-app
```

The Windows executable is expected at:

- Debug: `target\debug\peacelocker-app.exe`
- Release: `target\release\peacelocker-app.exe`

Cargo downloads and compiles dependencies on the first build, so the first build can take longer.

### 3. Run the application

Run directly through Cargo:

```powershell
cargo run -p peacelocker-app
```

Or run the debug executable after a successful build:

```powershell
.\target\debug\peacelocker-app.exe
```

For diagnostic logging in PowerShell:

```powershell
$env:RUST_LOG = "info"
cargo run -p peacelocker-app
```

To clear the environment variable:

```powershell
Remove-Item Env:RUST_LOG
```

### 4. Run the release executable

After a successful release build:

```powershell
.\target\release\peacelocker-app.exe
```

There is currently no installer or supported portable distribution package. The executable is a development build.

## Run the checks

Run these from the repository root:

```powershell
# Check all crates
cargo check --workspace

# Check formatting
cargo fmt --all -- --check

# Run Clippy on all targets and treat warnings as errors
cargo clippy --workspace --all-targets -- -D warnings

# Run unit and integration tests in the workspace
cargo test --workspace

# Build the application in release mode
cargo build --release -p peacelocker-app
```

To apply rustfmt rather than only check formatting:

```powershell
cargo fmt --all
```

For verbose test output:

```powershell
cargo test --workspace -- --nocapture
```

**Validation status:** tests and CI workflows have been authored, but do not assume they have passed. A successful local command is required before reporting a build/test as passing. GitHub Actions may also be unavailable when the repository's Actions quota is exhausted.

## Using the current application

1. Build and launch the app using the commands above.
2. The app opens to an interactive ASCII/monospace console. Use the left navigation to switch between Overview, Protection, Monitoring, Rules, Activity, Security, Notifications and Settings.
3. On first launch on Windows, open **Protection** and create a passphrase of 6–128 bytes. Confirm it and create the encrypted configuration.
4. Save the eight one-time recovery codes somewhere offline. Select the code text to copy it, then acknowledge that you saved them. The codes are not shown again.
5. On later launches, open **Protection** and unlock using the passphrase. Three consecutive incorrect attempts trigger a persisted six-hour lockout.
6. Open **Rules** to create, edit, enable/disable or delete process-name, executable-path, folder-path and browser-host rules. On Windows, each change is saved to the encrypted configuration. The Rules panel is locked until authentication succeeds.
7. Open **Monitoring** and manually start the process, Explorer or browser observer using its **[ START ]** control. Use **[ STOP ]** to stop each worker.
8. Review the latest observation and policy-match count in Overview or Activity.

The first successful process snapshot is used as a baseline. Processes already running at that point are not reported as newly started. Later process starts and exits are normalized into core events. Explorer monitoring establishes a first-snapshot baseline, then reports subsequent folder navigation and new filesystem-backed Explorer windows. Virtual shell locations (for example, This PC) are ignored rather than inferred from window titles. Browser monitoring reads known address-bar controls in the foreground window, skips the address bar while it has keyboard focus, and stores hostnames only; it does not inspect page content or background tabs.

Important behavior:

- Monitoring is manual and opt-in; it does not start automatically.
- The process monitor uses query-only handles and does not request administrator elevation. Explorer reads shell window locations and process identities. The browser observer reads a supported foreground browser address-bar value through UI Automation; it never writes to the browser UI.
- Some processes may be inaccessible to query; the UI reports a count.
- Policy matches are informational only. **No process is suspended, killed, or blocked; no folder access is denied; and no browser navigation is blocked.**
- On non-Windows systems, the desktop shell may be buildable, but DPAPI and Windows monitoring are unavailable. Rule edits on non-Windows systems remain in memory only.
- Recovery-code unlock/consumption, PIN change and durable event history are not implemented.

## Workspace layout

```text
PeaceLocker/
├── Cargo.toml
├── README.md
├── README_RUST_V2.md
├── crates/
│   ├── peacelocker-app/           # egui desktop application
│   ├── peacelocker-core/          # state, commands, rules and events
│   ├── peacelocker-security/      # PIN, recovery and encryption primitives
│   ├── peacelocker-monitor/       # monitor contracts, process tracker and worker
│   ├── peacelocker-storage/       # encrypted configuration and legacy parser
│   ├── peacelocker-notifications/ # notification boundary (currently minimal)
│   └── peacelocker-windows/       # Windows APIs, DPAPI and legacy import
├── docs/
│   ├── PEACELOCKER_V2_ARCHITECTURE.md
│   ├── PEACELOCKER_V2_SECURITY.md
│   ├── PEACELOCKER_V2_ROADMAP.md
│   ├── IMPLEMENTATION_STATUS.md
│   └── PHASE_*.md
└── [legacy C++ source files]
```

### Crate responsibilities

- `peacelocker-app`: desktop window, UI and application-level orchestration.
- `peacelocker-core`: platform-independent state transitions, validated rules, event contracts and policy decisions.
- `peacelocker-security`: Argon2id PIN/recovery verification and authenticated encryption primitives.
- `peacelocker-monitor`: process identity tracking, monitor abstractions, bounded event handling and supervised polling.
- `peacelocker-storage`: versioned configuration document, encrypted-store orchestration and legacy text parsing.
- `peacelocker-notifications`: future notification integrations.
- `peacelocker-windows`: Windows-only process enumeration, DPAPI and legacy vault support.

## Configuration and data

On Windows, the app stores its encrypted configuration at:

`%LOCALAPPDATA%\PeaceLocker\config.enc`

The first-run flow creates the store using a no-clobber write. The store uses a fresh random data-encryption key for each save, AES-256-GCM for the configuration payload, and Windows current-user DPAPI to protect the data key. Rule CRUD and persisted lockout state are saved through the authenticated session. The PIN is an application authentication gate; it is not used to derive the encryption key.

The configuration directory inherits the current user's Windows profile permissions. Explicit ACL verification, reparse-point hardening and single-instance coordination are not yet implemented. Do not manually edit the encrypted configuration file or copy it to another Windows user account and expect DPAPI to decrypt it.

## Troubleshooting

### `cargo` or `rustc` is not recognized

Install Rust with rustup, close and reopen PowerShell, then run:

```powershell
rustup show
cargo --version
```

Check that the rustup Cargo bin directory is on PATH (normally `%USERPROFILE%\.cargo\bin`).

### Linker or Windows SDK errors

Install Visual Studio 2022 Build Tools with the *Desktop development with C++* workload and a Windows 10/11 SDK. Reopen the terminal after installation.

### Rust component missing

```powershell
rustup component add rustfmt clippy
```

### Dependency download or network errors

Retry after confirming internet access:

```powershell
cargo fetch
cargo check --workspace
```

### The process monitor shows inaccessible processes

This is expected for some protected, elevated, system or short-lived processes. The monitor intentionally uses limited query access and does not elevate itself. It skips processes it cannot safely identify.

### A feature shown in the roadmap is not visible in the app

The roadmap includes planned and partially implemented work. Only the features explicitly listed as current functionality in this README should be considered present in the current application.

## Security notes

- Never commit PINs, recovery codes, webhook URLs, credentials, personal data or real vault contents.
- Do not add plaintext fallback for secrets or credentials.
- Keep unsafe Windows FFI isolated in `peacelocker-windows`.
- Keep monitor workers cancellable and ensure COM interfaces are created, used and released on the correct apartment thread.
- Treat monitor observations as best-effort telemetry, not as operating-system access control.
- Do not enable webcam capture, activity telemetry or network notifications without explicit user consent.
- Report security limitations and validation status accurately.
- The Rust rewrite is not production-ready and must not be used as the sole protection for sensitive data.

## Roadmap and documentation

Read these documents for design details and implementation decisions:

- [Rust v2 architecture](docs/PEACELOCKER_V2_ARCHITECTURE.md)
- [Security and privacy specification](docs/PEACELOCKER_V2_SECURITY.md)
- [Implementation roadmap](docs/PEACELOCKER_V2_ROADMAP.md)
- [Phase 1 — security foundation](docs/PHASE_1_SECURITY_FOUNDATION.md)
- [Phase 2 — storage and migration](docs/PHASE_2_STORAGE_AND_MIGRATION.md)
- [Phase 3 — core engine](docs/PHASE_3_CORE_ENGINE.md)
- [Phase 4 — monitoring](docs/PHASE_4_MONITORING.md)
- [Phase 7 — PIN session foundation](docs/PHASE_7_PIN_SESSION.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)

## Contributing

1. Work on `rewrite/rust-v2` for Rust rewrite changes.
2. Keep the legacy C++ implementation intact unless a task explicitly targets it.
3. Make focused changes and add tests for new behavior.
4. Run formatting, Clippy, tests and a Windows build before considering a change validated.
5. Update the implementation status and roadmap when milestone scope changes.
6. Do not merge to `main` or claim production readiness without review and explicit release approval.

