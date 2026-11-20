# Rust v2 implementation status

Last updated: 2026-11-21

## Current milestone

**Phase 0 — Workspace foundation: implemented, CI validation pending.**

Branch: `rewrite/rust-v2`

## Completed in the initial foundation pass

- [x] Created the Rust rewrite branch without changing `main`.
- [x] Created the Cargo workspace.
- [x] Added application, core, security, monitor, storage, notifications, and Windows platform crates.
- [x] Added the initial egui desktop shell.
- [x] Added a typed, platform-independent application snapshot.
- [x] Added initial core unit tests.
- [x] Added Windows GitHub Actions workflow for formatting, Clippy, and tests.
- [x] Added Rust development instructions and corrected the root README for the two-track repository.

## Not yet verified

- [ ] Windows CI completes successfully.
- [ ] Dependency resolution and compilation are confirmed.
- [ ] Formatting, Clippy, and tests pass on the remote runner.
- [ ] The desktop app is launched and visually checked on a Windows machine.

Do not mark Phase 0 complete until all verification items above pass.

## Explicitly not implemented yet

- PIN authentication or lockout.
- Argon2id password verifier.
- DPAPI key protection or authenticated encryption.
- Configuration persistence or legacy migration.
- Process, browser, or Explorer monitoring.
- Rules engine and enforcement actions.
- Discord notifications or webcam capture.
- Tray, startup registration, and watchdog lifecycle.

These features must be implemented in their planned phases. The current skeleton is not a security product and must not be used to protect real data.
