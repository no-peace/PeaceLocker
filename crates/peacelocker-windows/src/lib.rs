//! Narrow wrappers around Windows-specific APIs.

#[cfg(windows)]
mod process;
#[cfg(windows)]
mod browser;
#[cfg(windows)]
mod explorer;
#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
mod legacy_import;
#[cfg(windows)]
mod security_session;

#[cfg(windows)]
pub use browser::{BrowserMonitorMessage, BrowserMonitorService, BrowserMonitorStartError};

#[cfg(windows)]
pub use explorer::{ExplorerEnumerationError, ExplorerMonitorMessage, ExplorerMonitorService, ExplorerMonitorStartError};

#[cfg(windows)]
pub use process::{ProcessEnumeration, ProcessEnumerationError, enumerate_processes};

#[cfg(windows)]
pub use legacy_import::{LegacyVaultError, import_legacy_vault};

#[cfg(windows)]
pub use dpapi::{
    DpapiError, DpapiKeyProtector, DpapiProtectedEnvelope, ProtectedStorageError, open_configuration,
    protect_data_key, seal_configuration, unprotect_data_key,
};

#[cfg(windows)]
pub use security_session::{SecuritySession, SecuritySessionError, SetupResult};
