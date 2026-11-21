//! Narrow wrappers around Windows-specific APIs.
//!
//! Unsafe FFI and COM apartment management belong in this crate. DPAPI is
//! exposed as a small, fail-closed wrapper for protecting the installation DEK.

#[cfg(windows)]
mod process;
#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
mod legacy_import;

#[cfg(windows)]
pub use process::{ProcessEnumeration, ProcessEnumerationError, enumerate_processes};

#[cfg(windows)]
pub use legacy_import::{LegacyVaultError, import_legacy_vault};

#[cfg(windows)]
pub use dpapi::{
    DpapiError, DpapiKeyProtector, DpapiProtectedEnvelope, ProtectedStorageError, open_configuration,
    protect_data_key, seal_configuration, unprotect_data_key,
};
