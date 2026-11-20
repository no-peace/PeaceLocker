//! Narrow wrappers around Windows-specific APIs.
//!
//! Unsafe FFI and COM apartment management belong in this crate. DPAPI is
//! exposed as a small, fail-closed wrapper for protecting the installation DEK.

#[cfg(windows)]
mod dpapi;

#[cfg(windows)]
pub use dpapi::{
    DpapiError, DpapiProtectedEnvelope, ProtectedStorageError, open_configuration,
    protect_data_key, seal_configuration, unprotect_data_key,
};
