//! Windows Data Protection API (DPAPI) wrappers.
//!
//! The default scope is the current Windows user. No static optional entropy
//! is used. Failure is returned to the caller; there is no plaintext fallback.

use peacelocker_security::DataKey;
use std::{ffi::c_void, slice};
use thiserror::Error;
use windows::{
    Win32::Foundation::{HLOCAL, LocalFree},
    Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
    },
    core::PCWSTR,
};

const CRYPTPROTECT_UI_FORBIDDEN_FLAG: u32 = 0x0000_0001;

#[derive(Debug, Error)]
pub enum DpapiError {
    #[error("DPAPI operation failed: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("DPAPI returned an invalid output buffer")]
    InvalidOutput,
    #[error("protected key has an invalid length")]
    InvalidKeyLength,
}

/// Protect the 256-bit data key for the current Windows user.
///
/// The returned blob is opaque DPAPI output and must be stored with the
/// encrypted configuration. This is user-scope protection, not TPM protection.
pub fn protect_data_key(key: &DataKey) -> Result<Vec<u8>, DpapiError> {
    let bytes = key.expose_for_platform();
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| DpapiError::InvalidKeyLength)?,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: input points to a live 32-byte key for the duration of the call;
    // DPAPI writes an allocated output buffer that is copied and freed below.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN_FLAG,
            &mut output,
        )?;
    }

    copy_and_free_output(output)
}

/// Unprotect a current-user DPAPI blob and restore the in-memory data key.
pub fn unprotect_data_key(protected: &[u8]) -> Result<DataKey, DpapiError> {
    if protected.is_empty() || protected.len() > 64 * 1024 {
        return Err(DpapiError::InvalidKeyLength);
    }

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| DpapiError::InvalidKeyLength)?,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: input points to the caller-owned protected blob for this call;
    // DPAPI allocates output, which is copied and freed before returning.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN_FLAG,
            &mut output,
        )?;
    }

    let mut bytes = copy_and_free_output(output)?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(DpapiError::InvalidKeyLength);
    }
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DpapiError::InvalidKeyLength)?;
    Ok(DataKey::from_bytes(key))
}

fn copy_and_free_output(output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, DpapiError> {
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            // SAFETY: DPAPI allocated this buffer and ownership is transferred
            // to the caller, which releases it with LocalFree.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(output.pbData.cast::<c_void>())));
            }
        }
        return Err(DpapiError::InvalidOutput);
    }

    // SAFETY: DPAPI guarantees cbData readable bytes at pbData on success.
    let bytes = unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();

    // Clear DPAPI's allocation before releasing it. This is especially
    // important for CryptUnprotectData, whose output contains the raw DEK.
    // SAFETY: pbData points to cbData writable bytes allocated by DPAPI.
    unsafe {
        output.pbData.write_bytes(0, output.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast::<c_void>())));
    }
    Ok(bytes)
}
