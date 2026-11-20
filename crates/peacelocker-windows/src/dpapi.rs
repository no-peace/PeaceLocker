//! Windows Data Protection API (DPAPI) wrappers.
//!
//! The default scope is the current Windows user. No static optional entropy
//! is used. Failure is returned to the caller; there is no plaintext fallback.

use peacelocker_security::DataKey;
use std::{ffi::c_void, ptr, slice};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree},
    Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData},
};

const CRYPTPROTECT_UI_FORBIDDEN_FLAG: u32 = 0x0000_0001;

#[derive(Debug, Error)]
pub enum DpapiError {
    #[error("DPAPI operation failed with Windows error {0}")]
    ApiFailed(u32),
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
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };

    // SAFETY: input points to a live 32-byte key for the duration of the call;
    // DPAPI writes an allocated output buffer that is copied and freed below.
    unsafe {
        let succeeded = CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN_FLAG,
            &mut output,
        );
        if succeeded == 0 {
            return Err(DpapiError::ApiFailed(GetLastError()));
        }
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
        let succeeded = CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN_FLAG,
            &mut output,
        );
        if succeeded == 0 {
            return Err(DpapiError::ApiFailed(GetLastError()));
        }
    }

    let mut bytes = copy_and_free_output(output)?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(DpapiError::InvalidKeyLength);
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes);
    bytes.fill(0);
    Ok(DataKey::from_bytes(key))
}

fn copy_and_free_output(output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, DpapiError> {
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            // SAFETY: DPAPI allocated this buffer and ownership is transferred
            // to the caller, which releases it with LocalFree.
            unsafe {
                let _ = LocalFree(output.pbData.cast::<c_void>());
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


use peacelocker_security::{
    DataKey, EncryptedEnvelope, EncryptionError, SecretError, decrypt_with_aad,
    encrypt_with_aad,
};
use serde::{Deserialize, Serialize};

const DPAPI_ENVELOPE_VERSION: u32 = 1;

/// A complete configuration envelope: an AEAD-encrypted payload plus a
/// current-user DPAPI-wrapped DEK. Serialize this structure for persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpapiProtectedEnvelope {
    pub format_version: u32,
    pub protected_dek: Vec<u8>,
    pub payload: EncryptedEnvelope,
}

#[derive(Debug, Error)]
pub enum ProtectedStorageError {
    #[error(transparent)]
    Dpapi(#[from] DpapiError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error(transparent)]
    Random(#[from] SecretError),
    #[error("unsupported protected-envelope version")]
    UnsupportedVersion,
    #[error("protected key blob is empty or too large")]
    InvalidProtectedKey,
}

/// Generate a DEK, wrap it with current-user DPAPI, then encrypt the payload.
/// The DPAPI blob is included as AEAD associated data to prevent key-blob swaps.
pub fn seal_configuration(plaintext: &[u8]) -> Result<DpapiProtectedEnvelope, ProtectedStorageError> {
    let key = DataKey::generate()?;
    let protected_dek = protect_data_key(&key)?;
    let payload = encrypt_with_aad(&key, plaintext, &protected_dek)?;
    Ok(DpapiProtectedEnvelope {
        format_version: DPAPI_ENVELOPE_VERSION,
        protected_dek,
        payload,
    })
}

/// Unwrap the DEK and authenticate the payload. Any DPAPI or AEAD failure is
/// returned; no plaintext fallback or partial data is exposed.
pub fn open_configuration(
    envelope: &DpapiProtectedEnvelope,
) -> Result<Vec<u8>, ProtectedStorageError> {
    if envelope.format_version != DPAPI_ENVELOPE_VERSION {
        return Err(ProtectedStorageError::UnsupportedVersion);
    }
    if envelope.protected_dek.is_empty() || envelope.protected_dek.len() > 64 * 1024 {
        return Err(ProtectedStorageError::InvalidProtectedKey);
    }
    let key = unprotect_data_key(&envelope.protected_dek)?;
    Ok(decrypt_with_aad(&key, &envelope.payload, &envelope.protected_dek)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_wrapped_configuration_round_trip() {
        let envelope = seal_configuration(b"secret configuration")
            .expect("DPAPI should work for the current test user");
        let plaintext = open_configuration(&envelope).expect("DPAPI and AEAD should verify");
        assert_eq!(plaintext, b"secret configuration");
    }

    #[test]
    fn modified_dpapi_blob_is_rejected() {
        let mut envelope = seal_configuration(b"secret configuration")
            .expect("DPAPI should work for the current test user");
        envelope.protected_dek[0] ^= 1;
        assert!(open_configuration(&envelope).is_err());
    }
}
