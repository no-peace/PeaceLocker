//! Read-only migration support for the legacy C++ vault_data.bin container.
//!
//! Only legacy DPAPI-wrapped files are supported. TPM-wrapped blobs require
//! the old persisted TPM key and are reported as unsupported. RAW plaintext
//! fallback files are explicitly rejected.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use peacelocker_storage::{LegacyImportReport, parse_legacy_text};
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Error as IoError},
    path::Path,
    ptr, slice,
};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree},
    Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData},
};
use zeroize::Zeroizing;

const LEGACY_MAGIC: &[u8; 7] = b"PVBIN01";
const MAX_LEGACY_BLOB_BYTES: u32 = 1024 * 1024;
const MAX_LEGACY_FILE_BYTES: u64 = MAX_LEGACY_BLOB_BYTES as u64 + 11;

#[derive(Debug, Error)]
pub enum LegacyVaultError {
    #[error("legacy vault file I/O failed: {0}")]
    Io(#[from] IoError),
    #[error("legacy vault header is invalid")]
    InvalidHeader,
    #[error("legacy vault payload length is invalid")]
    InvalidLength,
    #[error("legacy vault exceeds the permitted size")]
    TooLarge,
    #[error("legacy TPM-protected vault cannot be migrated by this adapter")]
    UnsupportedTpmProtection,
    #[error("legacy plaintext fallback is rejected")]
    PlaintextFallbackRejected,
    #[error("legacy protection prefix is unsupported")]
    UnsupportedProtection,
    #[error("legacy DPAPI unprotect failed with Windows error {0}")]
    DpapiFailed(u32),
    #[error("legacy DPAPI returned an invalid output buffer")]
    InvalidDpapiOutput,
    #[error("legacy DPAPI output could not be released")]
    DpapiReleaseFailed,
    #[error("legacy configuration is not valid UTF-8")]
    InvalidUtf8,
    #[error("legacy text configuration could not be parsed: {0}")]
    InvalidLegacyText(String),
}

/// Read and decrypt a legacy vault without modifying or deleting the source.
///
/// The legacy HMAC is intentionally not treated as trusted authentication:
/// it used a hardcoded key in the old application. The returned report must be
/// shown to the user and explicitly reviewed before applying to a new store.
pub fn import_legacy_vault(path: &Path) -> Result<LegacyImportReport, LegacyVaultError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_LEGACY_FILE_BYTES {
        return Err(LegacyVaultError::TooLarge);
    }

    let mut file = File::open(path)?;
    let mut magic = [0_u8; 7];
    file.read_exact(&mut magic)?;
    if &magic != LEGACY_MAGIC {
        return Err(LegacyVaultError::InvalidHeader);
    }

    let mut length_bytes = [0_u8; 4];
    file.read_exact(&mut length_bytes)?;
    let blob_length = u32::from_le_bytes(length_bytes);
    if blob_length == 0 {
        return Err(LegacyVaultError::InvalidLength);
    }
    if blob_length > MAX_LEGACY_BLOB_BYTES {
        return Err(LegacyVaultError::TooLarge);
    }

    let mut sealed = vec![0_u8; blob_length as usize];
    file.read_exact(&mut sealed)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(LegacyVaultError::InvalidLength);
    }

    let sealed_text = std::str::from_utf8(&sealed).map_err(|_| LegacyVaultError::InvalidUtf8)?;
    let plaintext = if let Some(encoded) = sealed_text.strip_prefix("DPAPI:") {
        let protected = STANDARD
            .decode(encoded)
            .map_err(|_| LegacyVaultError::InvalidLength)?;
        Zeroizing::new(unprotect_legacy_dpapi(&protected)?)
    } else if sealed_text.starts_with("TPM:") {
        return Err(LegacyVaultError::UnsupportedTpmProtection);
    } else if sealed_text.starts_with("RAW:") {
        return Err(LegacyVaultError::PlaintextFallbackRejected);
    } else {
        return Err(LegacyVaultError::UnsupportedProtection);
    };

    let text = std::str::from_utf8(&plaintext).map_err(|_| LegacyVaultError::InvalidUtf8)?;
    let report = parse_legacy_text(text)
        .map_err(|error| LegacyVaultError::InvalidLegacyText(error.to_string()))?;
    Ok(report)
}

fn unprotect_legacy_dpapi(protected: &[u8]) -> Result<Vec<u8>, LegacyVaultError> {
    if protected.is_empty() || protected.len() > MAX_LEGACY_BLOB_BYTES as usize {
        return Err(LegacyVaultError::InvalidLength);
    }

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| LegacyVaultError::InvalidLength)?,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: input references the caller-owned DPAPI blob for this call.
    // DPAPI allocates output, which is cleared, copied, and freed below.
    unsafe {
        let succeeded = CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0x0000_0001,
            &mut output,
        );
        if succeeded == 0 {
            return Err(LegacyVaultError::DpapiFailed(GetLastError()));
        }
    }

    if output.pbData.is_null() || output.cbData == 0
        || output.cbData as usize > MAX_LEGACY_BLOB_BYTES as usize
    {
        if !output.pbData.is_null() {
            // SAFETY: DPAPI allocated cbData writable bytes on success.
            let remaining = unsafe {
                output.pbData.write_bytes(0, output.cbData as usize);
                LocalFree(output.pbData.cast::<c_void>())
            };
            if !remaining.is_null() {
                return Err(LegacyVaultError::DpapiReleaseFailed);
            }
        }
        return Err(LegacyVaultError::InvalidDpapiOutput);
    }

    // SAFETY: successful DPAPI output guarantees cbData readable bytes.
    let mut plaintext =
        unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    // SAFETY: DPAPI owns a writable cbData-byte allocation.
    let remaining = unsafe {
        output.pbData.write_bytes(0, output.cbData as usize);
        LocalFree(output.pbData.cast::<c_void>())
    };
    if !remaining.is_null() {
        plaintext.fill(0);
        return Err(LegacyVaultError::DpapiReleaseFailed);
    }
    Ok(plaintext)
}
