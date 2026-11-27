//! In-memory data-encryption key handling.

use getrandom::getrandom;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("the operating system secure random generator failed")]
    RandomUnavailable,
}

/// A randomly generated 256-bit data-encryption key.
///
/// Key bytes are zeroized on drop. A generated key can encrypt exactly one
/// envelope; a key restored from DPAPI is decrypt-only. The type is not
/// Clone, Debug, Serialize, or Deserialize.
pub struct DataKey {
    bytes: Zeroizing<[u8; 32]>,
    encryption_used: AtomicBool,
}

impl DataKey {
    /// Generate a fresh key using the operating system CSPRNG.
    pub fn generate() -> Result<Self, SecretError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom(&mut *bytes).map_err(|_| SecretError::RandomUnavailable)?;
        Ok(Self {
            bytes,
            encryption_used: AtomicBool::new(false),
        })
    }

    /// Reconstitute a key after unwrapping it with the platform key protector.
    /// Restored keys are decrypt-only to prevent nonce reuse across restarts.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            encryption_used: AtomicBool::new(true),
        }
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Borrow the key bytes for the platform key-protection boundary.
    /// Callers must not retain or copy the returned bytes.
    pub fn expose_for_platform(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn claim_for_encryption(&self) -> bool {
        self.encryption_used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_32_bytes_and_distinct() {
        let first = DataKey::generate().expect("CSPRNG available");
        let second = DataKey::generate().expect("CSPRNG available");
        assert_ne!(first.expose_for_platform(), second.expose_for_platform());
        assert_eq!(first.expose().len(), 32);
    }

    #[test]
    fn restored_key_is_decrypt_only() {
        let generated = DataKey::generate().expect("CSPRNG available");
        let restored = DataKey::from_bytes(*generated.expose());
        assert!(!restored.claim_for_encryption());
    }
}
