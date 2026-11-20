//! In-memory data-encryption key handling.

use getrandom::getrandom;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("the operating system secure random generator failed")]
    RandomUnavailable,
}

/// A randomly generated 256-bit data-encryption key.
///
/// The key is zeroized when this value is dropped. It is intentionally not
/// Clone, Debug, Serialize, or Deserialize.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Generate a fresh key using the operating system CSPRNG.
    pub fn generate() -> Result<Self, SecretError> {
        let mut bytes = [0_u8; 32];
        getrandom(&mut bytes).map_err(|_| SecretError::RandomUnavailable)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Reconstitute a key after unwrapping it with the platform key protector.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the key bytes for the platform key-protection boundary.
    /// Callers must not retain or copy the returned bytes.
    pub fn expose_for_platform(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_32_bytes_and_distinct() {
        let first = DataKey::generate().expect("CSPRNG available");
        let second = DataKey::generate().expect("CSPRNG available");
        assert_ne!(first.expose(), second.expose());
        assert_eq!(first.expose().len(), 32);
    }
}
