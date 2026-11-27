//! One-time recovery-code generation and verification.

use crate::{hash_pin, verify_pin};
use getrandom::getrandom;
use thiserror::Error;

const MAX_RECOVERY_CODES: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryCodeError {
    #[error("recovery-code count must be between 1 and 16")]
    InvalidCount,
    #[error("secure random generation failed")]
    RandomUnavailable,
    #[error("recovery-code hashing failed")]
    HashingFailed,
}

/// A set of hashed, single-use recovery codes.
///
/// This type intentionally does not expose stored verifier strings or
/// implement Debug/Serialize. Persist the verifier strings only inside the
/// encrypted configuration store.
pub struct RecoveryCodeSet {
    hashes: Vec<String>,
}

impl RecoveryCodeSet {
    /// Number of unused recovery codes.
    pub fn remaining(&self) -> usize {
        self.hashes.len()
    }

    /// Verify a submitted code and consume it on success.
    pub fn consume(&mut self, code: &str) -> bool {
        let mut matched = None;
        for (index, verifier) in self.hashes.iter().enumerate() {
            if verify_pin(code.as_bytes(), verifier).is_ok() {
                matched = Some(index);
            }
        }
        if let Some(index) = matched {
            self.hashes.remove(index);
            true
        } else {
            false
        }
    }

    /// Return the encoded verifiers for encrypted persistence.
    pub fn verifiers_for_storage(&self) -> &[String] {
        &self.hashes
    }

    /// Restore verifiers from an already authenticated encrypted store.
    pub fn from_stored_verifiers(hashes: Vec<String>) -> Result<Self, RecoveryCodeError> {
        if hashes.len() > MAX_RECOVERY_CODES
            || hashes.iter().any(|hash| hash.len() > 512 || !hash.starts_with("$argon2id$"))
        {
            return Err(RecoveryCodeError::HashingFailed);
        }
        Ok(Self { hashes })
    }
}

/// Plaintext recovery codes are returned once; the set retains only Argon2id verifiers.
pub struct RecoveryCodeBundle {
    pub codes: Vec<String>,
    pub verifier_set: RecoveryCodeSet,
}

/// Generate high-entropy, single-use recovery codes.
pub fn generate_recovery_codes(count: usize) -> Result<RecoveryCodeBundle, RecoveryCodeError> {
    if !(1..=MAX_RECOVERY_CODES).contains(&count) {
        return Err(RecoveryCodeError::InvalidCount);
    }

    let mut codes = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut random = [0_u8; 16];
        getrandom(&mut random).map_err(|_| RecoveryCodeError::RandomUnavailable)?;
        let code = random.iter().map(|byte| format!("{byte:02X}")).collect::<String>();
        let verifier =
            hash_pin(code.as_bytes()).map_err(|_| RecoveryCodeError::HashingFailed)?;
        codes.push(code);
        hashes.push(verifier);
    }

    Ok(RecoveryCodeBundle {
        codes,
        verifier_set: RecoveryCodeSet { hashes },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_is_single_use() {
        let mut bundle = generate_recovery_codes(2).expect("generation succeeds");
        let code = bundle.codes[0].clone();
        assert_eq!(bundle.verifier_set.remaining(), 2);
        assert!(bundle.verifier_set.consume(&code));
        assert_eq!(bundle.verifier_set.remaining(), 1);
        assert!(!bundle.verifier_set.consume(&code));
    }

    #[test]
    fn regeneration_replaces_the_old_set() {
        let first = generate_recovery_codes(1).expect("generation succeeds");
        let mut second = generate_recovery_codes(1).expect("generation succeeds");
        assert!(!second.verifier_set.consume(&first.codes[0]));
        assert!(second.verifier_set.consume(&second.codes[0]));
    }

    #[test]
    fn count_is_bounded() {
        assert!(matches!(generate_recovery_codes(0), Err(RecoveryCodeError::InvalidCount)));
        assert!(matches!(generate_recovery_codes(17), Err(RecoveryCodeError::InvalidCount)));
    }
}
