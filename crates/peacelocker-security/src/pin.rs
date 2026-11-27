//! PIN verifier creation and validation using Argon2id PHC strings.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use thiserror::Error;

const MAX_PIN_BYTES: usize = 128;
const MAX_PHC_BYTES: usize = 512;
const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PinError {
    #[error("PIN must contain between 1 and 128 UTF-8 bytes")]
    InvalidPinLength,
    #[error("PIN verifier is malformed or uses unsupported parameters")]
    InvalidVerifier,
    #[error("PIN does not match")]
    Mismatch,
    #[error("PIN hashing failed")]
    HashingFailed,
}

fn configured_argon2() -> Result<Argon2<'static>, PinError> {
    let params =
        Params::new(19 * 1024, 2, 1, Some(32)).map_err(|_| PinError::HashingFailed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn parse_bounded_verifier(encoded_verifier: &str) -> Result<PasswordHash<'_>, PinError> {
    if encoded_verifier.is_empty() || encoded_verifier.len() > MAX_PHC_BYTES {
        return Err(PinError::InvalidVerifier);
    }

    let parts: Vec<&str> = encoded_verifier.split('$').collect();
    if parts.len() != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
        return Err(PinError::InvalidVerifier);
    }

    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    for item in parts[3].split(',') {
        let Some((key, value)) = item.split_once('=') else {
            return Err(PinError::InvalidVerifier);
        };
        let parsed = value.parse::<u32>().map_err(|_| PinError::InvalidVerifier)?;
        match key {
            "m" => memory = Some(parsed),
            "t" => iterations = Some(parsed),
            "p" => parallelism = Some(parsed),
            _ => return Err(PinError::InvalidVerifier),
        }
    }

    let memory = memory.ok_or(PinError::InvalidVerifier)?;
    let iterations = iterations.ok_or(PinError::InvalidVerifier)?;
    let parallelism = parallelism.ok_or(PinError::InvalidVerifier)?;
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || !(1..=MAX_ITERATIONS).contains(&iterations)
        || !(1..=MAX_PARALLELISM).contains(&parallelism)
    {
        return Err(PinError::InvalidVerifier);
    }

    PasswordHash::new(encoded_verifier).map_err(|_| PinError::InvalidVerifier)
}

/// Create a PHC-encoded Argon2id verifier with a fresh random salt.
///
/// The raw PIN is never returned or persisted by this function. The caller
/// should minimize the lifetime of its input buffer.
pub fn hash_pin(pin: &[u8]) -> Result<String, PinError> {
    if pin.is_empty() || pin.len() > MAX_PIN_BYTES {
        return Err(PinError::InvalidPinLength);
    }

    let argon2 = configured_argon2()?;
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(pin, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PinError::HashingFailed)
}

/// Validate a stored Argon2id PHC verifier without performing a PIN guess.
pub fn validate_pin_verifier(encoded_verifier: &str) -> Result<(), PinError> {
    parse_bounded_verifier(encoded_verifier).map(|_| ())
}

/// Verify a PIN against a bounded Argon2id PHC verifier.
///
/// Bounds are checked before invoking Argon2 so attacker-controlled PHC
/// parameters cannot request unbounded memory or CPU.
pub fn verify_pin(pin: &[u8], encoded_verifier: &str) -> Result<(), PinError> {
    if pin.is_empty() || pin.len() > MAX_PIN_BYTES {
        return Err(PinError::InvalidPinLength);
    }

    let parsed = parse_bounded_verifier(encoded_verifier)?;
    Argon2::default()
        .verify_password(pin, &parsed)
        .map_err(|_| PinError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trip_and_wrong_pin() {
        let verifier = hash_pin(b"482691").expect("hash succeeds");
        assert!(verifier.starts_with("$argon2id$v=19$"));
        assert_eq!(validate_pin_verifier(&verifier), Ok(()));
        assert_eq!(verify_pin(b"482691", &verifier), Ok(()));
        assert_eq!(verify_pin(b"000000", &verifier), Err(PinError::Mismatch));
    }

    #[test]
    fn each_pin_gets_a_unique_salt() {
        let first = hash_pin(b"482691").expect("hash succeeds");
        let second = hash_pin(b"482691").expect("hash succeeds");
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_unbounded_parameters_before_hashing() {
        let verifier = "$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHQ$YWJj";
        assert_eq!(validate_pin_verifier(verifier), Err(PinError::InvalidVerifier));
        assert_eq!(verify_pin(b"1234", verifier), Err(PinError::InvalidVerifier));
    }

    #[test]
    fn rejects_empty_pin() {
        assert_eq!(hash_pin(b""), Err(PinError::InvalidPinLength));
        let verifier = hash_pin(b"482691").expect("hash succeeds");
        assert_eq!(verify_pin(b"", &verifier), Err(PinError::InvalidPinLength));
    }
}
