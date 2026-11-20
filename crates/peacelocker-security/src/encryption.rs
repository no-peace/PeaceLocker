//! AES-256-GCM envelope encryption with authenticated format metadata.

use crate::DataKey;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const FORMAT_VERSION: u32 = 1;
const CIPHER_NAME: &str = "AES-256-GCM";
const ASSOCIATED_DATA: &[u8] = b"PeaceLocker/config/v1/AES-256-GCM";
const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Serialized encrypted configuration envelope.
///
/// The 16-byte authentication tag is appended to ciphertext by the AEAD
/// implementation. The nonce is public and must never be reused with a key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub format_version: u32,
    pub cipher: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("secure random generation failed")]
    RandomUnavailable,
    #[error("plaintext exceeds the 16 MiB configuration limit")]
    PayloadTooLarge,
    #[error("unsupported or malformed encrypted envelope")]
    InvalidEnvelope,
    #[error("authenticated decryption failed; data may be corrupted or modified")]
    AuthenticationFailed,
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Encrypt a configuration payload using AES-256-GCM and a fresh random nonce.
///
/// A key must be rotated before 2^32 encryptions. PeaceLocker configuration
/// writes are low-volume; the storage layer must still enforce key rotation.
pub fn encrypt(key: &DataKey, plaintext: &[u8]) -> Result<EncryptedEnvelope, EncryptionError> {
    encrypt_with_aad(key, plaintext, &[])
}

/// Encrypt with caller-supplied authenticated metadata in addition to the
/// fixed PeaceLocker envelope context. The metadata is authenticated, not encrypted.
pub fn encrypt_with_aad(
    key: &DataKey,
    plaintext: &[u8],
    external_aad: &[u8],
) -> Result<EncryptedEnvelope, EncryptionError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES || external_aad.len() > 64 * 1024 {
        return Err(EncryptionError::PayloadTooLarge);
    }

    let mut nonce_bytes = [0_u8; 12];
    getrandom(&mut nonce_bytes).map_err(|_| EncryptionError::RandomUnavailable)?;
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_| EncryptionError::EncryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut aad = Vec::with_capacity(ASSOCIATED_DATA.len() + external_aad.len());
    aad.extend_from_slice(ASSOCIATED_DATA);
    aad.extend_from_slice(external_aad);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(EncryptedEnvelope {
        format_version: FORMAT_VERSION,
        cipher: CIPHER_NAME.to_owned(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Authenticate and decrypt an envelope. No plaintext is returned on failure.
pub fn decrypt(
    key: &DataKey,
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>, EncryptionError> {
    decrypt_with_aad(key, envelope, &[])
}

/// Authenticate and decrypt an envelope using the same external metadata
/// supplied during encryption.
pub fn decrypt_with_aad(
    key: &DataKey,
    envelope: &EncryptedEnvelope,
    external_aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if external_aad.len() > 64 * 1024 || envelope.format_version != FORMAT_VERSION
        || envelope.cipher != CIPHER_NAME
        || envelope.ciphertext.len() < 16
        || envelope.ciphertext.len() > MAX_PLAINTEXT_BYTES + 16
    {
        return Err(EncryptionError::InvalidEnvelope);
    }

    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_| EncryptionError::InvalidEnvelope)?;
    let mut aad = Vec::with_capacity(ASSOCIATED_DATA.len() + external_aad.len());
    aad.extend_from_slice(ASSOCIATED_DATA);
    aad.extend_from_slice(external_aad);
    cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload { msg: envelope.ciphertext.as_ref(), aad: &aad },
        )
        .map_err(|_| EncryptionError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_round_trip() {
        let key = DataKey::generate().expect("CSPRNG available");
        let envelope = encrypt(&key, b"private settings").expect("encryption succeeds");
        assert_eq!(decrypt(&key, &envelope).expect("authentication succeeds"), b"private settings");
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let key = DataKey::generate().expect("CSPRNG available");
        let mut envelope = encrypt(&key, b"private settings").expect("encryption succeeds");
        envelope.ciphertext[0] ^= 0x01;
        assert_eq!(decrypt(&key, &envelope), Err(EncryptionError::AuthenticationFailed));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let first = DataKey::generate().expect("CSPRNG available");
        let second = DataKey::generate().expect("CSPRNG available");
        let envelope = encrypt(&first, b"private settings").expect("encryption succeeds");
        assert_eq!(decrypt(&second, &envelope), Err(EncryptionError::AuthenticationFailed));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let key = DataKey::generate().expect("CSPRNG available");
        let mut envelope = encrypt(&key, b"data").expect("encryption succeeds");
        envelope.format_version = 99;
        assert_eq!(decrypt(&key, &envelope), Err(EncryptionError::InvalidEnvelope));
    }
}
