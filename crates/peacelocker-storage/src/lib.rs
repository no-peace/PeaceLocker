//! Versioned encrypted configuration persistence.
//!
//! The store never writes plaintext configuration. Every save creates a new
//! random DEK, wraps it through a platform KeyProtector, and encrypts the
//! serialized document. Replacement uses a same-directory temporary file.

use peacelocker_security::{
    DataKey, EncryptedEnvelope, EncryptionError, LockoutState, SecretError, decrypt_with_aad,
    encrypt_with_aad,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;
use zeroize::Zeroizing;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
const ENVELOPE_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 20 * 1024 * 1024;
const MAX_PROTECTED_KEY_BYTES: usize = 64 * 1024;
const MAX_RECOVERY_VERIFIERS: usize = 16;
const CONFIG_AAD: &[u8] = b"PeaceLocker/configuration-store/v1";

#[derive(Debug, Error)]
#[error("platform key protection failed")]
pub struct KeyProtectionError;

/// Platform boundary for protecting a fresh DEK and restoring a DEK.
///
/// Implementations must fail closed. They must not write raw key bytes to disk.
pub trait KeyProtector {
    fn protect_key(&self, key: &DataKey) -> Result<Vec<u8>, KeyProtectionError>;
    fn unprotect_key(&self, protected: &[u8]) -> Result<DataKey, KeyProtectionError>;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    pub schema_version: u32,
    pub revision: u64,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub pin_verifier: String,
    pub recovery_verifiers: Vec<String>,
    pub lockout: LockoutState,
}

impl ConfigDocument {
    pub fn new(pin_verifier: String, recovery_verifiers: Vec<String>, now_unix: u64) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            revision: 1,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            pin_verifier,
            recovery_verifiers,
            lockout: LockoutState::default(),
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION
            || self.revision == 0
            || self.created_at_unix == 0
            || self.updated_at_unix < self.created_at_unix
            || self.pin_verifier.len() > 512
            || !self.pin_verifier.starts_with("$argon2id$")
            || self.recovery_verifiers.len() > MAX_RECOVERY_VERIFIERS
            || self.recovery_verifiers.iter().any(|value| {
                value.len() > 512 || !value.starts_with("$argon2id$")
            })
            || !self.lockout.validate()
        {
            return Err(StoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreEnvelope {
    format_version: u32,
    protected_dek: Vec<u8>,
    payload: EncryptedEnvelope,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("configuration file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration JSON is malformed")]
    Serialization(#[from] serde_json::Error),
    #[error("configuration encryption failed: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("platform key protection failed")]
    KeyProtection(#[from] KeyProtectionError),
    #[error("secure random generation failed")]
    Secret(#[from] SecretError),
    #[error("configuration schema or fields are invalid")]
    InvalidConfiguration,
    #[error("encrypted configuration envelope is invalid or unsupported")]
    InvalidEnvelope,
    #[error("configuration file exceeds the permitted size")]
    FileTooLarge,
    #[error("configuration path has no parent directory")]
    InvalidPath,
    #[error("atomic file replacement failed: {0}")]
    Persist(#[from] tempfile::PersistError),
    #[error("the existing configuration could not be validated; refusing to overwrite it")]
    ExistingConfigurationInvalid,
}

pub struct EncryptedStore<P> {
    path: PathBuf,
    protector: P,
}

impl<P: KeyProtector> EncryptedStore<P> {
    pub fn new(path: impl Into<PathBuf>, protector: P) -> Self {
        Self { path: path.into(), protector }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<ConfigDocument, StoreError> {
        self.load_from_path(&self.path)
    }

    /// Load and authenticate the primary configuration. If it fails, callers
    /// may explicitly offer restore_backup; backup is never silently trusted.
    pub fn load_backup(&self) -> Result<ConfigDocument, StoreError> {
        self.load_from_path(&backup_path(&self.path))
    }

    /// Save a new encrypted generation. The previous authenticated primary
    /// is retained as one backup before atomic replacement.
    pub fn save(&self, document: &ConfigDocument) -> Result<(), StoreError> {
        document.validate()?;
        let parent = self.path.parent().ok_or(StoreError::InvalidPath)?;
        fs::create_dir_all(parent)?;

        if self.path.exists() {
            self.load().map_err(|_| StoreError::ExistingConfigurationInvalid)?;
            let old_bytes = read_bounded(&self.path)?;
            atomic_write(&backup_path(&self.path), &old_bytes)?;
        }

        let plaintext = Zeroizing::new(serde_json::to_vec(document)?);
        if plaintext.len() > MAX_CONFIG_BYTES {
            return Err(StoreError::FileTooLarge);
        }

        let key = DataKey::generate()?;
        let protected_dek = self.protector.protect_key(&key)?;
        if protected_dek.is_empty() || protected_dek.len() > MAX_PROTECTED_KEY_BYTES {
            return Err(StoreError::InvalidEnvelope);
        }
        let payload = encrypt_with_aad(&key, &plaintext, &aad_for(&protected_dek))?;
        let envelope = StoreEnvelope {
            format_version: ENVELOPE_VERSION,
            protected_dek,
            payload,
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(StoreError::FileTooLarge);
        }
        atomic_write(&self.path, &bytes)
    }

    /// Restore only after fully validating the backup. Saving it creates a
    /// fresh DEK and a fresh authenticated envelope; the damaged primary is
    /// not copied over the known-good backup.
    pub fn restore_backup(&self) -> Result<(), StoreError> {
        let backup = self.load_backup()?;
        backup.validate()?;
        let bytes = read_bounded(&backup_path(&self.path))?;
        atomic_write(&self.path, &bytes)
    }

    fn load_from_path(&self, path: &Path) -> Result<ConfigDocument, StoreError> {
        let bytes = read_bounded(path)?;
        let envelope: StoreEnvelope = serde_json::from_slice(&bytes)?;
        if envelope.format_version != ENVELOPE_VERSION
            || envelope.protected_dek.is_empty()
            || envelope.protected_dek.len() > MAX_PROTECTED_KEY_BYTES
        {
            return Err(StoreError::InvalidEnvelope);
        }
        let key = self.protector.unprotect_key(&envelope.protected_dek)?;
        let plaintext = Zeroizing::new(decrypt_with_aad(
            &key,
            &envelope.payload,
            &aad_for(&envelope.protected_dek),
        )?);
        if plaintext.len() > MAX_CONFIG_BYTES {
            return Err(StoreError::FileTooLarge);
        }
        let document: ConfigDocument = serde_json::from_slice(&plaintext)?;
        document.validate()?;
        Ok(document)
    }
}

fn aad_for(protected_dek: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONFIG_AAD.len() + protected_dek.len());
    aad.extend_from_slice(CONFIG_AAD);
    aad.extend_from_slice(protected_dek);
    aad
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StoreError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_ENVELOPE_BYTES {
        return Err(StoreError::FileTooLarge);
    }
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ENVELOPE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(StoreError::FileTooLarge);
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidPath)?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use peacelocker_security::{DataKey, hash_pin};

    struct TestProtector;

    impl KeyProtector for TestProtector {
        fn protect_key(&self, key: &DataKey) -> Result<Vec<u8>, KeyProtectionError> {
            Ok(key.expose_for_platform().to_vec())
        }

        fn unprotect_key(&self, protected: &[u8]) -> Result<DataKey, KeyProtectionError> {
            let bytes: [u8; 32] = protected.try_into().map_err(|_| KeyProtectionError)?;
            Ok(DataKey::from_bytes(bytes))
        }
    }

    fn document() -> ConfigDocument {
        ConfigDocument::new(hash_pin(b"correct horse").unwrap(), Vec::new(), 1_800_000_000)
    }

    #[test]
    fn encrypted_store_round_trip_and_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = EncryptedStore::new(&path, TestProtector);
        let first = document();
        store.save(&first).unwrap();
        assert_eq!(store.load().unwrap(), first);

        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_unix += 1;
        store.save(&second).unwrap();
        assert_eq!(store.load().unwrap(), second);
        assert_eq!(store.load_backup().unwrap(), first);
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = EncryptedStore::new(&path, TestProtector);
        store.save(&document()).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.iter().position(|byte| *byte == b'[').unwrap();
        bytes[index] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn invalid_configuration_is_not_saved() {
        let directory = tempfile::tempdir().unwrap();
        let store = EncryptedStore::new(directory.path().join("config.json"), TestProtector);
        let mut invalid = document();
        invalid.schema_version = 99;
        assert!(matches!(store.save(&invalid), Err(StoreError::InvalidConfiguration)));
        assert!(!store.exists());
    }

    #[test]
    fn corrupt_primary_does_not_overwrite_good_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let store = EncryptedStore::new(&path, TestProtector);
        let first = document();
        store.save(&first).unwrap();
        let mut second = first.clone();
        second.revision = 2;
        second.updated_at_unix += 1;
        store.save(&second).unwrap();
        fs::write(&path, b"corrupt").unwrap();
        assert!(store.save(&first).is_err());
        assert_eq!(store.load_backup().unwrap(), first);
        store.restore_backup().unwrap();
        assert_eq!(store.load().unwrap(), first);
    }
}
