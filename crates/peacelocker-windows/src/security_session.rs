//! PIN-gated access to the current-user DPAPI encrypted configuration.
//!
//! The PIN is an authentication gate; DPAPI remains responsible for protecting
//! the data-encryption key. No default PIN or plaintext fallback exists.

use peacelocker_security::{
    AuthError, LockoutState, PinAuthOutcome, PinError, RecoveryCodeError,
    authenticate_pin, generate_recovery_codes, hash_pin,
};
use peacelocker_storage::{ConfigDocument, EncryptedStore, KeyProtector, StoreError};
use thiserror::Error;

use crate::DpapiKeyProtector;

const RECOVERY_CODE_COUNT: usize = 8;

#[derive(Debug, Error)]
pub enum SecuritySessionError {
    #[error("encrypted configuration storage failed")]
    Store(#[from] StoreError),
    #[error("PIN operation failed")]
    Pin(#[from] PinError),
    #[error("recovery-code operation failed")]
    Recovery(#[from] RecoveryCodeError),
    #[error("PIN authentication state is invalid")]
    Authentication(#[from] AuthError),
    #[error("security is already configured")]
    AlreadyConfigured,
    #[error("security has not been configured")]
    NotConfigured,
}

/// Result of first-run setup. Recovery codes are plaintext and must be shown
/// to the user once; only their Argon2id verifiers are persisted.
pub struct SetupResult {
    pub recovery_codes: Vec<String>,
}

/// Authenticated configuration session. Keep this object alive only while the
/// app is unlocked. Dropping it releases the in-memory configuration.
pub struct SecuritySession {
    store: EncryptedStore<DpapiKeyProtector>,
    config: ConfigDocument,
}

impl SecuritySession {
    pub fn configuration_exists(path: impl Into<std::path::PathBuf>) -> bool {
        EncryptedStore::new(path, DpapiKeyProtector).exists()
    }

    /// First-run setup. Refuses to overwrite any existing file, including a
    /// corrupt one. The caller must securely display and let the user save
    /// the returned one-time recovery codes.
    pub fn setup(
        path: impl Into<std::path::PathBuf>,
        pin: &[u8],
        now_unix: u64,
    ) -> Result<(Self, SetupResult), SecuritySessionError> {
        let store = EncryptedStore::new(path, DpapiKeyProtector);
        if store.exists() {
            return Err(SecuritySessionError::AlreadyConfigured);
        }
        let verifier = hash_pin(pin)?;
        let recovery = generate_recovery_codes(RECOVERY_CODE_COUNT)?;
        let mut config = ConfigDocument::new(
            verifier,
            recovery.verifier_set.verifiers_for_storage().to_vec(),
            now_unix,
        );
        config.lockout = LockoutState::default();
        store.save(&config)?;
        Ok((
            Self { store, config },
            SetupResult { recovery_codes: recovery.codes },
        ))
    }

    /// Authenticate against an existing encrypted configuration. Lockout
    /// state is saved before returning both success and failure outcomes.
    pub fn unlock(
        path: impl Into<std::path::PathBuf>,
        pin: &[u8],
        now_unix: u64,
    ) -> Result<(Self, PinAuthOutcome), SecuritySessionError> {
        let store = EncryptedStore::new(path, DpapiKeyProtector);
        if !store.exists() {
            return Err(SecuritySessionError::NotConfigured);
        }
        let mut config = store.load()?;
        let outcome = authenticate_pin(
            pin,
            &config.pin_verifier,
            &mut config.lockout,
            now_unix,
        )?;
        config.revision = config.revision.saturating_add(1);
        config.updated_at_unix = config.updated_at_unix.max(now_unix);
        store.save(&config)?;
        Ok((Self { store, config }, outcome))
    }

    pub fn config(&self) -> &ConfigDocument {
        &self.config
    }

    /// Persist a complete rule snapshot while preserving all unrelated
    /// settings, credentials, recovery verifiers and lockout state.
    pub fn save_rules(
        &mut self,
        rules: Vec<peacelocker_core::Rule>,
        now_unix: u64,
    ) -> Result<(), SecuritySessionError> {
        let mut next = self.config.clone();
        next.rules = rules;
        next.revision = next.revision.checked_add(1)
            .ok_or(StoreError::InvalidConfiguration)?;
        next.updated_at_unix = next.updated_at_unix.max(now_unix);
        self.store.save(&next)?;
        self.config = next;
        Ok(())
    }
}
