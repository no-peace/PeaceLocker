//! Authentication, authenticated encryption, and secret-key handling.
//!
//! This crate deliberately has no plaintext fallback. Windows DPAPI integration
//! lives in the platform crate; portable cryptographic primitives live here.

mod auth;
mod encryption;
mod pin;
mod recovery;
mod secret;

pub use auth::{AuthError, LockoutState, PinAuthOutcome, authenticate_pin};
pub use encryption::{EncryptedEnvelope, decrypt, decrypt_with_aad, encrypt, encrypt_with_aad};
pub use pin::{PinError, hash_pin, validate_pin_verifier, verify_pin};
pub use recovery::{RecoveryCodeBundle, RecoveryCodeError, RecoveryCodeSet, generate_recovery_codes};
pub use secret::{DataKey, SecretError};
