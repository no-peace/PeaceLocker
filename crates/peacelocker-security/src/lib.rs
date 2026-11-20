//! Authentication, authenticated encryption, and secret-key handling.
//!
//! This crate deliberately has no plaintext fallback. Windows DPAPI integration
//! lives in the platform crate; portable cryptographic primitives live here.

mod encryption;
mod pin;
mod recovery;
mod secret;

pub use encryption::{EncryptedEnvelope, decrypt, encrypt};
pub use pin::{PinError, hash_pin, verify_pin};
pub use recovery::{RecoveryCodeBundle, RecoveryCodeError, RecoveryCodeSet, generate_recovery_codes};
pub use secret::{DataKey, SecretError};
