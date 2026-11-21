//! Persistable PIN authentication and failed-attempt lockout policy.

use crate::{PinError, verify_pin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_FAILED_ATTEMPTS: u8 = 3;
pub const LOCKOUT_SECONDS: u64 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LockoutState {
    failed_attempts: u8,
    lockout_until_unix: Option<u64>,
    last_observed_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAuthOutcome {
    Authenticated,
    Rejected { attempts_remaining: u8 },
    LockedOut { until_unix: u64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("the stored PIN verifier is invalid")]
    InvalidVerifier,
    #[error("PIN input has an invalid length")]
    InvalidPin,
}

impl LockoutState {
    pub fn failed_attempts(&self) -> u8 { self.failed_attempts }
    pub fn lockout_until_unix(&self) -> Option<u64> { self.lockout_until_unix }
    pub fn is_locked_at(&self, now_unix: u64) -> bool {
        self.lockout_until_unix.is_some_and(|until| now_unix < until)
    }
    pub fn validate(&self) -> bool {
        self.failed_attempts < MAX_FAILED_ATTEMPTS
            && (self.lockout_until_unix.is_none() || self.failed_attempts == 0)
    }
}

/// Verify a PIN and update lockout state. The caller must persist updated
/// state in the encrypted store before presenting the outcome as durable.
pub fn authenticate_pin(
    pin: &[u8],
    verifier: &str,
    state: &mut LockoutState,
    now_unix: u64,
) -> Result<PinAuthOutcome, AuthError> {
    if !state.validate() { return Err(AuthError::InvalidVerifier); }
    if let Some(last_seen) = state.last_observed_unix {
        if now_unix < last_seen {
            let deadline = state.lockout_until_unix.unwrap_or(0)
                .max(last_seen.saturating_add(LOCKOUT_SECONDS));
            state.lockout_until_unix = Some(deadline);
            state.failed_attempts = 0;
            state.last_observed_unix = Some(last_seen);
            return Ok(PinAuthOutcome::LockedOut { until_unix: deadline });
        }
    }
    state.last_observed_unix = Some(now_unix);
    if let Some(until) = state.lockout_until_unix {
        if now_unix < until {
            return Ok(PinAuthOutcome::LockedOut { until_unix: until });
        }
        state.lockout_until_unix = None;
        state.failed_attempts = 0;
    }
    match verify_pin(pin, verifier) {
        Ok(()) => {
            state.failed_attempts = 0;
            Ok(PinAuthOutcome::Authenticated)
        }
        Err(PinError::Mismatch) => {
            state.failed_attempts = state.failed_attempts.saturating_add(1);
            if state.failed_attempts >= MAX_FAILED_ATTEMPTS {
                let until = now_unix.saturating_add(LOCKOUT_SECONDS);
                state.failed_attempts = 0;
                state.lockout_until_unix = Some(until);
                Ok(PinAuthOutcome::LockedOut { until_unix: until })
            } else {
                Ok(PinAuthOutcome::Rejected {
                    attempts_remaining: MAX_FAILED_ATTEMPTS - state.failed_attempts,
                })
            }
        }
        Err(PinError::InvalidPinLength) => Err(AuthError::InvalidPin),
        Err(_) => Err(AuthError::InvalidVerifier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_pin;

    #[test]
    fn three_failures_trigger_six_hour_lockout() {
        let verifier = hash_pin(b"correct-pin").expect("hashing works");
        let mut state = LockoutState::default();
        assert_eq!(authenticate_pin(b"wrong", &verifier, &mut state, 1_000).unwrap(),
            PinAuthOutcome::Rejected { attempts_remaining: 2 });
        assert_eq!(authenticate_pin(b"wrong", &verifier, &mut state, 1_001).unwrap(),
            PinAuthOutcome::Rejected { attempts_remaining: 1 });
        assert_eq!(authenticate_pin(b"wrong", &verifier, &mut state, 1_002).unwrap(),
            PinAuthOutcome::LockedOut { until_unix: 1_002 + LOCKOUT_SECONDS });
        assert_eq!(authenticate_pin(b"correct-pin", &verifier, &mut state, 1_003).unwrap(),
            PinAuthOutcome::LockedOut { until_unix: 1_002 + LOCKOUT_SECONDS });
    }

    #[test]
    fn successful_authentication_resets_failures() {
        let verifier = hash_pin(b"correct-pin").expect("hashing works");
        let mut state = LockoutState::default();
        authenticate_pin(b"wrong", &verifier, &mut state, 100).unwrap();
        assert_eq!(authenticate_pin(b"correct-pin", &verifier, &mut state, 101).unwrap(),
            PinAuthOutcome::Authenticated);
        assert_eq!(state.failed_attempts(), 0);
    }

    #[test]
    fn clock_rollback_fails_closed() {
        let verifier = hash_pin(b"correct-pin").expect("hashing works");
        let mut state = LockoutState::default();
        assert_eq!(authenticate_pin(b"correct-pin", &verifier, &mut state, 10_000).unwrap(),
            PinAuthOutcome::Authenticated);
        assert_eq!(authenticate_pin(b"correct-pin", &verifier, &mut state, 9_999).unwrap(),
            PinAuthOutcome::LockedOut { until_unix: 10_000 + LOCKOUT_SECONDS });
    }

    #[test]
    fn expired_lockout_resets_attempt_counter() {
        let verifier = hash_pin(b"correct-pin").expect("hashing works");
        let mut state = LockoutState::default();
        authenticate_pin(b"wrong", &verifier, &mut state, 1).unwrap();
        authenticate_pin(b"wrong", &verifier, &mut state, 2).unwrap();
        authenticate_pin(b"wrong", &verifier, &mut state, 3).unwrap();
        assert_eq!(authenticate_pin(b"correct-pin", &verifier, &mut state, 3 + LOCKOUT_SECONDS).unwrap(),
            PinAuthOutcome::Authenticated);
    }
}
