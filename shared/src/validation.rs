//! Small, reusable validation guards.
//!
//! Each returns `Ok(())` when the invariant holds and a specific contract
//! [`Error`] otherwise, so callers can `?`-propagate. Keeping these here means
//! every contract validates inputs identically.

use crate::errors::Error;
use soroban_sdk::{Env, String};

/// Require a strictly positive amount (typical for transfers / deposits).
pub fn require_positive_amount(amount: i128) -> Result<(), Error> {
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    Ok(())
}

/// Require a non-negative amount (allows zero, e.g. a zero-limit budget).
pub fn require_non_negative_amount(amount: i128) -> Result<(), Error> {
    if amount < 0 {
        return Err(Error::InvalidAmount);
    }
    Ok(())
}

/// Require a non-empty string (names, ids, org slugs).
pub fn require_non_empty(value: &String) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Require that `expiry` (a unix timestamp in seconds) is still in the future
/// relative to the current ledger time.
pub fn require_not_expired(env: &Env, expiry: u64) -> Result<(), Error> {
    if env.ledger().timestamp() >= expiry {
        return Err(Error::ProposalExpired);
    }
    Ok(())
}

/// Require that the current ledger time has reached `unlock_at` (time locks).
pub fn require_time_reached(env: &Env, unlock_at: u64) -> Result<(), Error> {
    if env.ledger().timestamp() < unlock_at {
        return Err(Error::TimeLocked);
    }
    Ok(())
}

/// Require that `value` falls within an inclusive `[min, max]` window. Passing
/// `max == 0` is treated as "no upper bound".
pub fn require_within_amount_bounds(value: i128, min: i128, max: i128) -> Result<(), Error> {
    if value < min {
        return Err(Error::PolicyDenied);
    }
    if max != 0 && value > max {
        return Err(Error::PolicyDenied);
    }
    Ok(())
}
