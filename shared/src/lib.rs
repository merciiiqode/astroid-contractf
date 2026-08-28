#![no_std]
//! # astroid-shared
//!
//! Common building blocks shared by every Astroid Soroban contract. Keeping
//! these in one crate guarantees deterministic error codes, a single event
//! schema and identical, overflow-safe math across the whole protocol.
//!
//! Modules:
//! - [`errors`]     — the canonical `#[contracterror]` code table.
//! - [`events`]     — helpers that publish the standardized cross-cutting events
//!   the Astroid backend subscribes to.
//! - [`types`]      — `#[contracttype]` values reused by multiple contracts.
//! - [`math`]       — checked `i128` arithmetic (never wraps, returns errors).
//! - [`validation`] — small guard helpers (positive amounts, time windows, ...).
//! - [`constants`]  — protocol-wide constants (time units, storage TTLs, limits).

pub mod constants;
pub mod errors;
pub mod events;
pub mod math;
pub mod types;
pub mod validation;

pub use errors::Error;

#[cfg(test)]
mod test;
