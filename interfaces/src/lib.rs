#![no_std]
#![allow(clippy::too_many_arguments)]
//! # astroid-interfaces
//!
//! Shared interface traits for the Astroid protocol. Each trait is annotated
//! with [`soroban_sdk::contractclient`], which generates a strongly-typed
//! cross-contract client (e.g. `PolicyClient`, `BudgetClient`, `RegistryClient`).
//!
//! - The **caller** side (e.g. the Treasury contract) imports the generated
//!   client to invoke another contract with compile-checked signatures.
//! - The **callee** side (e.g. the Policy contract) implements the trait inside
//!   its `#[contractimpl]` block, which guarantees the on-chain function
//!   signatures match the client exactly.
//!
//! This is how Astroid keeps the dependency graph acyclic — `Registry → others`
//! and `Treasury → {Policy, Budget}` — without any contract crate depending on
//! another contract crate at compile time.

use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::{contractclient, Address, Env, String};

/// Registry lookup surface. The registry is the protocol's source of truth for
/// where each module/contract lives and who owns it (PRD Doc 7 §Registry).
#[contractclient(name = "RegistryClient")]
pub trait RegistryInterface {
    /// Resolve a registered module address by organization + kind.
    fn lookup(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error>;

    /// Verify that `owner` is the recorded owner of `org`.
    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error>;
}

/// Policy verification surface. Contracts call `check_transfer` to have a spend
/// validated against the active, hash-verified policy (PRD Doc 7 §Policy).
#[contractclient(name = "PolicyClient")]
pub trait PolicyInterface {
    /// Returns `Ok(())` if a transfer of `amount` of `asset` to `recipient` is
    /// permitted by the policy identified by `policy_id`, else a policy error.
    fn check_transfer(
        env: Env,
        policy_id: String,
        asset: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error>;
}

/// Budget enforcement surface. Contracts call `consume` to atomically debit a
/// remaining allocation, which reverts with `BudgetExceeded` when insufficient
/// (PRD Doc 7 §Budget).
#[contractclient(name = "BudgetClient")]
pub trait BudgetInterface {
    /// Debit `amount` from the budget's remaining allocation. `caller` must be
    /// the authorized consumer (the treasury/owner). Returns the new remaining.
    fn consume(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error>;

    /// Read the remaining allocation for a budget.
    fn remaining(env: Env, budget_id: String) -> Result<i128, Error>;
}
