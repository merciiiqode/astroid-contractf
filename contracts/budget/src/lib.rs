#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Budget Contract
//!
//! Enforces spending limits (PRD Doc 7 §Budget). Every spend calls
//! [`BudgetContract::consume`], which debits the remaining allocation and
//! reverts with [`Error::BudgetExceeded`] when a spend would push spending past
//! the limit. Budgets support periodic auto-reset windows (daily / monthly),
//! freezing, archiving and moving allocation between two budgets.
//!
//! Budgets are keyed by a backend-owned string id and are scoped to an owner
//! address (the treasury or organization owner) which authorizes consumption
//! and administration. Budgets implement the shared [`BudgetInterface`] so other
//! contracts (e.g. Treasury) can debit them through a typed client.
//!
//! Functions: `allocate`, `consume`, `reset`, `freeze`, `unfreeze`, `archive`,
//! `transfer_allocation`.

use astroid_interfaces::BudgetInterface;
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::{
    require_non_empty, require_non_negative_amount, require_positive_amount,
};
use astroid_shared::{constants, events};
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String};

/// Reset period for a recurring budget. `None` means one-shot (no auto-reset).
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Period {
    None = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3,
}

/// Stored budget record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub owner: Address,
    pub limit: i128,
    pub spent: i128,
    pub period: Period,
    /// Start of the current window (unix seconds). Used for auto-reset.
    pub window_start: u64,
    pub state: ResourceState,
}

/// Per-asset budget tracking.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetBudget {
    pub limit: i128,
    pub spent: i128,
    pub window_start: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Budget(String),
    AssetBudget(String, Address),
}

#[contract]
pub struct BudgetContract;

#[contractimpl]
impl BudgetContract {
    /// Initialize with an admin (used only for protocol-level bookkeeping; all
    /// budget operations are owner-gated).
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Allocate (create) a budget with a spending `limit` and optional reset
    /// `period`. `owner` authorizes and becomes the budget's controller.
    pub fn allocate(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&budget_id)?;
        require_non_negative_amount(limit)?;
        let key = DataKey::Budget(budget_id.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        let budget = Budget {
            owner: owner.clone(),
            limit,
            spent: 0,
            period,
            window_start: env.ledger().timestamp(),
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&key, &budget);
        Self::bump(&env, &budget_id);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("allocated")),
            (budget_id, owner, limit),
        );
        Ok(())
    }

    /// Reset the spent counter to zero (owner-gated). Also refreshes the window.
    pub fn reset(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        budget.spent = 0;
        budget.window_start = env.ledger().timestamp();
        Self::store(&env, &budget_id, &budget);
        env.events()
            .publish((symbol_short!("budget"), symbol_short!("reset")), budget_id);
        Ok(())
    }

    /// Change a budget's limit (owner-gated). New limit must be >= amount spent
    /// in the current window.
    pub fn set_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        new_limit: i128,
    ) -> Result<(), Error> {
        require_non_negative_amount(new_limit)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::apply_auto_reset(&env, &mut budget);
        if new_limit < budget.spent {
            return Err(Error::InvalidInput);
        }
        budget.limit = new_limit;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("setlimit")),
            (budget_id, new_limit),
        );
        Ok(())
    }

    /// Freeze a budget (owner-gated). Frozen budgets reject consumption.
    pub fn freeze(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        if budget.state == ResourceState::Archived {
            return Err(Error::BudgetArchived);
        }
        budget.state = ResourceState::Frozen;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("frozen")),
            budget_id,
        );
        Ok(())
    }

    /// Unfreeze a budget back to active (owner-gated).
    pub fn unfreeze(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        if budget.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }
        budget.state = ResourceState::Active;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("unfrozen")),
            budget_id,
        );
        Ok(())
    }

    /// Archive a budget (owner-gated, terminal). Rejects further consumption.
    pub fn archive(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        budget.state = ResourceState::Archived;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("archived")),
            budget_id,
        );
        Ok(())
    }

    /// Move unused allocation from one budget to another. Both must share the
    /// same owner, who authorizes. Reduces `from`'s limit and increases `to`'s.
    pub fn transfer_allocation(
        env: Env,
        caller: Address,
        from_id: String,
        to_id: String,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        if from_id == to_id {
            return Err(Error::InvalidInput);
        }
        let mut from = Self::require_owner(&env, &from_id, &caller)?;
        // `to` must exist and share the owner; caller already authorized above.
        let mut to = Self::load(&env, &to_id)?;
        if to.owner != caller {
            return Err(Error::Unauthorized);
        }
        Self::require_active(&from)?;
        Self::require_active(&to)?;
        // Only the unspent portion of `from` may be reallocated.
        let available = checked_sub(from.limit, from.spent)?;
        if amount > available {
            return Err(Error::BudgetExceeded);
        }
        from.limit = checked_sub(from.limit, amount)?;
        to.limit = checked_add(to.limit, amount)?;
        Self::store(&env, &from_id, &from);
        Self::store(&env, &to_id, &to);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("realloc")),
            (from_id, to_id, amount),
        );
        Ok(())
    }

    /// Set budget limit for a specific token (owner-gated).
    pub fn set_budget_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        limit: i128,
        _window_seconds: u64,
    ) -> Result<(), Error> {
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        require_non_negative_amount(limit)?;

        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let asset_budget = AssetBudget {
            limit,
            spent: 0,
            window_start: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("set_ast")),
            (budget_id, token, limit),
        );
        Ok(())
    }

    /// Check and record spend for a specific token.
    pub fn check_and_record_spend(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;

        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let mut asset_budget: AssetBudget = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::AssetNotAuthorized)?;

        // Check if within limit
        let new_spent = checked_add(asset_budget.spent, amount)?;
        if new_spent > asset_budget.limit {
            return Err(Error::BudgetExceeded);
        }

        asset_budget.spent = new_spent;
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("ast_spend")),
            (budget_id, token, amount),
        );
        Ok(())
    }

    // --- views ---

    pub fn get(env: Env, budget_id: String) -> Result<Budget, Error> {
        Self::load(&env, &budget_id)
    }

    // --- internal helpers ---

    fn load(env: &Env, id: &String) -> Result<Budget, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Budget(id.clone()))
            .ok_or(Error::NotFound)
    }

    fn store(env: &Env, id: &String, budget: &Budget) {
        env.storage()
            .persistent()
            .set(&DataKey::Budget(id.clone()), budget);
        Self::bump(env, id);
    }

    fn require_owner(env: &Env, id: &String, caller: &Address) -> Result<Budget, Error> {
        caller.require_auth();
        let budget = Self::load(env, id)?;
        if &budget.owner != caller {
            return Err(Error::Unauthorized);
        }
        Ok(budget)
    }

    fn require_active(budget: &Budget) -> Result<(), Error> {
        match budget.state {
            ResourceState::Active => Ok(()),
            ResourceState::Frozen | ResourceState::Paused => Err(Error::BudgetFrozen),
            ResourceState::Archived => Err(Error::BudgetArchived),
        }
    }

    /// Auto-reset the spent counter when the current window has elapsed for a
    /// recurring budget. Mutates in place; caller persists.
    fn apply_auto_reset(env: &Env, budget: &mut Budget) {
        let window = match budget.period {
            Period::None => return,
            Period::Daily => constants::SECONDS_PER_DAY,
            Period::Weekly => constants::SECONDS_PER_WEEK,
            Period::Monthly => constants::SECONDS_PER_MONTH,
        };
        let now = env.ledger().timestamp();
        if now >= budget.window_start.saturating_add(window) {
            budget.spent = 0;
            // Snap the window start to the current time.
            budget.window_start = now;
        }
    }

    fn bump(env: &Env, id: &String) {
        env.storage().persistent().extend_ttl(
            &DataKey::Budget(id.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_asset(env: &Env, budget_id: &String, token: &Address) {
        env.storage().persistent().extend_ttl(
            &DataKey::AssetBudget(budget_id.clone(), token.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared interface implementation used by other contracts (e.g. Treasury).
// ---------------------------------------------------------------------------
#[contractimpl]
impl BudgetInterface for BudgetContract {
    /// Debit `amount` from the budget. Applies any pending auto-reset first,
    /// then enforces `spent + amount <= limit`, else [`Error::BudgetExceeded`].
    fn consume(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::apply_auto_reset(&env, &mut budget);

        let new_spent = checked_add(budget.spent, amount)?;
        if new_spent > budget.limit {
            let remaining = checked_sub(budget.limit, budget.spent)?;
            events::budget_exceeded(&env, &budget_id, amount, remaining);
            return Err(Error::BudgetExceeded);
        }
        budget.spent = new_spent;
        Self::store(&env, &budget_id, &budget);
        let remaining = checked_sub(budget.limit, budget.spent)?;
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("consumed")),
            (budget_id, amount, remaining),
        );
        Ok(remaining)
    }

    /// Read remaining allocation, accounting for a pending auto-reset window.
    fn remaining(env: Env, budget_id: String) -> Result<i128, Error> {
        let mut budget = Self::load(&env, &budget_id)?;
        Self::apply_auto_reset(&env, &mut budget);
        checked_sub(budget.limit, budget.spent)
    }
}

#[cfg(test)]
mod test;
