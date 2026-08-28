#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid MultiSig Contract
//!
//! Prevents unilateral spending by requiring **N of M** signer approvals before
//! an action executes (PRD Doc 7 §MultiSig). The contract owns a dynamic signer
//! set and a threshold, and manages internal proposals through an
//! approve → execute flow with an optional per-proposal time lock and a global
//! emergency lock.
//!
//! Governance actions (`add_signer`, `remove_signer`, `set_threshold`,
//! `set_emergency_lock`) are themselves gated: they require the caller to be a
//! current signer and are authorized directly. In production these would
//! typically be routed through the proposal flow too; they are exposed directly
//! here for the platform's administrative bootstrap and kept signer-gated.
//!
//! Events: `SignerAdded`, `SignerRemoved`, `ThresholdChanged`,
//! `ProposalApproved`, `ProposalExecuted`, `EmergencyLock`.
//!
//! Execution below threshold is rejected with [`Error::ThresholdNotMet`].

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_SIGNERS, MIN_THRESHOLD,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::validation::require_time_reached;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Bytes, Env, Symbol, Vec,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Config: current signer set (instance).
    Signers,
    /// Config: current approval threshold (instance).
    Threshold,
    /// State: global emergency lock flag (instance).
    EmergencyLock,
    /// State: monotonic proposal id counter (instance).
    ProposalCount,
    /// State: proposal record by id (persistent).
    Proposal(u64),
    /// Relationship: whether a signer approved a proposal (persistent).
    Approval(u64, Address),
}

/// Internal multisig proposal. `action`/`payload` describe the intended change
/// or call; the multisig only records approvals and marks it executed once the
/// threshold is met. Actual value movement is delegated to the calling context
/// (e.g. the Treasury) which checks `is_executed`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsProposal {
    pub proposer: Address,
    /// A short action tag, e.g. `payment`, `config`.
    pub action: Symbol,
    /// Opaque payload (e.g. serialized transfer intent / hash).
    pub payload: Bytes,
    pub approvals: u32,
    pub executed: bool,
    /// Earliest timestamp at which execution is allowed (time lock; 0 = none).
    pub unlock_at: u64,
}

#[contract]
pub struct MultiSigContract;

#[contractimpl]
impl MultiSigContract {
    /// Initialize with an initial signer set and threshold. `threshold` must be
    /// within `[MIN_THRESHOLD, signers.len()]` and signers within `MAX_SIGNERS`.
    pub fn initialize(env: Env, signers: Vec<Address>, threshold: u32) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        Self::validate_threshold(threshold, n)?;
        Self::assert_unique(&signers)?;

        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &false);
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Add a signer. Signer-gated. Rejects duplicates and over-capacity sets.
    pub fn add_signer(env: Env, caller: Address, signer: Address) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let mut signers = Self::signers(&env)?;
        if signers.contains(&signer) {
            return Err(Error::AlreadyExists);
        }
        if signers.len() >= MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        signers.push_back(signer.clone());
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("added")), signer);
        Ok(())
    }

    /// Remove a signer. Signer-gated. Refuses to drop below the threshold or to
    /// empty the set, so the multisig can never become unusable.
    pub fn remove_signer(env: Env, caller: Address, signer: Address) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let mut signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        let idx = signers.first_index_of(&signer).ok_or(Error::NotASigner)?;
        if signers.len() - 1 < threshold {
            return Err(Error::InvalidThreshold);
        }
        signers.remove(idx);
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("removed")), signer);
        Ok(())
    }

    /// Update the approval threshold. Signer-gated. Must stay within
    /// `[MIN_THRESHOLD, signers.len()]`.
    pub fn set_threshold(env: Env, caller: Address, threshold: u32) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let signers = Self::signers(&env)?;
        Self::validate_threshold(threshold, signers.len())?;
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("changed")),
            threshold,
        );
        Ok(())
    }

    /// Toggle the global emergency lock (signer-gated). While locked, proposals
    /// cannot be created, approved or executed.
    pub fn set_emergency_lock(env: Env, caller: Address, locked: bool) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &locked);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("emergency"), symbol_short!("lock")), locked);
        Ok(())
    }

    /// Create a proposal. Only a signer may propose. `unlock_at` sets an optional
    /// time lock (0 = immediately executable once threshold met). The proposer's
    /// approval is counted automatically.
    pub fn propose(
        env: Env,
        proposer: Address,
        action: Symbol,
        payload: Bytes,
        unlock_at: u64,
    ) -> Result<u64, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &proposer)?;

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let proposal = MsProposal {
            proposer: proposer.clone(),
            action,
            payload,
            approvals: 1,
            executed: false,
            unlock_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::Approval(id, proposer.clone()), &true);
        Self::bump_proposal(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        Self::bump_instance(&env);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Approve a proposal. Only signers may approve, once each. Emits
    /// `ProposalApproved` with the running approval count.
    pub fn approve(env: Env, caller: Address, proposal_id: u64) -> Result<u32, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let akey = DataKey::Approval(proposal_id, caller.clone());
        if env.storage().persistent().get(&akey).unwrap_or(false) {
            return Err(Error::AlreadySigned);
        }
        env.storage().persistent().set(&akey, &true);
        proposal.approvals = checked_add(proposal.approvals as i128, 1)? as u32;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (proposal_id, caller, proposal.approvals),
        );
        Ok(proposal.approvals)
    }

    /// Execute a proposal once it has reached threshold and any time lock has
    /// elapsed. Marks it executed and emits `ProposalExecuted`. Rejects with
    /// [`Error::ThresholdNotMet`] when approvals are insufficient.
    pub fn execute(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let threshold = Self::threshold(&env)?;
        if proposal.approvals < threshold {
            return Err(Error::ThresholdNotMet);
        }
        if proposal.unlock_at != 0 {
            require_time_reached(&env, proposal.unlock_at)?;
        }
        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("executed")),
            proposal_id,
        );
        Ok(())
    }

    // --- views ---

    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<MsProposal, Error> {
        Self::load_proposal(&env, proposal_id)
    }

    pub fn get_signers(env: Env) -> Result<Vec<Address>, Error> {
        Self::signers(&env)
    }

    pub fn get_threshold(env: Env) -> Result<u32, Error> {
        Self::threshold(&env)
    }

    pub fn is_signer(env: Env, who: Address) -> bool {
        Self::signers(&env)
            .map(|s| s.contains(&who))
            .unwrap_or(false)
    }

    pub fn is_locked(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false)
    }

    // --- internal helpers ---

    fn signers(env: &Env) -> Result<Vec<Address>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)
    }

    fn threshold(env: &Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)
    }

    fn load_proposal(env: &Env, id: u64) -> Result<MsProposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::NotFound)
    }

    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.contains(caller) {
            return Err(Error::NotASigner);
        }
        Ok(())
    }

    fn require_not_locked(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false);
        if locked {
            return Err(Error::EmergencyLock);
        }
        Ok(())
    }

    fn validate_threshold(threshold: u32, n: u32) -> Result<(), Error> {
        if threshold < MIN_THRESHOLD || threshold > n {
            return Err(Error::InvalidThreshold);
        }
        Ok(())
    }

    fn assert_unique(signers: &Vec<Address>) -> Result<(), Error> {
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let a = signers.get(i).unwrap();
            let mut j = i + 1;
            while j < len {
                if a == signers.get(j).unwrap() {
                    return Err(Error::InvalidInput);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    fn bump_proposal(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Proposal(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod test;
