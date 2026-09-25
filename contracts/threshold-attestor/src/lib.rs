//! VELA threshold attestor: an M-of-N multisig smart-account contract
//! (C-address) acting as the attestor for the on-chain AttestationRegistry.
//!
//! ## Problem Addressed (M5 in docs/security-audit.md)
//!
//! In the initial testnet deployment, the AttestationRegistry held a single
//! Ed25519 G-address as its attestor. A single compromised server or hot key
//! could forge provenance for arbitrary contracts or rotate the attestor.
//!
//! Making the attestor a Soroban smart account (C-address) means the account's
//! own `__check_auth` enforces M-of-N threshold signatures on-chain before
//! `attestation-registry` executes `upsert`, `revoke`, or `set_attestor`.
//!
//! ## Fast-path Revocation vs Attestation Threshold
//!
//! Revocation must remain fast so that an upgraded, broken, or compromised
//! contract can be removed without awaiting a full consensus of disparate
//! signers. The contract supports a dedicated `revoke_threshold` (defaulting to
//! `threshold` if unspecified), allowing faster emergency revocation when
//! configured, while strictly enforcing M-of-N on all writes.
//!
//! ## Anti-Replay & Distinct Signers
//!
//! - Signatures must refer to strictly increasing `signer_index` values,
//!   preventing duplicate signatures from the same key.
//! - Validates that the number of distinct valid signatures is at least the
//!   required threshold.
//! - Instance storage TTL is renewed on initialization, auth check, and rotation.

#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, symbol_short, Bytes, BytesN, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ThresholdError {
    /// Instance uninitialized.
    NotInitialized = 1,
    /// Threshold must be at least 1 and <= number of signers.
    InvalidThreshold = 2,
    /// Signers list must not be empty and cannot exceed 32.
    InvalidSigners = 3,
    /// Insufficient valid signatures provided to meet threshold.
    InsufficientSignatures = 4,
    /// Signer index is out of bounds or not strictly ascending.
    InvalidSignerIndex = 5,
    /// Duplicate signer key provided in constructor or update.
    DuplicateSigner = 6,
}

/// Instance TTL renewal parameters: renew to ~30 days when below ~1 week.
const RENEW_THRESHOLD: u32 = 60 * 60 * 24 / 5 * 7;
const RENEW_TO: u32 = 60 * 60 * 24 / 5 * 30;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageKey {
    Threshold,
    RevokeThreshold,
    Signers,
}

/// A single Ed25519 signature from one of the configured signers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerSignature {
    /// Zero-based index into the configured `signers` list.
    pub signer_index: u32,
    /// 64-byte Ed25519 signature over the 32-byte authorization hash payload.
    pub signature: BytesN<64>,
}

/// The threshold signature payload passed in the transaction authorization entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdSignatures {
    pub signatures: Vec<SignerSignature>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    /// Deploy-time constructor. Configures the required threshold, public keys,
    /// and optional separate revocation threshold.
    pub fn __constructor(
        env: Env,
        threshold: u32,
        signers: Vec<BytesN<32>>,
        revoke_threshold: Option<u32>,
    ) {
        validate_and_store_config(&env, threshold, signers, revoke_threshold);
        renew_instance(&env);
    }

    /// The threshold required for general operations (e.g. upsert, set_attestor).
    pub fn threshold(env: Env) -> u32 {
        load_threshold(&env)
    }

    /// The threshold required for revocation operations.
    pub fn revoke_threshold(env: Env) -> u32 {
        load_revoke_threshold(&env)
    }

    /// The configured list of signer Ed25519 public keys.
    pub fn signers(env: Env) -> Vec<BytesN<32>> {
        load_signers(&env)
    }

    /// Number of configured signers.
    pub fn signer_count(env: Env) -> u32 {
        load_signers(&env).len()
    }

    /// Rotates the threshold and signers list. Requires threshold authorization
    /// from this contract itself (i.e. signed by current threshold).
    pub fn set_signers(
        env: Env,
        new_threshold: u32,
        new_signers: Vec<BytesN<32>>,
        new_revoke_threshold: Option<u32>,
    ) {
        env.current_contract_address().require_auth();
        validate_and_store_config(&env, new_threshold, new_signers, new_revoke_threshold);
        renew_instance(&env);

        env.events().publish((symbol_short!("rotate"),), new_threshold);
    }
}

#[contractimpl]
impl CustomAccountInterface for Contract {
    type Signature = ThresholdSignatures;
    type Error = ThresholdError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Self::Signature,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        let is_revoke = is_all_revoke(&auth_contexts);
        let required_threshold = if is_revoke {
            load_revoke_threshold(&env)
        } else {
            load_threshold(&env)
        };

        if signatures.signatures.len() < required_threshold {
            return Err(ThresholdError::InsufficientSignatures);
        }

        let signers = load_signers(&env);
        let num_signers = signers.len();
        let payload_bytes = Bytes::from_array(&env, &signature_payload.to_array());

        let mut last_index: Option<u32> = None;
        let mut valid_count: u32 = 0;

        for sig in signatures.signatures.iter() {
            // Ensure strictly ascending indices to prevent duplicate signers
            if let Some(prev) = last_index {
                if sig.signer_index <= prev {
                    return Err(ThresholdError::InvalidSignerIndex);
                }
            }
            if sig.signer_index >= num_signers {
                return Err(ThresholdError::InvalidSignerIndex);
            }
            last_index = Some(sig.signer_index);

            let pk = signers.get(sig.signer_index).unwrap();
            // ed25519_verify verifies or panics if invalid
            env.crypto().ed25519_verify(&pk, &payload_bytes, &sig.signature);
            valid_count += 1;
        }

        if valid_count < required_threshold {
            return Err(ThresholdError::InsufficientSignatures);
        }

        renew_instance(&env);
        Ok(())
    }
}

fn validate_and_store_config(
    env: &Env,
    threshold: u32,
    signers: Vec<BytesN<32>>,
    revoke_threshold: Option<u32>,
) {
    let n = signers.len();
    if n == 0 || n > 32 {
        panic_with_error!(env, ThresholdError::InvalidSigners);
    }
    if threshold == 0 || threshold > n {
        panic_with_error!(env, ThresholdError::InvalidThreshold);
    }

    // Verify all signer public keys are distinct
    for i in 0..n {
        let s_i = signers.get(i).unwrap();
        for j in (i + 1)..n {
            if s_i == signers.get(j).unwrap() {
                panic_with_error!(env, ThresholdError::DuplicateSigner);
            }
        }
    }

    let r_thresh = match revoke_threshold {
        Some(r) => {
            if r == 0 || r > n {
                panic_with_error!(env, ThresholdError::InvalidThreshold);
            }
            r
        }
        None => threshold,
    };

    env.storage().instance().set(&StorageKey::Threshold, &threshold);
    env.storage().instance().set(&StorageKey::RevokeThreshold, &r_thresh);
    env.storage().instance().set(&StorageKey::Signers, &signers);
}

fn is_all_revoke(auth_contexts: &Vec<Context>) -> bool {
    if auth_contexts.is_empty() {
        return false;
    }
    for context in auth_contexts.iter() {
        match context {
            Context::Contract(contract_ctx) => {
                if contract_ctx.fn_name != symbol_short!("revoke") {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn load_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get::<StorageKey, u32>(&StorageKey::Threshold)
        .unwrap_or_else(|| panic_with_error!(env, ThresholdError::NotInitialized))
}

fn load_revoke_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get::<StorageKey, u32>(&StorageKey::RevokeThreshold)
        .unwrap_or_else(|| panic_with_error!(env, ThresholdError::NotInitialized))
}

fn load_signers(env: &Env) -> Vec<BytesN<32>> {
    env.storage()
        .instance()
        .get::<StorageKey, Vec<BytesN<32>>>(&StorageKey::Signers)
        .unwrap_or_else(|| panic_with_error!(env, ThresholdError::NotInitialized))
}

fn renew_instance(env: &Env) {
    env.storage().instance().extend_ttl(RENEW_THRESHOLD, RENEW_TO);
}

#[cfg(test)]
mod test;
