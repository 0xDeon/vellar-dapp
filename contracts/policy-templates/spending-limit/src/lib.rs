//! VELA configurable spending-limit policy: a CUMULATIVE rolling-window
//! allowance whose cap and window are set PER INSTANCE at deploy time, plus
//! optional on-chain SAFETY RULES over the transfer patterns it recognizes.
//!
//! This is a hardened, configurable derivative of the passkey-kit
//! `sample-policy` reference. It preserves every security invariant of that
//! reference and changes exactly one thing: the two compile-time constants
//! (`WINDOW_ALLOWANCE`, `WINDOW_SECONDS`) become immutable per-instance
//! configuration supplied to `__constructor`, so a user can choose their own
//! spending limit from the VELA policy builder and deploy an instance that
//! enforces THAT number.
//!
//! ## Safety rules (on-chain spending controls for KNOWN transfer patterns)
//!
//! Beyond the cumulative allowance, an instance carries an immutable
//! [`SafetyRules`] set, evaluated inside `policy__` (i.e. inside the wallet's
//! `__check_auth`) so a violating transfer is REJECTED on-chain rather than
//! warned about in a UI:
//!
//! - **Per-token maximum single transfer** — `max_single_transfer` maps a
//!   token contract to the largest amount (in THAT token's base units) any one
//!   `transfer` context may move. Denominated per token because there is no
//!   price oracle on Soroban: a cap is meaningful only in the units of the
//!   token it applies to. Never USD.
//! - **Token allowlist** — `allowed_tokens`, when set, restricts which SEP-41
//!   token contracts this policy will authorize transfers of. `None` keeps the
//!   original "any SEP-41 transfer" behavior.
//!
//! Both rule tables are BOUNDED ([`MAX_RULE_ENTRIES`]) and the number of auth
//! contexts evaluated per call is BOUNDED ([`MAX_CONTEXTS`]), so the work done
//! in `__check_auth` is predictable — this matters because x402 facilitators
//! re-simulate payments, executing this code repeatedly.
//!
//! **Scope, stated honestly:** the rules understand exactly one transfer
//! pattern — a SEP-41 `transfer(from, to, amount)` where `from` is the bound
//! wallet — and deny everything else. They are spending controls for that
//! known pattern, not a universal transaction firewall: a contract call that
//! moves value through some other path is simply not authorized by this policy
//! at all (deny-by-default), and value the wallet moves through OTHER signers
//! is outside this policy's view.
//!
//! ## Why the limit is a cumulative window, not a per-transfer cap
//!
//! `Signature::Policy` carries NO secret — anyone can submit it, so a policy
//! authorizing value transfers authorizes them for EVERYONE. A per-transfer
//! cap is therefore NOT a spending limit: repeated capped transfers can move
//! the wallet's full balance (smart-wallet-interface PolicyInterface docs).
//! So the user's "daily limit" is enforced as a CUMULATIVE total over a
//! FIXED (tumbling) window, NOT a continuously sliding one: `spent` accumulates
//! from the first spend of a window and resets to zero once `window_seconds`
//! have elapsed since that `window_start` (see `policy__`). Because the reset is
//! on a fixed schedule rather than sliding, spending near a boundary can move up
//! to `2 * daily_limit` within a short span — the full cap just before the reset
//! plus the full cap just after. The bound is therefore `daily_limit` per FIXED
//! window and AT MOST `2 * daily_limit` across any boundary. This is intentional
//! and TESTED (see `test.rs` boundary test): treat this as a spending guardrail,
//! not a hard cap. For a hard guarantee, pair it — via the granting signer's
//! `SignerLimits` — with an authenticated cryptographic co-signer. The
//! `max_single_transfer` rule is a per-context ceiling ON TOP of the cumulative
//! window, never a replacement for it.
//!
//! ## Explicit `auth_contexts` parsing
//!
//! Every context is parsed field by field: it must be a contract invocation,
//! must not target the wallet's own admin surface, must be `transfer`, must
//! carry exactly `(from: Address, to: Address, amount: i128)`, and `from` MUST
//! be the bound wallet. A context whose `from` is any other address is a
//! mismatched authorization context and is rejected — the policy never
//! rubber-stamps a shape it does not fully understand.
//!
//! ## Re-simulation safety
//!
//! `policy__` is deterministic in (ledger timestamp, stored allowance,
//! contexts). Simulation runs it against a read-only snapshot, so repeated
//! dry-runs neither consume budget nor change the verdict; only an applied
//! transaction advances `spent`. `test.rs` pins this with ledger snapshots.
//!
//! ## Immutable configuration (deploy-once)
//!
//! Config is written once in `__constructor` and NEVER mutated afterwards.
//! There is deliberately no setter: if the wallet owner could raise their own
//! cap in-place, the policy would guarantee nothing. Changing a limit or a rule
//! means deploying a fresh instance and re-attaching it with a passkey approval
//! (`kit.updatePolicy`), which is an explicit, auditable admin action.
//!
//! ## Single-tenant binding
//!
//! Each instance is bound at deploy to ONE wallet (`config.wallet`). `install`
//! and `policy__` both reject any wallet other than the bound one, so a
//! deployed instance cannot be attached to, or spent through, a different
//! wallet than the one it was configured for.
//!
//! Preserved sample-policy invariants: caller authentication
//! (`source.require_auth()` before touching per-wallet state), deny-by-default
//! (only positive `transfer`s to a non-wallet contract pass; everything else
//! fails closed), checked arithmetic, TTL renewal on install and every
//! successful check, and permissionless self-clean (`uninstall` clears state
//! only once this policy is genuinely no longer a signer on the wallet).

#![no_std]

use smart_wallet_interface::{types::SignerKey, PolicyInterface, SmartWalletClient};
use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Env, Map, TryFromVal, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyError {
    /// A context is not permitted (deny-by-default), or the cumulative
    /// window allowance would be exceeded.
    NotAllowed = 1,
    /// `policy__` was called for a wallet that never installed this policy.
    NotInstalled = 2,
    /// `uninstall` was called while this policy is still a signer on the
    /// wallet.
    StillInstalled = 3,
    /// Constructor was given an out-of-range configuration value.
    InvalidConfig = 4,
    /// `install`/`policy__` was called by a wallet other than the one this
    /// instance was configured (bound) for at deploy time.
    WrongWallet = 5,
    /// A transfer context targets a token that is not on the instance's
    /// `allowed_tokens` allowlist.
    TokenNotAllowed = 6,
    /// A single transfer context exceeds the per-token `max_single_transfer`
    /// ceiling for its token.
    SingleTransferExceeded = 7,
    /// A transfer context's `from` argument is not the bound wallet: the
    /// authorization context does not match what this policy governs.
    ContextMismatch = 8,
    /// More auth contexts than `MAX_CONTEXTS` were supplied; the policy
    /// refuses unbounded work.
    TooManyContexts = 9,
}

/// Bounds on the configurable window. A non-positive allowance or a zero
/// window would make the policy either useless or a division-free footgun, so
/// both are rejected at construction. The window ceiling (365 days) is a
/// sanity guard — a "rolling window" longer than a year is almost certainly a
/// units mistake (e.g. passing milliseconds).
const MIN_ALLOWANCE: i128 = 1;
const MIN_WINDOW_SECONDS: u64 = 1;
const MAX_WINDOW_SECONDS: u64 = 60 * 60 * 24 * 365;

/// Upper bound on entries in each safety-rule table. Keeps the per-context
/// lookups inside `__check_auth` O(MAX_RULE_ENTRIES) and the instance config
/// small. Eight tokens is far more than any budgeted signer needs.
pub const MAX_RULE_ENTRIES: u32 = 8;

/// Upper bound on auth contexts evaluated per `policy__` call. The smart
/// wallet passes the full context list of one authorization; a legitimate
/// payment has one (occasionally a few) transfer contexts. Anything larger is
/// refused outright so the work here stays bounded under re-simulation.
pub const MAX_CONTEXTS: u32 = 16;

/// TTL renewal parameters (in ledgers at the historical 5s close time): bump
/// to ~30 days whenever remaining TTL drops below ~1 week. Both are well under
/// any real network's `max_ttl`. Identical to the sample-policy reference.
const RENEW_THRESHOLD: u32 = 60 * 60 * 24 / 5 * 7;
const RENEW_TO: u32 = 60 * 60 * 24 / 5 * 30;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageKey {
    /// Immutable per-instance configuration, written once by the constructor.
    Config,
    /// Marker that `wallet` completed `install`.
    Installed(Address),
    /// Per-wallet cumulative-spend accounting for the current window.
    Spend(Address),
}

/// Immutable safety rules over the recognized transfer pattern. Every amount
/// is in the base units of the token it is keyed by — never a fiat value.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyRules {
    /// token contract → largest amount (base units) a SINGLE transfer of that
    /// token may move. Tokens absent from the map have no per-transfer
    /// ceiling (the cumulative window still applies). At most
    /// `MAX_RULE_ENTRIES` entries; every cap must be >= 1.
    pub max_single_transfer: Map<Address, i128>,
    /// When `Some`, ONLY transfers of these token contracts are authorized;
    /// any other token fails closed with `TokenNotAllowed`. `None` = any
    /// SEP-41 token (the original behavior). `Some` must hold between 1 and
    /// `MAX_RULE_ENTRIES` entries — an empty allowlist is a misconfiguration
    /// (it would authorize nothing) and is rejected at construction.
    pub allowed_tokens: Option<Vec<Address>>,
}

/// Immutable configuration set at deploy time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The single wallet this instance is bound to.
    pub wallet: Address,
    /// Cumulative amount (in stroops / base units) this policy authorizes per
    /// window, summed across every authorized transfer regardless of token.
    pub daily_limit: i128,
    /// Rolling-window length in seconds.
    pub window_seconds: u64,
    /// Safety rules over the recognized transfer pattern.
    pub rules: SafetyRules,
}

/// Per-wallet cumulative-spend accounting for the current window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allowance {
    pub window_start: u64,
    pub spent: i128,
}

/// A fully parsed, validated transfer context. Only contexts that decode to
/// this shape are ever counted or authorized.
struct ParsedTransfer {
    token: Address,
    amount: i128,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    /// Deploy-time configuration. Runs exactly once (CAP-0058 constructor);
    /// there is no other path to write `Config`, so the limit, window and
    /// rules are immutable for the life of the instance.
    ///
    /// `wallet` is the account this instance will be attached to; `install`
    /// and `policy__` reject any other wallet. `daily_limit` is the cumulative
    /// window allowance in base units; `window_seconds` is the rolling-window
    /// length. `rules` are the safety rules described in the module docs. All
    /// values are range-checked; an out-of-range rule table fails the deploy
    /// rather than silently shipping a policy that means something else.
    pub fn __constructor(
        env: Env,
        wallet: Address,
        daily_limit: i128,
        window_seconds: u64,
        rules: SafetyRules,
    ) {
        if daily_limit < MIN_ALLOWANCE {
            panic_with_error!(&env, PolicyError::InvalidConfig);
        }
        if window_seconds < MIN_WINDOW_SECONDS || window_seconds > MAX_WINDOW_SECONDS {
            panic_with_error!(&env, PolicyError::InvalidConfig);
        }
        validate_rules(&env, &wallet, &rules);

        env.storage().instance().set::<StorageKey, Config>(
            &StorageKey::Config,
            &Config {
                wallet,
                daily_limit,
                window_seconds,
                rules,
            },
        );

        renew_instance(&env);
    }

    /// Read the immutable configuration (limit, window, rules, bound wallet).
    /// A read-only view for clients and tests; no auth required.
    pub fn config(env: Env) -> Config {
        load_config(&env)
    }
}

#[contractimpl]
impl PolicyInterface for Contract {
    fn install(env: Env, wallet: Address) {
        // The wallet is the direct invoker during add_signer; invoker auth.
        wallet.require_auth();

        // Single-tenant: refuse to install on any wallet other than the one
        // this instance was configured for. A hard panic here aborts the
        // wallet's add_signer, so a misdirected attach fails cleanly.
        let config = load_config(&env);
        if wallet != config.wallet {
            panic_with_error!(&env, PolicyError::WrongWallet);
        }

        let installed_key = StorageKey::Installed(wallet);
        env.storage()
            .persistent()
            .set::<StorageKey, bool>(&installed_key, &true);

        renew_instance(&env);
        renew_persistent(&env, &installed_key);
    }

    fn uninstall(env: Env, wallet: Address) {
        // Permissionless: clear per-wallet state only once this policy is
        // genuinely no longer a signer on `wallet`. The wallet's get_signer is
        // a read-only view; a griefer cannot clear state for a wallet where
        // this policy is still installed.
        let still_signer = SmartWalletClient::new(&env, &wallet)
            .get_signer(&SignerKey::Policy(env.current_contract_address()))
            .is_some();

        if still_signer {
            panic_with_error!(&env, PolicyError::StillInstalled);
        }

        env.storage()
            .persistent()
            .remove::<StorageKey>(&StorageKey::Installed(wallet.clone()));
        env.storage()
            .persistent()
            .remove::<StorageKey>(&StorageKey::Spend(wallet));
    }

    fn policy__(env: Env, source: Address, _signer: SignerKey, contexts: Vec<Context>) {
        // Authenticate the caller really is the wallet before touching any
        // per-wallet state. Satisfied by invoker auth during __check_auth.
        source.require_auth();

        let config = load_config(&env);

        // Single-tenant: this instance only authorizes for its bound wallet.
        // (An external caller could pass any `source`; the require_auth above
        // stops them spending a wallet they don't control, and this stops a
        // legitimately-authed OTHER wallet from ever passing here.)
        if source != config.wallet {
            panic_with_error!(&env, PolicyError::WrongWallet);
        }

        let installed_key = StorageKey::Installed(source.clone());
        if !env.storage().persistent().has::<StorageKey>(&installed_key) {
            panic_with_error!(&env, PolicyError::NotInstalled);
        }

        // Bounded work: an empty authorization authorizes nothing (refuse
        // rather than rubber-stamp a vacuous auth), and an oversized one is
        // refused outright rather than iterated.
        if contexts.is_empty() {
            panic_with_error!(&env, PolicyError::NotAllowed);
        }
        if contexts.len() > MAX_CONTEXTS {
            panic_with_error!(&env, PolicyError::TooManyContexts);
        }

        // Deny-by-default. Parse every context explicitly, apply the safety
        // rules per context, and sum the amounts across the invocation;
        // anything not explicitly permitted rejects.
        let mut total: i128 = 0;
        for context in contexts.iter() {
            let transfer = parse_transfer(&env, &source, &context);
            apply_rules(&env, &config.rules, &transfer);

            total = match total.checked_add(transfer.amount) {
                Some(total) => total,
                None => panic_with_error!(&env, PolicyError::NotAllowed),
            };
        }

        // Cumulative rolling-window allowance. Load the wallet's spend record,
        // resetting it if the window has elapsed, and reject if this
        // invocation would push cumulative spend over the configured cap.
        let now = env.ledger().timestamp();
        let spend_key = StorageKey::Spend(source.clone());
        let mut allowance = env
            .storage()
            .persistent()
            .get::<StorageKey, Allowance>(&spend_key)
            .unwrap_or(Allowance {
                window_start: now,
                spent: 0,
            });

        if now.saturating_sub(allowance.window_start) >= config.window_seconds {
            allowance.window_start = now;
            allowance.spent = 0;
        }

        let new_spent = match allowance.spent.checked_add(total) {
            Some(new_spent) => new_spent,
            None => panic_with_error!(&env, PolicyError::NotAllowed),
        };

        if new_spent > config.daily_limit {
            panic_with_error!(&env, PolicyError::NotAllowed);
        }

        allowance.spent = new_spent;
        env.storage()
            .persistent()
            .set::<StorageKey, Allowance>(&spend_key, &allowance);

        // Keep this policy and its per-wallet state alive for as long as it is
        // actively authorizing.
        renew_instance(&env);
        renew_persistent(&env, &installed_key);
        renew_persistent(&env, &spend_key);
    }
}

/// Range-check the rule tables at construction. Oversized tables are refused
/// (bounded work); a zero/negative single-transfer cap or an empty allowlist
/// would authorize nothing and is treated as a misconfiguration.
fn validate_rules(env: &Env, wallet: &Address, rules: &SafetyRules) {
    if rules.max_single_transfer.len() > MAX_RULE_ENTRIES {
        panic_with_error!(env, PolicyError::InvalidConfig);
    }
    for (token, cap) in rules.max_single_transfer.iter() {
        if cap < MIN_ALLOWANCE || token == *wallet {
            panic_with_error!(env, PolicyError::InvalidConfig);
        }
    }
    if let Some(tokens) = &rules.allowed_tokens {
        if tokens.is_empty() || tokens.len() > MAX_RULE_ENTRIES {
            panic_with_error!(env, PolicyError::InvalidConfig);
        }
        for token in tokens.iter() {
            if token == *wallet {
                panic_with_error!(env, PolicyError::InvalidConfig);
            }
        }
    }
}

/// Explicitly parse one auth context into the single transfer pattern this
/// policy understands, failing closed on any deviation.
fn parse_transfer(env: &Env, source: &Address, context: &Context) -> ParsedTransfer {
    let Context::Contract(ContractContext {
        contract,
        fn_name,
        args,
    }) = context
    else {
        // Non-contract contexts (deploys, etc.) are never permitted.
        panic_with_error!(env, PolicyError::NotAllowed)
    };

    // Never authorize the wallet's own admin surface
    // (add/update/remove/upgrade). `source` is the wallet.
    if *contract == *source {
        panic_with_error!(env, PolicyError::NotAllowed);
    }

    // Only `transfer` is permitted.
    if *fn_name != symbol_short!("transfer") {
        panic_with_error!(env, PolicyError::NotAllowed);
    }

    // SEP-41 transfer: exactly (from, to, amount). Fail closed on any other
    // arity — an extra or missing argument is not a shape we understand.
    if args.len() != 3 {
        panic_with_error!(env, PolicyError::NotAllowed);
    }

    // `from` MUST be the bound wallet: this policy only ever authorizes the
    // wallet spending its own funds. Any other `from` is a mismatched context.
    let from = match args
        .get(0)
        .and_then(|v| Address::try_from_val(env, &v).ok())
    {
        Some(from) => from,
        None => panic_with_error!(env, PolicyError::NotAllowed),
    };
    if from != *source {
        panic_with_error!(env, PolicyError::ContextMismatch);
    }

    // `to` must decode as an address; a transfer to the wallet itself moves
    // nothing and is refused rather than counted against the budget.
    let to = match args
        .get(1)
        .and_then(|v| Address::try_from_val(env, &v).ok())
    {
        Some(to) => to,
        None => panic_with_error!(env, PolicyError::NotAllowed),
    };
    if to == *source {
        panic_with_error!(env, PolicyError::NotAllowed);
    }

    // Fail closed if the amount argument is not a positive i128.
    let amount = match args.get(2).and_then(|v| i128::try_from_val(env, &v).ok()) {
        Some(amount) => amount,
        None => panic_with_error!(env, PolicyError::NotAllowed),
    };
    if amount <= 0 {
        panic_with_error!(env, PolicyError::NotAllowed);
    }

    ParsedTransfer {
        token: contract.clone(),
        amount,
    }
}

/// Apply the per-context safety rules. Both lookups are bounded by
/// `MAX_RULE_ENTRIES`.
fn apply_rules(env: &Env, rules: &SafetyRules, transfer: &ParsedTransfer) {
    if let Some(tokens) = &rules.allowed_tokens {
        if !tokens.contains(&transfer.token) {
            panic_with_error!(env, PolicyError::TokenNotAllowed);
        }
    }
    if let Some(cap) = rules.max_single_transfer.get(transfer.token.clone()) {
        if transfer.amount > cap {
            panic_with_error!(env, PolicyError::SingleTransferExceeded);
        }
    }
}

fn load_config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get::<StorageKey, Config>(&StorageKey::Config)
        // A deployed instance always ran its constructor, so this is
        // unreachable in practice; fail closed rather than unwrap-panic
        // opaquely.
        .unwrap_or_else(|| panic_with_error!(env, PolicyError::NotInstalled))
}

fn renew_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(RENEW_THRESHOLD, RENEW_TO);
}

fn renew_persistent(env: &Env, key: &StorageKey) {
    env.storage()
        .persistent()
        .extend_ttl::<StorageKey>(key, RENEW_THRESHOLD, RENEW_TO);
}

#[cfg(test)]
mod test;
