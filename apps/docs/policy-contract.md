# Policy Contract — Configurable Spending Limit

Source: `contracts/policy-templates/spending-limit` (crate
`vela-spending-limit-policy`).
Testnet wasm hash: `c42ab9b52c977a3ba29ca3e848dda499e91180e0c01de86a7e21e241989fcbdf`
(canonical `vela-verify:1.94.0` build, self-verified by a clean byte-identical
rebuild; re-pinned 2026-09-25 with the on-chain safety rules below).

This is a hardened, **configurable** derivative of the audited passkey-kit
`sample-policy`. It lets a user choose their own spending limit in the UI and
have _that number_ enforced on-chain, per account.

## Why a cumulative window, not a per-transaction cap

A policy signer carries **no secret** — anyone can submit it, so a policy that
authorizes value transfers authorizes them for everyone. That means a
per-transaction cap is **not** a spending limit: repeated capped transfers can
drain the whole balance.

So the user's limit is enforced as a **cumulative allowance over a fixed
(tumbling) window** — not a continuously sliding one: `spent` accumulates from
the first spend of a window and resets to zero once `window_seconds` have
elapsed since that `window_start`. Because the reset is on a fixed schedule
rather than sliding, spending near a boundary can move up to **`2 * daily_limit`**
within a short span (the full cap just before the reset plus the full cap just
after). The bound is therefore `daily_limit` per fixed window and **at most
`2 * daily_limit`** across any boundary. Treat this as a spending guardrail, not
a hard cap. For a hard guarantee, pair the policy — via the granting signer's
`SignerLimits` — with an authenticated co-signer.

## Constructor (immutable configuration)

```rust
pub fn __constructor(env: Env, wallet: Address, daily_limit: i128, window_seconds: u64, rules: SafetyRules)
```

- `wallet` — the single smart account this instance is bound to.
- `daily_limit` — cumulative window allowance, in **stroops** (1 XLM =
  10,000,000 stroops).
- `window_seconds` — fixed (tumbling) window length (Vellar uses 24h = 86400 by
  default). The window resets on a fixed schedule, so up to `2 * daily_limit` can
  move across a boundary — see above.

Configuration is written **once** and never mutated — there is no setter. If the
owner could raise their own cap in-place, the policy would guarantee nothing.
Changing a limit means deploying a fresh instance and re-attaching it with a
passkey (an explicit, auditable admin action).

- `rules` — the on-chain safety rules (below). Pass an empty rule set for the
  original behaviour.

Range checks: `daily_limit ≥ 1`, `1 ≤ window_seconds ≤ 31,536,000` (365 days).

## On-chain safety rules (supported transfer patterns)

```rust
pub struct SafetyRules {
    /// token contract → largest amount (base units) ONE transfer of that token may move
    pub max_single_transfer: Map<Address, i128>,   // at most 8 entries, each ≥ 1
    /// when Some, ONLY transfers of these token contracts are authorized
    pub allowed_tokens: Option<Vec<Address>>,      // None = any token; Some = 1..=8 entries
}
```

Both rules are evaluated inside `policy__` — i.e. inside the account's
`__check_auth` — so a violating transfer is **rejected on-chain**, not warned
about in a UI. Errors are distinct so clients can explain the refusal:
`TokenNotAllowed` (6), `SingleTransferExceeded` (7), `ContextMismatch` (8),
`TooManyContexts` (9).

What the rules are, honestly:

- **Token-denominated, never fiat.** There is no price oracle on Soroban, so a
  cap is meaningful only in the units of the token it applies to. The policy
  never calls pricing infrastructure.
- **One known transfer pattern.** The policy understands a SEP-41
  `transfer(from, to, amount)` where `from` is the bound wallet. Every context
  is parsed field by field; a `transfer` whose `from` is some other address is
  a mismatched authorization context and is rejected. Anything that is not
  that pattern is denied by default.
- **Not a universal firewall.** Value the account moves through other contract
  paths, or through other signers, is outside this policy's view. The UI copy
  says "on-chain spending controls for supported transfer patterns".
- **Bounded work.** Rule tables are capped at 8 entries and `policy__` refuses
  more than 16 auth contexts (and an empty context list), so the work done per
  `__check_auth` is predictable — x402 facilitators re-simulate payments, and
  each simulation runs this code.
- **Re-simulation safe.** `policy__` is deterministic in (ledger timestamp,
  stored allowance, contexts); a simulation's writes are discarded, so repeated
  dry-runs consume no budget. Pinned by ledger-snapshot tests.
- **Not shipped: "never-sent-before recipient".** That rule needs the contract
  to keep its own on-chain recipient history (rent-bearing persistent entries
  and an admin surface to record recipients). It was left out rather than
  approximated with off-chain history.

## Policy Template Schema Validation (idea.md §6.2)

Templates submitted to `policy-service` are strictly validated prior to code generation or on-chain instantiation:

- **Strict Schema Enforcement**: Unknown or extra properties outside the template definition are rejected with field-level errors (`.strict()`).
- **Owner Addresses**: Validated against Stellar address formats (`G…` or `C…`). Duplicated owner addresses are rejected. `single_owner` requires exactly one owner; `multisig_threshold` requires at least two owners.
- **Multisig Threshold**: Must be an integer `≥ 2` and cannot exceed the number of distinct owners (`threshold ≤ owners.length`).
- **Spending Limits**:
  - `dailyXlm` and `perTxXlm` must be positive decimal strings with at most 7 decimal places (stroop precision).
  - Minimum allowance is 1 stroop (`0.0000001` XLM). Sub-stroop amounts (`0`, negative, or `> 7` decimal places) fail validation.
  - When both are specified, `perTxXlm` must not exceed `dailyXlm`.
- **Contract Allowlists**: Must be valid contract addresses (`C…`). Duplicates are rejected, and at least one contract must be provided.
- **Timelocks**: `adminActionDelaySeconds` must be an integer between `1` second and `31,536,000` seconds (365 days).

## Single-tenant binding

Each instance is bound to one wallet at deploy. Both the `install` hook and the
`policy__` authorization check reject any wallet other than the bound one, so a
deployed instance cannot be attached to — or spent through — a different account.

## Preserved security invariants

The contract keeps every hardening property of the reference policy:

- **Caller authentication** — `source.require_auth()` before touching any
  per-wallet state.
- **Deny-by-default** — only positive `transfer`s to a non-wallet contract pass;
  any other function, a non-contract context, a missing/mistyped amount, a
  non-positive amount, or a context targeting the wallet's own admin surface all
  fail closed.
- **Checked arithmetic** throughout.
- **TTL renewal** on install and every successful check, so the policy can't
  silently archive into a wallet lock.
- **Permissionless self-clean** — `uninstall` clears per-wallet state only after
  confirming the policy is genuinely no longer a signer on that wallet.

## Deploy flow

The contract is instantiated per user (see
[Core Flows §4](./core-flows.md#4-create-and-deploy-a-policy)):

1. policy-service deploys a configured instance bound to the account
   (sponsor-funded, from the wasm hash above).
2. The web app passkey-signs `kit.addPolicy(contractId, …)` to attach it, which
   runs the contract's `install` hook.

### Build & test locally

```sh
cd contracts
cargo test -p vela-spending-limit-policy   # unit tests (constructor validation,
                                           # deny-by-default, window enforcement,
                                           # wrong-wallet, TTL, self-clean)
stellar contract build                     # optimized wasm
```

## Sibling policies

- **`token-spending-limit`** (testnet wasm `7756ebbd…`) — the same cumulative
  window bound to ONE token; transfers of any other token are rejected. This is
  the budget an **agent session key** is minted against from Settings: the
  agent's `SignerLimits` name the instance as a required co-signer, so every
  spend is checked on-chain. The SDK's client-side `maxAmount` is a guard, not
  the budget. The window is tumbling (up to 2× across a boundary) — the mint UI
  says so.
- **`verified-recipient`** (testnet wasm `ef07b922…`) — the signer may only
  invoke contracts with a live attestation in the attestation registry.
  `ProvenanceMode::Strict` accepts any live attestation;
  `ProvenanceMode::TrustedPublishers(set)` only attestations attributed (by the
  registry's `publisher_of`) to one of up to 16 publisher ids. Same explicit
  `auth_contexts` parsing and 16-context bound as above. **Verified means
  reproducible, attributable source provenance — not audited, benign or safe.**
  If the registry is unreachable the policy fails closed; the account's admin
  passkey can always detach it (`remove_signer(Policy)` runs no policy code).
- **`attestation-registry`** (testnet wasm `1c243e00…`, instance
  `CDYLXSYEE7CSPM3JTU52TODQWVUMDUZVFIDPEAVGDCBO7Q4YFKYHHR4W`) — the on-chain
  mirror of the off-chain verification pipeline. `upsert_with_publisher`
  attributes an attestation to a publisher id
  (`sha256(host/owner)` of the verified repository); `upsert` writes an
  unattributed one, which never matches a trusted-publisher set.

## Status

**Testnet only. Not yet audited for mainnet.** Mainnet use is gated on the
smart-contract security-review checklist (see [Security Model](./security-model.md)).
Dependencies are pinned to the audited passkey-kit contract workspace
(soroban-sdk 27, `smart-wallet-interface` via a pinned commit).
