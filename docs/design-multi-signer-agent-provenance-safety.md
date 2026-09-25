# Design & decisions: multi-signer management, agent keys, verified provenance, on-chain safety rules

Status: **built** (#401, #394, #398, #399 — one PR). This is the in-repo record
of the load-bearing decisions and deliberate deviations for that work, in the
`docs/decisions.md` format (context, decision, reason, security implications,
alternatives). `docs/decisions.md` itself is git-ignored in this repository, so
the entries live here; copy them into the private decisions log if that is
still the source of truth.

---

## 2026-09-25 — Signer listing: indexer-enumerated, ledger-confirmed (#401)

**Context.** Soroban RPC cannot enumerate a contract's storage entries, and the
smart wallet stores one entry per signer keyed by `SignerKey`, so there is no
single RPC call that lists an account's signers.

**Decision.** `WalletRuntime.listSigners` enumerates through passkey-kit's
hosted `MercuryIndexer` (keyless, indexes the wallet's own
`SignerAdded`/`SignerRemoved` events on testnet and mainnet) and then CONFIRMS
every non-removed row with a direct ledger read (`kit.getSigner`). A row the
ledger no longer has is dropped; the ledger is the truth, the indexer is the
candidate list. At most 64 rows are confirmed per listing.

**Reason.** The chain is authoritative, cross-device changes must show up on
refresh, and no separate local signer list may exist. The indexer alone could
lag; the ledger read alone cannot enumerate.

**Security implications.** A stale or malicious indexer can hide a signer
from the list (it cannot fabricate one — unconfirmed rows are dropped). Hiding
does not grant authority: the wallet contract, not the list, decides who can
sign. Revocation and the last-admin guard act on `SignerKey`s the user chose
from the confirmed list, and the contract re-checks everything on submit.

**Alternatives.** Backend event indexing in wallet-service (a second indexer
to run and trust); reading the wallet's `SignerAdded` events via RPC
`getEvents` (bounded retention, incomplete history).

---

## 2026-09-25 — Last-passkey lockout: the contract is the guard, the UI mirrors it (#401)

**Context.** Revoking the only passkey would permanently lock the account
(no seed phrase, no social recovery by design).

**Decision.** The smart wallet contract (pinned passkey-kit rev `50981cc`)
already refuses to remove or demote its last durable admin signer
(`LastAdminSigner` = 103) and its last durable signer (`LastSigner` = 104).
The web app mirrors that rule client-side (`canRevokeSigner`) to refuse before
a passkey prompt and to explain, and maps codes 103/104 to a clear message
when the contract refuses. Both layers are tested; the contract's refusal is
the security boundary.

**Alternatives.** A UI-only check (bypassable); a hard block on every
passkey removal (would also block legitimate rotation).

---

## 2026-09-25 — Second passkey is a durable, unlimited admin peer (#401)

**Decision.** `addPasskeySigner` adds the new credential as
`Persistent`, `SignerLimits(None)`, no expiration.

**Reason.** A recovery passkey that cannot administer the account cannot
recover it. Anything narrower would count as "not a durable admin" for the
contract's lockout guard and leave the original passkey as the single point of
failure.

**Security implications.** The second passkey is a full peer: losing either
device is survivable, compromising either device is fatal. This is the
documented trade-off of the sanctioned recovery story.

---

## 2026-09-25 — Agent budget = token-scoped policy attached standalone + named as required co-signer (#394)

**Decision.** Minting an agent key deploys a `token-spending-limit` instance
bound to (wallet, token), attaches it as a STANDALONE policy signer
(`SignerLimits(None)`, first passkey prompt), then adds the agent's ed25519
key with `SignerLimits { token → [Policy(instance)] }` (second passkey
prompt). Order: attach first, then add the key.

**Reason.** `policy__` refuses until `install` has run, and `install` only
runs when the policy is added as a signer — so the policy must be attached
before the agent can spend. Attaching standalone keeps the V3/RA-6 recovery
invariant (the admin passkey can detach it without the policy's consent).
Attach-then-add means a failure between the two steps leaves either an
attached-but-unused policy (harmless) or nothing; the reverse order could
leave a key whose policy is not installed, which fails closed anyway but is
confusing.

**Security implications.** Two explicit passkey prompts; the budget is the
contract's `daily_limit` over a FIXED (tumbling) window (up to 2× across a
boundary — security-audit.md M3, stated verbatim in the UI). The SDK's
`maxAmount` is a client guard, not the budget. When a verified-provenance
policy is attached to the account, it is added as a second required co-signer
on the agent's grant (budget caps how much, provenance caps through-what).

---

## 2026-09-25 — Agent key material: CSPRNG in the browser, revealed once, never stored (#394)

**Decision.** The keypair is derived from 32 bytes of
`crypto.getRandomValues`; the seed buffer is zeroed after use; the secret
lives only in the mint state machine's `success` state until
`DISMISS_SECRET`, is never logged (error copy passes through `redactSecrets`),
never persisted, never put in a URL.

**Reason (deviation from "non-extractable WebCrypto")**. The operator must run
the key headlessly elsewhere (`createSessionKeySigner` takes the `S…`
secret), so the material has to leave the page exactly once. A
non-extractable key would make the mint flow useless to the agent it is for.
The non-extractable recommendation applies to the agent RUNTIME
(open-work-catalogue 2.3), not the mint UI.

---

## 2026-09-25 — Agent keys are testnet-only (#394)

**Decision.** The mint card refuses on any network other than testnet and
shows the network on the card.

**Reason.** The token-scoped policy is validated on testnet only; mainnet use
is gated on the smart-contract checklist (idea.md §12; open-work-catalogue
2.5). Reuses the existing `NEXT_PUBLIC_STELLAR_NETWORK` gating — no second
network selector.

---

## 2026-09-25 — Provenance modes: where each is enforced (#398)

**Context.** A policy signer is consulted by the wallet only when it appears
in an authorization's signature map: as a required co-signer in the signing
key's `SignerLimits`, or as an explicit `Signature::Policy` entry. An
unlimited passkey is, by definition, not limited by any policy.

**Decision.**

- `strict` and `trusted_publishers` are ON-CHAIN: a `verified-recipient`
  instance (`ProvenanceMode::Strict` / `TrustedPublishers(set)`) is deployed
  for the account and attached as a standalone policy signer. It binds
  (a) every agent key minted while it is attached (required co-signer), and
  (b) any authorization that includes it in the signature map (the SDK's
  x402 signers do this via `policies`). Rejection happens in `__check_auth`.
- `warn` is WALLET-SIDE: no policy; the send flow looks the target up and
  shows a provenance warning, then proceeds. It is labelled as a signal.
- The unlimited passkey itself is NOT gated. That is deliberate: the passkey
  is the recovery path (detach the policy), and gating it would require
  listing every allowed contract in its `SignerLimits`, which is not
  "verified-only" but an allowlist.

**Security implications.** Copy states exactly this. "Verified" means
reproducible, attributable source provenance — never audited / benign / safe.
Registry unavailable ⇒ the policy traps ⇒ fail closed; recovery is the
admin's `remove_signer(Policy)`, which the wallet performs without consulting
the policy (V3 / RA-6), proven on testnet with a registry-less instance.

**Alternatives.** Limiting the passkey via `SignerLimits` (turns the feature
into a static allowlist and removes the recovery path); a wallet-contract
change (out of scope — the deployed passkey-kit wallet is audited and pinned).

---

## 2026-09-25 — Publisher attribution lives in the registry, keyed by source owner (#398)

**Decision.** `attestation-registry` gains `upsert_with_publisher(contract,
wasm_hash, publisher: BytesN<32>, expires)` and `publisher_of(contract) ->
Option<BytesN<32>>` (None when unverified, expired, or unattributed). The
publisher id is `sha256(lower(host + "/" + repo-owner))` of the verification
record's `repoUrl`, computed by `@vellar/service-kit`'s `publisherIdFor` in
BOTH the attestor worker (write side) and policy-service (policy config side),
so the two never disagree. Legacy `upsert` still works and writes an
unattributed record, which never matches a trusted set.

**Reason.** "Trusted publishers only" must be a publisher set, not a hash
list; the repository owner is the only attribution the pipeline actually
establishes. Storing it on the attestation ties attribution to the live
provenance claim (both expire together).

**Security implications.** Attribution is exactly as strong as the pipeline's
`repoUrl` handling (SSRF guard, pinned clone). A publisher id says WHOSE
source reproduced the bytes; it is not an endorsement.

**Deployment.** New registry wasm `1c243e00…` (canonical image,
self-verified) deployed as `CDYLXSYEE7CSPM3JTU52TODQWVUMDUZVFIDPEAVGDCBO7Q4YFKYHHR4W` with
the SAME attestor address as the previous instance, so the worker's existing
key keeps writing once `ATTESTATION_REGISTRY_ID` is switched in its config.
The previous registry (`CBZVS2ET…`) stays readable; strict-mode instances
pinned to it keep working.

---

## 2026-09-25 — Safety rules: two token-denominated rules, no recipient history (#399)

**Decision.** `spending-limit` gains an immutable `SafetyRules` constructor
argument: `max_single_transfer: Map<token, i128>` (per-token ceiling on any
one transfer, in that token's base units) and `allowed_tokens:
Option<Vec<Address>>` (token allowlist). Both tables are bounded to 8 entries;
`policy__` refuses more than 16 auth contexts, refuses empty context lists,
and parses every context field-by-field (`transfer(from, to, amount)` with
`from == wallet`; anything else is a mismatched context and is rejected).

**Reason.** These are the two rule types the existing contract architecture
enforces cleanly without new storage. The "never-sent-before recipient" rule
was NOT shipped: it needs the contract to keep an authoritative per-wallet
recipient history (rent-bearing persistent entries, an admin-authorized
"record recipient" surface and its UI), and a per-token cap plus an allowlist
already cover the issue's minimum of two rule types honestly.

**Security implications.** No USD anywhere; no oracle calls. Rules are
"on-chain spending controls for supported transfer patterns" — value moved
through other contract paths is outside the policy's view and the copy says
so. Existing invariants (single-tenant binding, caller auth, deny-by-default,
checked arithmetic, TTL renewal, tumbling window, permissionless self-clean)
are preserved and the original test suite still passes unchanged apart from
the constructor arity. Re-simulation safety is pinned by ledger-snapshot
tests (`repeated_simulation_does_not_consume_budget_and_settlement_does`).

**Deployment.** New wasm `c42ab9b5…` (canonical image, self-verified,
uploaded to testnet). Instances deployed from the previous hash keep their
original (rule-less) semantics until detached and re-attached — the same
"new wasm = new instance" rule as every other policy change.

---

## 2026-09-25 — policy-service on `dev` was missing its own imports

**Context.** `services/policy-service/src/server.ts` on `dev` referenced
`generateBodySchema`, `deployBodySchema`, `deployInstanceBodySchema`,
`validateDefinition`, `validatePolicyForDeployment`, `validatePolicyInstance`,
`simulatePolicyDeploy`, `deployPolicyInstance`, `verifyAndRecordAttach` and a
`deploymentDeps` value without importing or defining them (an unfinished
refactor, see `REFACTOR_348_*.md`). Every route that deploys or records a
policy threw `ReferenceError` at runtime; 30 server tests and `pnpm
typecheck` were red before this branch.

**Decision.** Add the missing imports and the `deploymentDeps` object in
`buildServer`. No behavioural change beyond making the routes execute.

**Reason.** The agent-key mint and provenance flows depend on these routes;
the fix is minimal and mechanical. Five remaining `deployment.test.ts`
failures (an ISO-date fixture mismatch and a stubbed RPC lookup returning
`undefined`) predate this branch and are unrelated; they are left untouched
and called out in the PR.
