# Headless Agent Runtime Example (x402)

Autonomous agent runtime demonstrating x402-gated micro-payments under an on-chain budget using a **non-extractable WebCrypto Ed25519 signer**, without holding or exposing any raw account secret keys.

Based on **technical-doc.md §17.3, §17.4, §17.5**, `docs/decisions.md` (2026-07-26), and `docs/design-x402-sdk-client.md`.

---

## Key Features

1. **Non-Extractable WebCrypto Key (§17.4):**
   - The Ed25519 private key is generated with `crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])`.
   - The `extractable: false` attribute guarantees that the private key material **cannot be exported, printed, serialized to disk, or leaked**.
   - If an agent process is compromised or inspected, raw secret keys cannot be extracted.

2. **Autonomous x402 Payments:**
   - Pays 402-gated endpoints via the SDK x402 client (`402 Payment Required` → parse requirements → sign V1 auth entry → retry with `PAYMENT-SIGNATURE`).
   - Targets real gated endpoints in the Vellar stack (e.g. `POST /lifecycle/execute` at $0.50, `GET /verification/:contractId` at $0.05).

3. **Graceful Over-Budget Handling:**
   - Facilitators verify payments by **re-simulation**, which executes `__check_auth` on the smart account.
   - Therefore, the on-chain token spending limit policy runs at **verify time**, not just settlement time.
   - When the agent's allocated budget is exhausted, the verify simulation fails, and the agent catches `PaymentRejectedError` gracefully rather than crashing or entering an infinite retry loop.

4. **Honest V1-Credential Tradeoff (§17.5):**
   - The agent path signs type-1 `sorobanCredentialsAddress` (V1) credentials because deployed facilitators reject CAP-0071-02 type-2 credentials.
   - This is an **accepted, deliberate tradeoff** for a dedicated per-wallet key: the agent key is an Ed25519 signer bound directly to a restricted spending policy, rather than an unconstrained master key.
   - Source pointer: `docs/design-x402-sdk-client.md §1` & `technical-doc.md §17.5`.

5. **Testnet Only:**
   - Per §17.4, agent key payments remain restricted to Stellar **Testnet** until the mainnet security audit and checklist gates (Group 1 item 1.1) are fully met.

---

## Prerequisites

- Node.js >= 22 (for native WebCrypto Ed25519 support)
- pnpm >= 11
- A deployed Vellar smart account on Stellar Testnet

---

## Quickstart

### 1. Install dependencies

From the monorepo root:
```bash
pnpm install
```

### 2. Configure environment variables (optional)

```bash
export SMART_ACCOUNT_ADDRESS="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
export TARGET_URL="https://api.vellar.xyz/verification/CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75"
```

### 3. Run the agent

```bash
pnpm --filter @vellar/example-headless-agent start
```

### Expected Output

```
=== Vellar Headless Autonomous Agent (x402) ===
[Agent] Generated non-extractable WebCrypto Ed25519 key:
[Agent] Public Key (G...): GDJ7...3K2L
[Agent] Private Key Extractable: false
[Agent] Requesting https://api.vellar.xyz/verification/... using authorized agent key GDJ7...3K2L...
[Agent] Successfully fetched https://api.vellar.xyz/verification/... (HTTP 200, paid: true)
[Agent] Final Result: {
  url: 'https://api.vellar.xyz/verification/...',
  status: 200,
  paid: true,
  data: { verified: true, ... }
}
```

When an agent exceeds its assigned on-chain budget:
```
[Agent] 🛑 Budget policy rejected payment for https://api.vellar.xyz/lifecycle/execute. Re-simulation failed at __check_auth.
[Agent] Reason: PaymentRejectedError: x402 payment was not accepted: policy rejected spend over-budget
[Agent] Gracefully stopping spend to protect the wallet.
[Agent] Final Result: {
  url: 'https://api.vellar.xyz/lifecycle/execute',
  status: 402,
  paid: false,
  overBudget: true,
  error: 'On-chain budget policy exhausted. Agent will not retry.'
}
```

---

## Running Tests

Run the test suite with network mocks:
```bash
pnpm --filter @vellar/example-headless-agent test
```
