// Testnet evidence for #401 / #394 / #398 / #399 — REAL transactions against
// a REAL passkey-kit smart wallet, driving exactly the on-chain paths the web
// UI drives (add_signer / remove_signer / policy attach / policy-limited
// spends). Run from apps/web:
//
//   EVIDENCE_SECRET=S… ATTESTOR_SECRET=S… WALLET_ID=C… EVIDENCE_REGISTRY_ID=C… \
//   TRUSTED_PUBLISHER_ID_HEX=… UNTRUSTED_PUBLISHER_ID_HEX=… \
//   node --experimental-transform-types scripts/testnet-policy-evidence.mts
//
// The wallet's admin signer is an ed25519 key held by the operator (a passkey
// cannot be driven from Node — WebAuthn needs a browser). On-chain the two
// signer kinds are indistinguishable for everything exercised here: both are
// admin-capable `Signer` entries, and `add_signer` / `remove_signer` /
// `LastAdminSigner` / `__check_auth` treat them identically. What the browser
// adds (the WebAuthn ceremony) is covered by the settings-page unit tests and
// by passkey-kit itself.
//
// No secret is ever printed. The script writes a JSON evidence log (tx hashes,
// contract ids, outcomes) to EVIDENCE_OUT (default ./testnet-evidence.json).

import { writeFileSync } from "node:fs";
import {
  Account,
  Address,
  Asset,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";
import { Client as ContractClient } from "@stellar/stellar-sdk/contract";
import { createSessionKeySigner } from "vellar-sdk";
import { createPolicyDeployer } from "../../../services/policy-service/src/deploy.ts";
import type { DeployPolicyInstanceInput } from "../../../services/policy-service/src/deploy.ts";

const RPC_URL = "https://soroban-testnet.stellar.org";
const PASSPHRASE = Networks.TESTNET;
const NATIVE_SAC = Asset.native().contractId(PASSPHRASE);

const SPENDING_LIMIT_WASM = "c42ab9b52c977a3ba29ca3e848dda499e91180e0c01de86a7e21e241989fcbdf";
const VERIFIED_RECIPIENT_WASM = "ef07b922670bab0f2c15c48bc96a3af0d858250c785536dde3e49d6ead690def";
const TOKEN_SPENDING_WASM = "7756ebbd6423a225692a529ca1294bc74e40bc7265184265dcd9bfc2e6a09c5e";

const XLM = 10_000_000n;

const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`missing env ${k}`);
  return v;
};

const admin = Keypair.fromSecret(env("EVIDENCE_SECRET"));
const attestor = Keypair.fromSecret(env("ATTESTOR_SECRET"));
const WALLET = env("WALLET_ID");
const EVIDENCE_REGISTRY = env("EVIDENCE_REGISTRY_ID");
const OUT = process.env.EVIDENCE_OUT ?? "./testnet-evidence.json";

const server = new rpc.Server(RPC_URL);
const evidence: Array<Record<string, unknown>> = [];
function record(entry: Record<string, unknown>) {
  evidence.push({ ...entry, at: new Date().toISOString() });
  console.log(JSON.stringify(entry));
  writeFileSync(OUT, JSON.stringify(evidence, null, 2));
}

// ---------------------------------------------------------------- helpers

async function waitFinal(hash: string): Promise<"success" | "failed"> {
  for (let i = 0; i < 40; i++) {
    const r = await server.getTransaction(hash);
    if (r.status === rpc.Api.GetTransactionStatus.SUCCESS) return "success";
    if (r.status === rpc.Api.GetTransactionStatus.FAILED) return "failed";
    await new Promise((res) => setTimeout(res, 1500));
  }
  throw new Error(`tx ${hash} not final`);
}

/** A smart-wallet signer: `secret`'s ed25519 key plus the policies its
 * SignerLimits require (exactly what the SDK's agent x402 signer uses). */
function walletSigner(secret: string, policies: string[] = []) {
  return createSessionKeySigner({ address: WALLET, secretKey: secret, policies });
}

type Outcome = { ok: true; hash?: string; simulations?: number } | { ok: false; error: string };

/**
 * Invoke `contractId.fn(args)` with the smart wallet as the authorizing
 * address: simulate → sign the wallet's auth entry through __check_auth's
 * signature map (ed25519 + policy co-signers) → RE-simulate with the real
 * signatures (so resources include __check_auth) → assemble → send. Returns
 * the tx hash on success; on a rejection returns the diagnostic verbatim.
 */
async function invokeAsWallet(
  contractId: string,
  fn: string,
  args: xdr.ScVal[],
  signer: ReturnType<typeof walletSigner>,
  opts: { repeatSimulations?: number } = {},
): Promise<Outcome> {
  const source = await server.getAccount(admin.publicKey());
  // TransactionBuilder.build() bumps the Account's sequence, so every build
  // starts from a fresh Account at the same sequence number.
  const build = (auth?: xdr.SorobanAuthorizationEntry[]) =>
    new TransactionBuilder(new Account(source.accountId(), source.sequenceNumber()), {
      fee: (Number(BASE_FEE) * 100).toString(),
      networkPassphrase: PASSPHRASE,
    })
      .addOperation(
        Operation.invokeContractFunction({ contract: contractId, function: fn, args, auth }),
      )
      .setTimeout(60)
      .build();

  const sim1 = await server.simulateTransaction(build());
  if (rpc.Api.isSimulationError(sim1)) return { ok: false, error: sim1.error };
  const latest = await server.getLatestLedger();
  const expiration = latest.sequence + 60;
  const signedAuth: xdr.SorobanAuthorizationEntry[] = [];
  for (const entry of sim1.result?.auth ?? []) {
    const creds = entry.credentials();
    if (creds.switch() !== xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
      signedAuth.push(entry);
      continue;
    }
    const addr = Address.fromScAddress(creds.address().address()).toString();
    if (addr !== WALLET) {
      signedAuth.push(entry);
      continue;
    }
    const signed = await signer.signAuthEntry(entry.toXDR("base64"), {
      networkPassphrase: PASSPHRASE,
      expirationLedger: expiration,
    });
    signedAuth.push(xdr.SorobanAuthorizationEntry.fromXDR(signed, "base64"));
  }

  const withAuth = build(signedAuth);
  const repeats = opts.repeatSimulations ?? 1;
  let sim: rpc.Api.SimulateTransactionResponse | undefined;
  for (let i = 0; i < repeats; i++) {
    sim = await server.simulateTransaction(withAuth);
    if (rpc.Api.isSimulationError(sim)) return { ok: false, error: sim.error };
  }
  const prepared = rpc.assembleTransaction(withAuth, sim!).build();
  prepared.sign(admin);
  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") {
    return { ok: false, error: `send: ${sent.errorResult?.toXDR("base64")}` };
  }
  const final = await waitFinal(sent.hash);
  return final === "success"
    ? { ok: true, hash: sent.hash, simulations: repeats }
    : { ok: false, error: `failed on-chain ${sent.hash}` };
}

const transferArgs = (to: string, amount: bigint) => [
  nativeToScVal(Address.fromString(WALLET), { type: "address" }),
  nativeToScVal(Address.fromString(to), { type: "address" }),
  nativeToScVal(amount, { type: "i128" }),
];

/** Wallet admin calls (add_signer / remove_signer): encode the typed args with
 * the wallet's on-chain spec, then go through the same sign → re-simulate →
 * send path as every other wallet-authorized call. */
async function walletClient(signer: ReturnType<typeof walletSigner>) {
  const client = await ContractClient.from({
    contractId: WALLET,
    rpcUrl: RPC_URL,
    networkPassphrase: PASSPHRASE,
    publicKey: admin.publicKey(),
  });
  const run = async (method: string, args: Record<string, unknown>): Promise<Outcome> => {
    try {
      const scVals = client.spec.funcArgsToScVals(method, args);
      return await invokeAsWallet(WALLET, method, scVals, signer);
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  };
  return { run };
}

/** Host maps must be key-sorted; contract addresses sort by their raw bytes. */
const byAddress = (a: string, b: string) =>
  Buffer.compare(Address.fromString(a).toBuffer(), Address.fromString(b).toBuffer());

const ed25519Signer = (
  kp: Keypair,
  limits: Map<string, string[]> | undefined,
  expiration?: number,
  storage: "Persistent" | "Temporary" = "Persistent",
) => ({
  tag: "Ed25519",
  values: [
    kp.rawPublicKey(),
    [expiration === undefined ? undefined : BigInt(expiration)],
    [
      limits === undefined
        ? undefined
        : new Map(
            [...limits]
              .sort(([a], [b]) => byAddress(a, b))
              .map(([c, policies]) => [
                c,
                [...policies].sort(byAddress).map((p) => ({ tag: "Policy", values: [p] })),
              ]),
          ),
    ],
    { tag: storage, values: undefined },
  ],
});
const policySigner = (policy: string) => ({
  tag: "Policy",
  values: [policy, [undefined], [undefined], { tag: "Persistent", values: undefined }],
});
const key = (tag: "Ed25519" | "Policy", value: Buffer | string) => ({ tag, values: [value] });

const errorCode = (msg: string) => /Error\(Contract, #(\d+)\)/.exec(msg)?.[1] ?? null;
const outcome = (r: Outcome) => ({ ...r, code: r.ok ? null : errorCode(r.error) });

async function deployPolicy(
  wasm: string,
  constructorArgs: DeployPolicyInstanceInput["constructorArgs"],
) {
  const deployer = createPolicyDeployer(
    {
      rpcUrl: RPC_URL,
      networkPassphrase: PASSPHRASE,
      sponsorSecretKey: admin.secret(),
      rpcTimeoutMs: 30_000,
      pollTimeoutMs: 120_000,
    },
    wasm,
  );
  return deployer.deployInstance({ wallet: WALLET, constructorArgs });
}

/** Submit a transaction whose only authorizer is a classic G-account (the tx
 * source): build → prepare → sign → send → wait. */
async function submitAs(kp: Keypair, op: xdr.Operation): Promise<string> {
  const source = await server.getAccount(kp.publicKey());
  const tx = new TransactionBuilder(source, {
    fee: (Number(BASE_FEE) * 100).toString(),
    networkPassphrase: PASSPHRASE,
  })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(tx);
  prepared.sign(kp);
  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") throw new Error(`send failed: ${sent.errorResult?.toXDR("base64")}`);
  const final = await waitFinal(sent.hash);
  if (final !== "success") throw new Error(`tx ${sent.hash} failed`);
  return sent.hash;
}

async function fundWallet(xlm: bigint) {
  return submitAs(
    admin,
    Operation.invokeContractFunction({
      contract: NATIVE_SAC,
      function: "transfer",
      args: [
        nativeToScVal(Address.fromString(admin.publicKey()), { type: "address" }),
        nativeToScVal(Address.fromString(WALLET), { type: "address" }),
        nativeToScVal(xlm * XLM, { type: "i128" }),
      ],
    }),
  );
}

/** Deploy the SAC for a fresh classic asset issued by the admin account and
 * mint some to the wallet: a real token contract the wallet holds that nobody
 * has attested — the "unverified target" / "other token". */
async function deployHeldToken(): Promise<string> {
  // A fresh asset code per run: the evidence registry is persistent, so a
  // token attested in an earlier run would otherwise be "verified" already.
  const asset = new Asset(
    `EV${Math.floor(Math.random() * 1e9)
      .toString(36)
      .toUpperCase()}`.slice(0, 12),
    admin.publicKey(),
  );
  const sac = asset.contractId(PASSPHRASE);
  try {
    await submitAs(admin, Operation.createStellarAssetContract({ asset }));
  } catch {
    // Already deployed by a previous run — the SAC id is deterministic.
  }
  await submitAs(
    admin,
    Operation.invokeContractFunction({
      contract: sac,
      function: "mint",
      args: [
        nativeToScVal(Address.fromString(WALLET), { type: "address" }),
        nativeToScVal(1000n * XLM, { type: "i128" }),
      ],
    }),
  );
  return sac;
}

/** Attest `contract` in the evidence registry as `publisherHex` (attestor-signed). */
async function attest(contract: string, publisherHex: string): Promise<string> {
  const latest = await server.getLatestLedger();
  return submitAs(
    attestor,
    Operation.invokeContractFunction({
      contract: EVIDENCE_REGISTRY,
      function: "upsert_with_publisher",
      args: [
        nativeToScVal(Address.fromString(contract), { type: "address" }),
        nativeToScVal(Buffer.alloc(32, 0x33), { type: "bytes" }),
        nativeToScVal(Buffer.from(publisherHex, "hex"), { type: "bytes" }),
        nativeToScVal(latest.sequence + 20_000, { type: "u32" }),
      ],
    }),
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- scenarios

async function main() {
  const adminSigner = walletSigner(admin.secret());
  // Destination: the admin account (funded; the EVID issuer, so it can receive
  // EVID without a trustline and XLM without existing-account checks).
  const dest = admin.publicKey();
  const fund = await fundWallet(300n);
  record({ step: "fund-wallet", wallet: WALLET, hash: fund });
  const EVID_SAC = await deployHeldToken();
  record({
    step: "deploy + mint EVID (a second token the wallet holds; unattested)",
    contractId: EVID_SAC,
  });

  const w = await walletClient(adminSigner);
  let r: Outcome;

  // ===== #401 signer lifecycle ==============================================
  const second = Keypair.random();
  r = await w.run("add_signer", { signer: ed25519Signer(second, undefined) });
  record({
    issue: 401,
    step: "add second admin signer (stand-in for a second passkey)",
    signer: second.publicKey(),
    ...outcome(r),
  });

  r = await invokeAsWallet(
    NATIVE_SAC,
    "transfer",
    transferArgs(dest, 1n * XLM),
    walletSigner(second.secret()),
  );
  record({
    issue: 401,
    step: "transfer signed ONLY by the new signer",
    expected: "success",
    ...outcome(r),
  });

  r = await w.run("remove_signer", { signer_key: key("Ed25519", second.rawPublicKey()) });
  record({ issue: 401, step: "revoke the second signer on-chain", ...outcome(r) });

  r = await invokeAsWallet(
    NATIVE_SAC,
    "transfer",
    transferArgs(dest, 1n * XLM),
    walletSigner(second.secret()),
  );
  record({
    issue: 401,
    step: "transfer signed by the REVOKED signer",
    expected: "rejected (MissingContext #110: no live signer covers the context)",
    ...outcome(r),
  });

  r = await w.run("remove_signer", { signer_key: key("Ed25519", admin.rawPublicKey()) });
  record({
    issue: 401,
    step: "attempt to remove the LAST admin signer",
    expected: "rejected by the wallet contract (LastAdminSigner #103)",
    ...outcome(r),
  });

  // ===== #399 spending-limit safety rules ===================================
  const spend = await deployPolicy(SPENDING_LIMIT_WASM, {
    dailyLimitStroops: (50n * XLM).toString(),
    windowSeconds: 3600,
    rules: {
      maxSingleTransfer: [{ token: NATIVE_SAC, amountBaseUnits: (20n * XLM).toString() }],
      allowedTokens: [NATIVE_SAC],
    },
  });
  record({
    issue: 399,
    step: "deploy spending-limit instance (50 XLM/h, max single 20 XLM, allowlist [XLM])",
    wasm: SPENDING_LIMIT_WASM,
    ...spend,
  });
  r = await w.run("add_signer", { signer: policySigner(spend.contractId) });
  record({ issue: 399, step: "attach policy (standalone signer, admin-approved)", ...outcome(r) });
  const ruled = Keypair.random();
  r = await w.run("add_signer", {
    signer: ed25519Signer(
      ruled,
      new Map([
        [NATIVE_SAC, [spend.contractId]],
        [EVID_SAC, [spend.contractId]],
      ]),
    ),
  });
  record({
    issue: 399,
    step: "add key limited by the policy on XLM + EVID",
    signer: ruled.publicKey(),
    ...outcome(r),
  });
  const ruledSigner = walletSigner(ruled.secret(), [spend.contractId]);
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 10n * XLM), ruledSigner);
  record({
    issue: 399,
    step: "10 XLM transfer (under single cap, under window)",
    expected: "success",
    ...outcome(r),
  });
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 25n * XLM), ruledSigner);
  record({
    issue: 399,
    step: "25 XLM transfer (over the 20 XLM single cap)",
    expected: "rejected SingleTransferExceeded (#7)",
    ...outcome(r),
  });
  r = await invokeAsWallet(EVID_SAC, "transfer", transferArgs(dest, 1n * XLM), ruledSigner);
  record({
    issue: 399,
    step: "EVID transfer (token not on the allowlist)",
    expected: "rejected TokenNotAllowed (#6)",
    ...outcome(r),
  });
  // NOTE: a policy that is BOTH a required co-signer (SignerLimits) and a
  // Signature::Policy map entry — the shape the SDK session signer produces —
  // is invoked in both __check_auth passes, so the cumulative window counts
  // each spend twice (10 XLM above consumed 20 of the 50 XLM window).
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 10n * XLM), ruledSigner);
  record({
    issue: 399,
    step: "10 XLM transfer (window: 20 + 20 = 40 of 50 as counted)",
    expected: "success",
    ...outcome(r),
  });
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 10n * XLM), ruledSigner);
  record({
    issue: 399,
    step: "10 XLM transfer (would exceed the 50 XLM window as counted)",
    expected: "rejected NotAllowed (#1)",
    ...outcome(r),
  });

  // ===== #394 agent key with token budget ====================================
  const tokenPolicy = await deployPolicy(TOKEN_SPENDING_WASM, {
    token: NATIVE_SAC,
    dailyLimitBaseUnits: (5n * XLM).toString(),
    windowSeconds: 3600,
  });
  record({
    issue: 394,
    step: "deploy token-spending-limit instance (5 XLM / h, bound to XLM)",
    wasm: TOKEN_SPENDING_WASM,
    ...tokenPolicy,
  });
  r = await w.run("add_signer", { signer: policySigner(tokenPolicy.contractId) });
  record({ issue: 394, step: "attach budget policy (admin-approved)", ...outcome(r) });
  const agent = Keypair.random();
  const expiresAt = Math.floor(Date.now() / 1000) + 150;
  const agentLimits = new Map([
    [NATIVE_SAC, [tokenPolicy.contractId]],
    [EVID_SAC, [tokenPolicy.contractId]],
  ]);
  // Approval bypass check: the agent key cannot add itself — only the admin can.
  const wAgent = await walletClient(walletSigner(agent.secret()));
  r = await wAgent.run("add_signer", { signer: ed25519Signer(agent, agentLimits, expiresAt) });
  record({
    issue: 394,
    step: "mint attempt signed by the agent key itself (no admin/passkey approval)",
    expected: "rejected (MissingContext #110)",
    ...outcome(r),
  });
  r = await w.run("add_signer", { signer: ed25519Signer(agent, agentLimits, expiresAt) });
  record({
    issue: 394,
    step: "mint agent key (admin-approved addEd25519 with the policy as required co-signer, 150s expiry)",
    agent: agent.publicKey(),
    expiresAt,
    ...outcome(r),
  });
  const agentSigner = walletSigner(agent.secret(), [tokenPolicy.contractId]);
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 2n * XLM), agentSigner, {
    repeatSimulations: 3,
  });
  record({
    issue: 394,
    step: "agent pays 2 XLM (under budget) after 3 re-simulations",
    expected: "success; simulations consume no budget",
    ...outcome(r),
  });
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 4n * XLM), agentSigner);
  record({
    issue: 394,
    step: "agent pays 4 XLM (2+4 > 5 budget)",
    expected: "rejected by the policy (#1)",
    ...outcome(r),
  });
  r = await invokeAsWallet(EVID_SAC, "transfer", transferArgs(dest, 1n * XLM), agentSigner);
  record({
    issue: 394,
    step: "agent pays 1 EVID (wrong token: the budget is bound to XLM)",
    expected: "rejected by the token policy (#1)",
    ...outcome(r),
  });
  const waitMs = expiresAt * 1000 - Date.now() + 10_000;
  if (waitMs > 0) await sleep(waitMs);
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 1n * XLM), agentSigner);
  record({
    issue: 394,
    step: "agent pays 1 XLM after expiry",
    expected: "rejected SignerExpired (#102)",
    ...outcome(r),
  });
  r = await w.run("remove_signer", { signer_key: key("Ed25519", agent.rawPublicKey()) });
  record({ issue: 394, step: "revoke the agent key (remote kill)", ...outcome(r) });

  // ===== #398 verified provenance ============================================
  const strict = await deployPolicy(VERIFIED_RECIPIENT_WASM, {
    registry: EVIDENCE_REGISTRY,
    mode: "strict",
  });
  record({
    issue: 398,
    step: "deploy verified-recipient STRICT instance",
    wasm: VERIFIED_RECIPIENT_WASM,
    registry: EVIDENCE_REGISTRY,
    ...strict,
  });
  r = await w.run("add_signer", { signer: policySigner(strict.contractId) });
  record({ issue: 398, step: "attach strict policy (admin-approved)", ...outcome(r) });
  const prov = Keypair.random();
  r = await w.run("add_signer", {
    signer: ed25519Signer(
      prov,
      new Map([
        [NATIVE_SAC, [strict.contractId]],
        [EVID_SAC, [strict.contractId]],
      ]),
    ),
  });
  record({
    issue: 398,
    step: "add key gated by the strict policy on XLM + EVID",
    signer: prov.publicKey(),
    ...outcome(r),
  });
  const provSigner = walletSigner(prov.secret(), [strict.contractId]);
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 1n * XLM), provSigner, {
    repeatSimulations: 3,
  });
  record({
    issue: 398,
    step: "strict: transfer through an ATTESTED contract (XLM SAC), 3 re-simulations",
    expected: "success",
    ...outcome(r),
  });
  r = await invokeAsWallet(EVID_SAC, "transfer", transferArgs(dest, 1n * XLM), provSigner);
  record({
    issue: 398,
    step: "strict: transfer through an UNATTESTED contract (EVID SAC)",
    expected: "rejected NotAllowed (#1)",
    ...outcome(r),
  });

  const trustedId = env("TRUSTED_PUBLISHER_ID_HEX");
  const untrustedId = env("UNTRUSTED_PUBLISHER_ID_HEX");
  const att = await attest(EVID_SAC, untrustedId);
  record({
    issue: 398,
    step: "attest EVID SAC in the evidence registry, attributed to an UNTRUSTED publisher",
    hash: att,
    publisher: untrustedId,
  });
  const trusted = await deployPolicy(VERIFIED_RECIPIENT_WASM, {
    registry: EVIDENCE_REGISTRY,
    mode: "trusted_publishers",
    trustedPublisherIds: [trustedId],
  });
  record({
    issue: 398,
    step: "deploy verified-recipient TRUSTED-PUBLISHERS instance",
    trustedPublisherIds: [trustedId],
    ...trusted,
  });
  r = await w.run("add_signer", { signer: policySigner(trusted.contractId) });
  record({ issue: 398, step: "attach trusted-publishers policy", ...outcome(r) });
  const tp = Keypair.random();
  r = await w.run("add_signer", {
    signer: ed25519Signer(
      tp,
      new Map([
        [NATIVE_SAC, [trusted.contractId]],
        [EVID_SAC, [trusted.contractId]],
      ]),
    ),
  });
  record({
    issue: 398,
    step: "add key gated by the trusted-publishers policy",
    signer: tp.publicKey(),
    ...outcome(r),
  });
  const tpSigner = walletSigner(tp.secret(), [trusted.contractId]);
  r = await invokeAsWallet(NATIVE_SAC, "transfer", transferArgs(dest, 1n * XLM), tpSigner);
  record({
    issue: 398,
    step: "trusted: XLM SAC attested BY the trusted publisher",
    expected: "success",
    ...outcome(r),
  });
  r = await invokeAsWallet(EVID_SAC, "transfer", transferArgs(dest, 1n * XLM), tpSigner);
  record({
    issue: 398,
    step: "trusted: EVID SAC attested (verified!) by an UNTRUSTED publisher",
    expected: "rejected UntrustedPublisher (#6)",
    ...outcome(r),
  });

  // Registry unavailable: a strict instance bound to an address with no contract.
  const ghostRegistry = Address.contract(Buffer.from(Keypair.random().rawPublicKey())).toString();
  const bricked = await deployPolicy(VERIFIED_RECIPIENT_WASM, {
    registry: ghostRegistry,
    mode: "strict",
  });
  record({
    issue: 398,
    step: "deploy strict instance bound to a NON-EXISTENT registry",
    registry: ghostRegistry,
    ...bricked,
  });
  r = await w.run("add_signer", { signer: policySigner(bricked.contractId) });
  record({ issue: 398, step: "attach it (standalone)", ...outcome(r) });
  const br = Keypair.random();
  r = await w.run("add_signer", {
    signer: ed25519Signer(br, new Map([[NATIVE_SAC, [bricked.contractId]]])),
  });
  record({ issue: 398, step: "add key gated by the registry-less policy", ...outcome(r) });
  r = await invokeAsWallet(
    NATIVE_SAC,
    "transfer",
    transferArgs(dest, 1n * XLM),
    walletSigner(br.secret(), [bricked.contractId]),
  );
  record({
    issue: 398,
    step: "registry unavailable: gated transfer",
    expected: "fails closed",
    ...outcome(r),
  });
  r = await w.run("remove_signer", { signer_key: key("Policy", bricked.contractId) });
  record({
    issue: 398,
    step: "RECOVERY: admin detaches the policy WITHOUT the registry / policy's consent",
    expected: "success",
    ...outcome(r),
  });
  r = await w.run("remove_signer", { signer_key: key("Ed25519", br.rawPublicKey()) });
  record({ issue: 398, step: "cleanup: remove the gated key", ...outcome(r) });

  // Detach the remaining policies through the same recovery primitive (#401 policy detach).
  for (const [label, id] of [
    ["spending-limit", spend.contractId],
    ["token-budget", tokenPolicy.contractId],
    ["strict", strict.contractId],
    ["trusted", trusted.contractId],
  ] as const) {
    r = await w.run("remove_signer", { signer_key: key("Policy", id) });
    record({
      issue: 401,
      step: `detach ${label} policy via the kit.remove(SignerKey.Policy) path`,
      policy: id,
      ...outcome(r),
    });
  }
  for (const kp of [ruled, prov, tp]) {
    r = await w.run("remove_signer", { signer_key: key("Ed25519", kp.rawPublicKey()) });
    record({
      issue: 401,
      step: "cleanup: revoke limited key",
      signer: kp.publicKey(),
      ...outcome(r),
    });
  }
  record({ step: "done", evidenceFile: OUT });
}

main().catch((err) => {
  console.error("evidence run failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
