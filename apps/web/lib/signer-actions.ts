import type { AgentPolicyGrant } from "vellar-sdk";
import type { SignerKeyRef } from "./signer-model";

// Signer add/remove WIRING (#401 / #394), extracted from connector-factory the
// same way policy-signer.ts is (RA-6): the code that decides EXACTLY what the
// kit is asked to sign lives here, behind a structural kit interface, so it is
// unit-tested with a fake kit. Every action here is a wallet-admin mutation:
// the kit builds the wallet's add_signer / remove_signer, `kit.sign` runs the
// ONLY passkey prompt, and the signed XDR goes to our backend for submission.
// Nothing in this module is a mutation until that transaction is applied.

export interface SignerKit {
  createKey(appName: string, userName: string): Promise<{ keyId: string; publicKey: Uint8Array }>;
  addSecp256r1(
    keyId: string,
    publicKey: Uint8Array,
    limits: undefined,
    store: unknown,
    expiration?: number,
  ): Promise<unknown>;
  addEd25519(
    publicKey: string,
    limits: Map<string, unknown[]> | undefined,
    store: unknown,
    expiration?: number,
  ): Promise<unknown>;
  remove(signerKey: unknown): Promise<unknown>;
  sign(tx: unknown): Promise<unknown>;
}

export interface SignerActionBackend {
  submitTransaction(req: { signedXdr: string; network: string }): Promise<{ hash: string }>;
}

export interface SignerActionDeps {
  kit: SignerKit;
  backend: SignerActionBackend;
  network: string;
  appName: string;
  /** passkey-kit SignerKey constructors — injected (browser-only module). */
  SignerKey: {
    Policy(id: string): unknown;
    Ed25519(publicKey: string): unknown;
    Secp256r1(keyId: string): unknown;
  };
  /** passkey-kit SignerStore enum — injected (browser-only module). */
  SignerStore: { Persistent: unknown; Temporary: unknown };
}

export interface AddAgentKeyInput {
  publicKey: string;
  grants: AgentPolicyGrant[];
  /** Unix seconds (the contract's unit). */
  expirationSeconds?: number;
  store: "persistent" | "temporary";
}

function toXdr(signed: unknown, fallback: unknown): string {
  const value = signed ?? fallback;
  return typeof value === "string" ? value : (value as { toXDR(): string }).toXDR();
}

export function toSignerKey(deps: Pick<SignerActionDeps, "SignerKey">, key: SignerKeyRef): unknown {
  switch (key.kind) {
    case "Policy":
      return deps.SignerKey.Policy(key.value);
    case "Ed25519":
      return deps.SignerKey.Ed25519(key.value);
    case "Secp256r1":
      return deps.SignerKey.Secp256r1(key.value);
  }
}

/** The agent key's `SignerLimits`: for every granted token contract, the
 * listed policies are REQUIRED co-signers. Never an empty list — an empty
 * co-signer list would grant the token with no policy at all. */
export function agentLimits(
  deps: Pick<SignerActionDeps, "SignerKey">,
  grants: AgentPolicyGrant[],
): Map<string, unknown[]> {
  if (grants.length === 0) throw new Error("An agent key needs at least one token grant.");
  const limits = new Map<string, unknown[]>();
  for (const grant of grants) {
    if (!grant.policies || grant.policies.length === 0) {
      throw new Error(
        `The grant for ${grant.token} has no policy — refusing an unbounded agent key.`,
      );
    }
    limits.set(
      grant.token,
      grant.policies.map((p) => deps.SignerKey.Policy(p)),
    );
  }
  return limits;
}

export function createSignerActions(deps: SignerActionDeps) {
  const { kit, backend, network, SignerStore } = deps;

  async function signAndSubmit(tx: unknown): Promise<{ hash: string }> {
    const signed = await kit.sign(tx);
    return backend.submitTransaction({ signedXdr: toXdr(signed, tx), network });
  }

  return {
    /**
     * Add a second passkey. Step 1 registers a NEW credential in the browser
     * (no chain effect). Step 2 asks the EXISTING connected passkey to sign the
     * wallet's add_signer for it: Persistent, unlimited, non-expiring — a full
     * admin peer, i.e. a recovery passkey. The new passkey is on the account
     * only once the returned transaction is applied.
     */
    async addPasskeySigner(label: string): Promise<{ hash: string; keyId: string }> {
      const created = await kit.createKey(deps.appName, label);
      const tx = await kit.addSecp256r1(
        created.keyId,
        created.publicKey,
        undefined,
        SignerStore.Persistent,
        undefined,
      );
      const { hash } = await signAndSubmit(tx);
      return { hash, keyId: created.keyId };
    },

    /**
     * Mint an agent session key (#394): a policy-limited Ed25519 signer. The
     * limits map is what bounds the key on-chain — the wallet consults every
     * listed policy in `__check_auth` for every authorization on that token.
     */
    async addAgentKey(input: AddAgentKeyInput): Promise<{ hash: string }> {
      const limits = agentLimits(deps, input.grants);
      const store = input.store === "temporary" ? SignerStore.Temporary : SignerStore.Persistent;
      const tx = await kit.addEd25519(input.publicKey, limits, store, input.expirationSeconds);
      return signAndSubmit(tx);
    },

    /** On-chain removal of any signer kind (remote kill for agent keys,
     * revocation for passkeys/device sessions, detach for policies). */
    async removeSigner(key: SignerKeyRef): Promise<{ hash: string }> {
      const tx = await kit.remove(toSignerKey(deps, key));
      return signAndSubmit(tx);
    },
  };
}
