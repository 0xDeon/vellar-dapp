import { describe, expect, it, vi } from "vitest";
import { agentLimits, createSignerActions, type SignerActionDeps } from "./signer-actions";

const SignerKey = {
  Policy: (id: string) => ({ tag: "Policy", id }),
  Ed25519: (pk: string) => ({ tag: "Ed25519", pk }),
  Secp256r1: (k: string) => ({ tag: "Secp256r1", k }),
};
const SignerStore = { Persistent: "P", Temporary: "T" };

function deps() {
  const calls: Record<string, unknown[][]> = {};
  const rec =
    (name: string, ret: unknown = { tx: name }) =>
    async (...args: unknown[]) => {
      (calls[name] ??= []).push(args);
      return ret;
    };
  const kit = {
    createKey: vi.fn(async () => ({ keyId: "new-cred", publicKey: new Uint8Array(65) })),
    addSecp256r1: vi.fn(rec("addSecp256r1")),
    addEd25519: vi.fn(rec("addEd25519")),
    remove: vi.fn(rec("remove")),
    sign: vi.fn(async (tx: unknown) => ({ toXDR: () => `signed:${(tx as { tx: string }).tx}` })),
  };
  const backend = { submitTransaction: vi.fn(async () => ({ hash: "txhash" })) };
  const d: SignerActionDeps = {
    kit,
    backend,
    network: "testnet",
    appName: "Vellar Wallet",
    SignerKey,
    SignerStore,
  };
  return { d, kit, backend, calls };
}

describe("addPasskeySigner", () => {
  it("registers a new credential, then the EXISTING passkey signs add_signer for a durable unlimited peer", async () => {
    const { d, kit, backend, calls } = deps();
    const res = await createSignerActions(d).addPasskeySigner("phone");
    expect(kit.createKey).toHaveBeenCalledWith("Vellar Wallet", "phone");
    // Persistent + unlimited (limits undefined) + no expiration: a recovery
    // passkey must be a durable admin peer or it cannot recover the account.
    expect(calls.addSecp256r1).toEqual([
      ["new-cred", new Uint8Array(65), undefined, SignerStore.Persistent, undefined],
    ]);
    expect(kit.sign).toHaveBeenCalledWith({ tx: "addSecp256r1" });
    expect(backend.submitTransaction).toHaveBeenCalledWith({
      signedXdr: "signed:addSecp256r1",
      network: "testnet",
    });
    expect(res).toEqual({ hash: "txhash", keyId: "new-cred" });
  });

  it("does not submit anything when the passkey approval is refused", async () => {
    const { d, kit, backend } = deps();
    kit.sign.mockRejectedValueOnce(new Error("NotAllowedError"));
    await expect(createSignerActions(d).addPasskeySigner("phone")).rejects.toThrow(
      "NotAllowedError",
    );
    expect(backend.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("addAgentKey", () => {
  it("adds a policy-limited Ed25519 signer with the grants as required co-signers", async () => {
    const { d, calls, backend } = deps();
    await createSignerActions(d).addAgentKey({
      publicKey: "GAGENT",
      grants: [{ token: "CTOKEN", policies: ["CPOLICY"] }],
      expirationSeconds: 1_800_000_000,
      store: "persistent",
    });
    const [publicKey, limits, store, expiration] = calls.addEd25519![0]!;
    expect(publicKey).toBe("GAGENT");
    expect(limits).toEqual(new Map([["CTOKEN", [{ tag: "Policy", id: "CPOLICY" }]]]));
    expect(store).toBe(SignerStore.Persistent);
    expect(expiration).toBe(1_800_000_000);
    expect(backend.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("refuses an unbounded grant (no policies) before any prompt", async () => {
    const { d, kit } = deps();
    await expect(
      createSignerActions(d).addAgentKey({
        publicKey: "GAGENT",
        grants: [{ token: "CTOKEN", policies: [] }],
        store: "persistent",
      }),
    ).rejects.toThrow(/unbounded/);
    expect(kit.addEd25519).not.toHaveBeenCalled();
    expect(kit.sign).not.toHaveBeenCalled();
    expect(() => agentLimits(d, [])).toThrow(/at least one token grant/);
  });
});

describe("removeSigner", () => {
  it.each([
    ["Policy", "CPOLICY", { tag: "Policy", id: "CPOLICY" }],
    ["Ed25519", "GKEY", { tag: "Ed25519", pk: "GKEY" }],
    ["Secp256r1", "cred", { tag: "Secp256r1", k: "cred" }],
  ] as const)("removes a %s signer by its exact SignerKey", async (kind, value, expected) => {
    const { d, calls, backend } = deps();
    const res = await createSignerActions(d).removeSigner({ kind, value });
    expect(calls.remove).toEqual([[expected]]);
    expect(backend.submitTransaction).toHaveBeenCalledWith({
      signedXdr: "signed:remove",
      network: "testnet",
    });
    expect(res.hash).toBe("txhash");
  });
});
