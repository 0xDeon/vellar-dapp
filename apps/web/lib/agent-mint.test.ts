import { describe, expect, it, vi } from "vitest";
import {
  initialMintState,
  isMintBusy,
  mintReducer,
  runMint,
  type MintConfig,
  type MintEffects,
  type MintEvent,
  type MintState,
} from "./agent-mint";

const config: MintConfig = {
  token: "CTOKEN",
  tokenSymbol: "XLM",
  amountBaseUnits: "100000000",
  windowSeconds: 86_400,
  expiresAtSeconds: 1_800_000_000,
  network: "testnet",
};
const key = { publicKey: "GAGENT", secret: "SSECRET" };

function play(events: MintEvent[], from: MintState = initialMintState): MintState {
  return events.reduce(mintReducer, from);
}

const happyPath: MintEvent[] = [
  { type: "START", config },
  { type: "KEY_CREATED", key },
  { type: "POLICY_DEPLOYED", policyContractId: "CPOLICY" },
  { type: "PASSKEY_APPROVED", for: "attach-policy" },
  { type: "POLICY_ATTACHED", hash: "attachtx" },
  { type: "SIGNER_ADDED", hash: "addtx" },
  { type: "CONFIRMED" },
];

describe("mintReducer", () => {
  it("walks the full sequence to success and carries the secret for a one-time reveal", () => {
    const steps = happyPath.map((_, i) => play(happyPath.slice(0, i + 1)).step);
    expect(steps).toEqual([
      "creating-key",
      "policy-creation",
      "awaiting-passkey-approval",
      "attaching-policy",
      "adding-signer",
      "confirming",
      "success",
    ]);
    const done = play(happyPath);
    expect(done).toMatchObject({
      step: "success",
      publicKey: "GAGENT",
      secret: "SSECRET",
      policyContractId: "CPOLICY",
      attachTxHash: "attachtx",
      addSignerTxHash: "addtx",
    });
  });

  it("DISMISS_SECRET drops the secret and nothing can bring it back", () => {
    const done = play(happyPath);
    const dismissed = mintReducer(done, { type: "DISMISS_SECRET" });
    expect(dismissed.step).toBe("success");
    expect("secret" in dismissed && dismissed.secret).toBeFalsy();
    // Replaying any event on the dismissed state never re-exposes it.
    for (const e of happyPath) {
      const s = mintReducer(dismissed, e);
      expect("secret" in s && s.secret).toBeFalsy();
    }
  });

  it("ignores out-of-order events (a late effect cannot corrupt the flow)", () => {
    expect(play([{ type: "CONFIRMED" }])).toEqual(initialMintState);
    expect(
      play([
        { type: "START", config },
        { type: "SIGNER_ADDED", hash: "x" },
      ]).step,
    ).toBe("creating-key");
    // Approval for the wrong prompt is not an approval.
    const awaiting = play(happyPath.slice(0, 3));
    expect(mintReducer(awaiting, { type: "PASSKEY_APPROVED", for: "add-signer" })).toBe(awaiting);
  });

  it("the passkey prompt cannot be skipped: no path from policy-creation to attaching-policy without approval", () => {
    const deployed = play(happyPath.slice(0, 3));
    expect(deployed.step).toBe("awaiting-passkey-approval");
    expect(mintReducer(deployed, { type: "POLICY_ATTACHED", hash: "h" })).toBe(deployed);
  });

  it.each([
    ["creating-key", 1],
    ["policy-creation", 2],
    ["attaching-policy", 4],
    ["adding-signer", 5],
  ] as const)(
    "FAIL at %s records the stage; the signer is not reported as existing",
    (stage, n) => {
      const s = mintReducer(play(happyPath.slice(0, n)), { type: "FAIL", stage, message: "boom" });
      expect(s).toMatchObject({ step: "error", stage, message: "boom", signerMayExist: false });
    },
  );

  it("FAIL while confirming reports that the agent signer may already exist on-chain", () => {
    const s = mintReducer(play(happyPath.slice(0, 6)), {
      type: "FAIL",
      stage: "confirming",
      message: "timeout",
    });
    expect(s).toMatchObject({ step: "error", signerMayExist: true, policyContractId: "CPOLICY" });
    // The error state never carries key material.
    expect(JSON.stringify(s)).not.toContain("SSECRET");
  });

  it("RESET recovers from error and from success", () => {
    const err = mintReducer(play(happyPath.slice(0, 2)), {
      type: "FAIL",
      stage: "policy-creation",
      message: "x",
    });
    expect(mintReducer(err, { type: "RESET" })).toEqual(initialMintState);
    expect(mintReducer(play(happyPath), { type: "RESET" })).toEqual(initialMintState);
  });

  it("isMintBusy is true only mid-flight", () => {
    expect(isMintBusy(initialMintState)).toBe(false);
    expect(isMintBusy(play(happyPath.slice(0, 3)))).toBe(true);
    expect(isMintBusy(play(happyPath))).toBe(false);
  });
});

function effects(over: Partial<MintEffects> = {}) {
  const order: string[] = [];
  const e: MintEffects = {
    generateKey: vi.fn(async () => {
      order.push("generateKey");
      return key;
    }),
    generatePolicy: vi.fn(async () => {
      order.push("generatePolicy");
      return { id: "pol-1" } as never;
    }),
    simulateDeploy: vi.fn(async () => {
      order.push("simulate");
      return { ok: true };
    }),
    deployInstance: vi.fn(async () => {
      order.push("deploy");
      return { contractId: "CPOLICY" };
    }),
    attachPolicy: vi.fn(async () => {
      order.push("attach");
      return { hash: "attachtx" };
    }),
    recordDeployment: vi.fn(async () => {
      order.push("record");
    }),
    addAgentKey: vi.fn(async () => {
      order.push("addAgentKey");
      return { hash: "addtx" };
    }),
    confirm: vi.fn(async () => {
      order.push("confirm");
    }),
    ...over,
  };
  return { e, order };
}

describe("runMint", () => {
  it("runs deploy → attach (passkey) → add signer (passkey) → confirm and ends in success", async () => {
    const { e, order } = effects();
    const events: MintEvent[] = [];
    await runMint(config, { effects: e, wallet: "CWALLET", dispatch: (ev) => events.push(ev) });
    expect(order).toEqual([
      "generateKey",
      "generatePolicy",
      "simulate",
      "deploy",
      "attach",
      "record",
      "addAgentKey",
      "confirm",
    ]);
    expect(e.addAgentKey).toHaveBeenCalledWith({
      publicKey: "GAGENT",
      token: "CTOKEN",
      policyContractId: "CPOLICY",
      expiresAtSeconds: 1_800_000_000,
    });
    const final = events.reduce(mintReducer, initialMintState);
    expect(final.step).toBe("success");
  });

  it("stops before any passkey prompt when the deploy simulation fails", async () => {
    const { e } = effects({
      simulateDeploy: vi.fn(async () => ({ ok: false, error: "bad budget" })),
    });
    const events: MintEvent[] = [];
    await runMint(config, { effects: e, wallet: "CWALLET", dispatch: (ev) => events.push(ev) });
    expect(e.attachPolicy).not.toHaveBeenCalled();
    expect(e.addAgentKey).not.toHaveBeenCalled();
    expect(events.reduce(mintReducer, initialMintState)).toMatchObject({
      step: "error",
      stage: "policy-creation",
      message: "bad budget",
    });
  });

  it("a refused passkey approval for the attach fails at attaching-policy and never adds the signer", async () => {
    const { e } = effects({
      attachPolicy: vi.fn(async () => {
        throw new Error("passkey cancelled");
      }),
    });
    const events: MintEvent[] = [];
    await runMint(config, { effects: e, wallet: "CWALLET", dispatch: (ev) => events.push(ev) });
    expect(e.addAgentKey).not.toHaveBeenCalled();
    expect(events.reduce(mintReducer, initialMintState)).toMatchObject({
      step: "error",
      stage: "attaching-policy",
      signerMayExist: false,
    });
  });

  it("a confirmation timeout reports the signer may exist so the operator can revoke", async () => {
    const { e } = effects({
      confirm: vi.fn(async () => {
        throw new Error("not final");
      }),
    });
    const events: MintEvent[] = [];
    await runMint(config, { effects: e, wallet: "CWALLET", dispatch: (ev) => events.push(ev) });
    expect(events.reduce(mintReducer, initialMintState)).toMatchObject({
      step: "error",
      stage: "confirming",
      signerMayExist: true,
    });
  });

  it("error copy goes through the redaction hook", async () => {
    const { e } = effects({
      deployInstance: vi.fn(async () => {
        throw new Error("leak SSECRET");
      }),
    });
    const events: MintEvent[] = [];
    await runMint(config, {
      effects: e,
      wallet: "CWALLET",
      dispatch: (ev) => events.push(ev),
      errorMessage: () => "redacted",
    });
    expect(events.reduce(mintReducer, initialMintState)).toMatchObject({ message: "redacted" });
  });
});
