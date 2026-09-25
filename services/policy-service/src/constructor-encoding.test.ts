import { Address, scValToNative, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import { constructorScVals, provenanceModeScVal, safetyRulesScVal } from "./deploy";
import { ATTESTATION_REGISTRY_ID } from "./templates";

// The ScVal shapes the policy contracts' constructors decode
// (`SafetyRules` struct, `ProvenanceMode` enum). A wrong encoding fails the
// deploy simulation, but the tests here pin the shape so a template change
// can't silently ship an argument the contract reads as something else.

const WALLET = "CAFK7NMQOT7G2SKMREDUII3EOK4APIY54WIK6CVGY72XWFE76YFRDF67";
const TOKEN_A = "CBZVS2ETJKCIMRRWUHTZFVMWDACJNYUZ54JIXUJCHXNBFNXELKTSWHGP";
const TOKEN_B = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const REGISTRY = ATTESTATION_REGISTRY_ID;

describe("safetyRulesScVal", () => {
  it("encodes the empty rule set as {allowed_tokens: None, max_single_transfer: {}}", () => {
    const v = safetyRulesScVal(undefined);
    expect(v.switch()).toBe(xdr.ScValType.scvMap());
    const entries = v.map()!;
    expect(entries.map((e) => e.key().sym().toString())).toEqual([
      "allowed_tokens",
      "max_single_transfer",
    ]);
    expect(entries[0]!.val().switch()).toBe(xdr.ScValType.scvVoid());
    expect(entries[1]!.val().map()).toEqual([]);
  });

  it("encodes caps as an address-keyed i128 map sorted by contract id, and the allowlist as a vec", () => {
    const v = safetyRulesScVal({
      maxSingleTransfer: [
        { token: TOKEN_B, amountBaseUnits: "7" },
        { token: TOKEN_A, amountBaseUnits: "5" },
      ],
      allowedTokens: [TOKEN_B, TOKEN_A],
    });
    const native = scValToNative(v) as {
      allowed_tokens: string[];
      max_single_transfer: Map<string, bigint>;
    };
    expect(native.allowed_tokens).toEqual([TOKEN_B, TOKEN_A]);
    const caps = v.map()![1]!.val().map()!;
    const keys = caps.map((e) => Address.fromScVal(e.key()).toString());
    // Host maps must be key-sorted; TOKEN_A's raw bytes sort before TOKEN_B's.
    expect(keys).toEqual(
      [TOKEN_A, TOKEN_B].sort((a, b) =>
        Buffer.compare(Address.fromString(a).toBuffer(), Address.fromString(b).toBuffer()),
      ),
    );
    expect(caps.map((e) => scValToNative(e.val()))).toEqual(
      keys.map((k) => (k === TOKEN_A ? 5n : 7n)),
    );
  });
});

describe("provenanceModeScVal", () => {
  it("encodes Strict as a unit variant and TrustedPublishers as a tuple variant of 32-byte ids", () => {
    const strict = provenanceModeScVal({ registry: REGISTRY, mode: "strict" });
    expect(scValToNative(strict)).toEqual(["Strict"]);
    const id = "ab".repeat(32);
    const trusted = provenanceModeScVal({
      registry: REGISTRY,
      mode: "trusted_publishers",
      trustedPublisherIds: [id],
    });
    const native = scValToNative(trusted) as [string, Buffer[]];
    expect(native[0]).toBe("TrustedPublishers");
    expect(native[1].map((b) => Buffer.from(b).toString("hex"))).toEqual([id]);
  });

  it("refuses a publisher id that is not 32 bytes", () => {
    expect(() =>
      provenanceModeScVal({
        registry: REGISTRY,
        mode: "trusted_publishers",
        trustedPublisherIds: ["abcd"],
      }),
    ).toThrow(/32 bytes/);
  });
});

describe("constructorScVals", () => {
  it("spending-limit: (wallet, i128 limit, u64 window, SafetyRules)", () => {
    const vals = constructorScVals({
      wallet: WALLET,
      constructorArgs: { dailyLimitStroops: "1000000000", windowSeconds: 86400 },
    });
    expect(vals).toHaveLength(4);
    expect(Address.fromScVal(vals[0]!).toString()).toBe(WALLET);
    expect(scValToNative(vals[1]!)).toBe(1000000000n);
    expect(scValToNative(vals[2]!)).toBe(86400n);
    expect(vals[3]!.switch()).toBe(xdr.ScValType.scvMap());
  });

  it("token-spending-limit: (wallet, token, i128 limit, u64 window)", () => {
    const vals = constructorScVals({
      wallet: WALLET,
      constructorArgs: { token: TOKEN_A, dailyLimitBaseUnits: "5", windowSeconds: 3600 },
    });
    expect(vals.map((v) => scValToNative(v))).toEqual([WALLET, TOKEN_A, 5n, 3600n]);
  });

  it("verified-recipient: (wallet, registry, ProvenanceMode)", () => {
    const vals = constructorScVals({
      wallet: WALLET,
      constructorArgs: { registry: REGISTRY, mode: "strict" },
    });
    expect(vals.map((v) => scValToNative(v))).toEqual([WALLET, REGISTRY, ["Strict"]]);
  });
});
