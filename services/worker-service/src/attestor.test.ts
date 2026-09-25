import { describe, expect, it, vi } from "vitest";
import { publisherIdFor } from "@vellar/service-kit";
import { createAttestor, type AttestationSubmitter } from "./attestor";
import { createMemoryJobStore } from "./memory-job-store";
import { ArtifactResolveError, type ContractArtifactResolver } from "./resolver";
import type { VerificationOutcome } from "./verify";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

function fakeSubmitter(over: Partial<AttestationSubmitter> = {}) {
  const calls = {
    upserts: [] as Array<[string, string, number]>,
    attributed: [] as Array<[string, string, string, number]>,
    revokes: [] as string[],
  };
  const submitter: AttestationSubmitter = {
    async upsert(contract, hash, expires) {
      calls.upserts.push([contract, hash, expires]);
    },
    async upsertWithPublisher(contract, hash, publisher, expires) {
      calls.attributed.push([contract, hash, publisher, expires]);
    },
    async revoke(contract) {
      calls.revokes.push(contract);
    },
    async isAttested() {
      return true;
    },
    async currentLedger() {
      return 1000;
    },
    ...over,
  };
  return { submitter, calls };
}

const verified = (hash: string | null = HASH_A): VerificationOutcome => ({
  status: "verified",
  ...(hash === null ? {} : { outputHash: hash }),
  statusDetail: "ok",
  log: "ok",
});
const failed = (): VerificationOutcome => ({
  status: "failed",
  statusDetail: "mismatch",
  log: "mismatch",
});

describe("attestor.reportOutcome", () => {
  it("upserts on verified with the rebuilt hash and now+ttl expiry", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter, ttlLedgers: 500 });
    await attestor.reportOutcome("CCONTRACT", verified());
    expect(calls.upserts).toEqual([["CCONTRACT", HASH_A, 1500]]);
    expect(calls.revokes).toEqual([]);
  });

  it("attributes the attestation to the repo owner when the source has a repoUrl", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter, ttlLedgers: 500 });
    await attestor.reportOutcome("CCONTRACT", verified(), {
      repoUrl: "https://github.com/Vellar-Wallet/vellar-dapp",
    });
    expect(calls.upserts).toEqual([]);
    expect(calls.attributed).toEqual([
      ["CCONTRACT", HASH_A, publisherIdFor("github.com/vellar-wallet"), 1500],
    ]);
  });

  it("writes an UNattributed attestation when the source cannot be attributed", async () => {
    // An upload-sourced verification (no repoUrl) or a repoUrl with no owner
    // segment is verified but never trusted-publisher-eligible.
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter, ttlLedgers: 500 });
    await attestor.reportOutcome("CA", verified(), {});
    await attestor.reportOutcome("CB", verified(), { repoUrl: "https://github.com/" });
    expect(calls.attributed).toEqual([]);
    expect(calls.upserts).toEqual([
      ["CA", HASH_A, 1500],
      ["CB", HASH_A, 1500],
    ]);
  });

  it("skips a verified outcome without an outputHash (never attests an empty claim)", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter });
    await attestor.reportOutcome("CCONTRACT", verified(null));
    expect(calls.upserts).toEqual([]);
  });

  it("revokes on failed when currently attested", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter });
    await attestor.reportOutcome("CCONTRACT", failed());
    expect(calls.revokes).toEqual(["CCONTRACT"]);
  });

  it("does not pay for a revoke when the contract was never attested", async () => {
    const { submitter, calls } = fakeSubmitter({ isAttested: async () => false });
    const attestor = createAttestor({ submitter });
    await attestor.reportOutcome("CCONTRACT", failed());
    expect(calls.revokes).toEqual([]);
  });

  it("swallows submitter errors — the pipeline must never be affected", async () => {
    const { submitter } = fakeSubmitter({
      upsert: async () => {
        throw new Error("chain down");
      },
    });
    const log = { info: vi.fn(), error: vi.fn() };
    const attestor = createAttestor({ submitter, log });
    await expect(attestor.reportOutcome("CCONTRACT", verified())).resolves.toBeUndefined();
    expect(log.error).toHaveBeenCalled();
  });
});

describe("attestor.runUpgradeSweep", () => {
  function store(entries: Array<{ contractId: string; outputHash: string }>) {
    return { listLatestVerified: async () => entries };
  }
  function resolverReturning(map: Record<string, string | ArtifactResolveError>) {
    const resolver: ContractArtifactResolver = {
      async resolveDeployedHash(contractId) {
        const value = map[contractId];
        if (value instanceof ArtifactResolveError) throw value;
        if (value === undefined) throw new ArtifactResolveError("missing", "not_found");
        return value;
      },
    };
    return resolver;
  }

  it("revokes when the live hash drifted from the attested one", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter });
    const revoked = await attestor.runUpgradeSweep(
      store([{ contractId: "CUPGRADED", outputHash: HASH_A }]),
      resolverReturning({ CUPGRADED: HASH_B }),
    );
    expect(revoked).toBe(1);
    expect(calls.revokes).toEqual(["CUPGRADED"]);
  });

  it("keeps attestations whose live hash still matches", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter });
    const revoked = await attestor.runUpgradeSweep(
      store([{ contractId: "CSTABLE", outputHash: HASH_A }]),
      resolverReturning({ CSTABLE: HASH_A }),
    );
    expect(revoked).toBe(0);
    expect(calls.revokes).toEqual([]);
  });

  it("revokes when the contract vanished (not_found) but skips transient rpc errors", async () => {
    const { submitter, calls } = fakeSubmitter();
    const attestor = createAttestor({ submitter });
    const revoked = await attestor.runUpgradeSweep(
      store([
        { contractId: "CGONE", outputHash: HASH_A },
        { contractId: "CFLAKY", outputHash: HASH_A },
      ]),
      resolverReturning({
        CGONE: new ArtifactResolveError("gone", "not_found"),
        CFLAKY: new ArtifactResolveError("rpc down", "rpc_error"),
      }),
    );
    expect(revoked).toBe(1);
    expect(calls.revokes).toEqual(["CGONE"]);
  });

  it("skips contracts with no live attestation (nothing to revoke)", async () => {
    const { submitter, calls } = fakeSubmitter({ isAttested: async () => false });
    const attestor = createAttestor({ submitter });
    const revoked = await attestor.runUpgradeSweep(
      store([{ contractId: "CUPGRADED", outputHash: HASH_A }]),
      resolverReturning({ CUPGRADED: HASH_B }),
    );
    expect(revoked).toBe(0);
    expect(calls.revokes).toEqual([]);
  });
});

describe("memory store listLatestVerified", () => {
  it("returns the latest terminal record per contract, only when verified", async () => {
    const store = createMemoryJobStore();
    const job = (contractId: string) => ({
      contractId,
      sourceType: "repo" as const,
      repoUrl: "https://example.com/r.git",
      commitHash: "c".repeat(40),
      toolchainVersion: "t",
      buildFlags: [],
    });

    // CVERIFIED: single verified run → listed.
    store.submit("r1", job("CVERIFIED"));
    await store.claimSubmitted(1);
    await store.complete("r1", {
      status: "verified",
      outputHash: HASH_A,
      statusDetail: "",
      log: "",
    });

    // CSUPERSEDED: verified, then a LATER failed run → not listed.
    store.submit("r2", job("CSUPERSEDED"));
    await store.claimSubmitted(1);
    await store.complete("r2", {
      status: "verified",
      outputHash: HASH_A,
      statusDetail: "",
      log: "",
    });
    await new Promise((r) => setTimeout(r, 2));
    store.submit("r3", job("CSUPERSEDED"));
    await store.claimSubmitted(1);
    await store.complete("r3", { status: "failed", statusDetail: "", log: "" });

    // CPENDING: still submitted → not listed.
    store.submit("r4", job("CPENDING"));

    const listed = await store.listLatestVerified(10);
    expect(listed).toEqual([{ contractId: "CVERIFIED", outputHash: HASH_A }]);
  });
});
