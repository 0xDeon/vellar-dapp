import { describe, expect, it } from "vitest";
import { createPolicyClient, PolicyApiError } from "vellar-sdk";
import {
  Address,
  Keypair,
  nativeToScVal,
  Operation,
  TransactionBuilder,
  xdr,
  Account,
} from "@stellar/stellar-sdk";
import { buildServer, createMemoryPolicyRepository } from "./server";

// SEAM-CROSSING integration tests (security-audit.md RA-11-E / blocker #5):
// Verifies that external vellar-sdk correctly interacts with the real
// policy-service buildServer across all documented /policies/deploy outcomes:
//   - 200: Policy successfully attached on-chain and marked deployed
//   - 422: attach_mismatch (unrelated/spoofed attach tx) -> terminal PolicyApiError (retryable = false)
//   - 422: no_instance (attach attempted before instance deployed) -> terminal PolicyApiError (retryable = false)
//   - 503: attach_unconfirmed (RPC pending or unreachable) -> retryable PolicyApiError (retryable = true)

describe("vellar-sdk ↔ policy-service /policies/deploy seam (RA-11-E)", () => {
  const PASSPHRASE = "Test SDF Network ; September 2015";
  const WALLET = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
  const POLICY_CONTRACT = "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA";

  function addPolicyXdr(wallet: string, policy: string): string {
    const signer = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Policy"),
      nativeToScVal(Address.fromString(policy), { type: "address" }),
      xdr.ScVal.scvVoid(),
    ]);
    const func = xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(wallet).toScAddress(),
        functionName: "add_signer",
        args: [signer],
      }),
    );
    const op = Operation.invokeHostFunction({ func, auth: [] });
    const src = new Account(Keypair.random().publicKey(), "0");
    return new TransactionBuilder(src, { fee: "100", networkPassphrase: PASSPHRASE })
      .addOperation(op)
      .setTimeout(30)
      .build()
      .toXDR();
  }

  async function createSeamClient(verifyAttach: (h: string) => Promise<unknown>) {
    const policies = createMemoryPolicyRepository();
    const app = buildServer({
      policies,
      verifyAttach: verifyAttach as never,
      network: "testnet",
      networkPassphrase: PASSPHRASE,
    });
    await app.ready();

    const fetchImpl = (async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const headers = {
        "content-type": "application/json",
        ...((init?.headers as Record<string, string>) ?? {}),
      };
      const res = await app.inject({
        method: (init?.method ?? "GET") as "GET" | "POST",
        url: u.pathname + u.search,
        headers,
        payload: init?.body ? (init.body as string) : undefined,
      });
      return new Response(res.body, {
        status: res.statusCode,
        headers: { "content-type": (res.headers["content-type"] as string) ?? "application/json" },
      });
    }) as unknown as typeof fetch;

    const client = createPolicyClient({
      apiUrl: "http://policy.test",
      fetch: fetchImpl,
    });

    const spendingPolicy = {
      version: "1",
      type: "spending_limit",
      owners: [WALLET],
      spendingLimits: { dailyXlm: "100", perTxXlm: "25" },
    };

    // Helper to seed a policy in instance_deployed state
    async function seedPolicy(hasInstance = true) {
      const gen = await app.inject({
        method: "POST",
        url: "/policies/generate",
        payload: { definition: spendingPolicy, network: "testnet" },
      });
      const policy = gen.json().policy as { id: string };
      if (hasInstance) {
        const rec = await policies.find(policy.id);
        await policies.update({
          ...rec!,
          status: "instance_deployed",
          instance: {
            contractId: POLICY_CONTRACT,
            wallet: WALLET,
            txHash: "deploytx",
            deployedAt: new Date().toISOString(),
          },
        });
      }
      return policy.id;
    }

    return { app, client, seedPolicy, policies };
  }

  it("200 mode: handles successful attach verification and marks policy deployed", async () => {
    const { client, seedPolicy, policies } = await createSeamClient(async () => ({
      status: "SUCCESS",
      envelopeXdr: addPolicyXdr(WALLET, POLICY_CONTRACT),
    }));

    const policyId = await seedPolicy(true);
    const policy = await client.recordDeployment(
      policyId,
      "real_valid_hash",
      POLICY_CONTRACT,
    );

    expect(policy.status).toBe("deployed");
    const stored = await policies.find(policyId);
    expect(stored?.status).toBe("deployed");
  });

  it("422 mode (attach_mismatch): raises non-retryable PolicyApiError for spoofed tx", async () => {
    const otherContract = "CAFK7NMQOT7G2SKMREDUII3EOK4APIY54WIK6CVGY72XWFE76YFRDF67";
    const { client, seedPolicy, policies } = await createSeamClient(async () => ({
      status: "SUCCESS",
      envelopeXdr: addPolicyXdr(WALLET, otherContract),
    }));

    const policyId = await seedPolicy(true);
    try {
      await client.recordDeployment(
        policyId,
        "mismatched_hash",
        POLICY_CONTRACT,
      );
      expect.fail("Expected PolicyApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyApiError);
      const apiErr = err as PolicyApiError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.retryable).toBe(false); // Retrying a lie is terminal
    }

    const stored = await policies.find(policyId);
    expect(stored?.status).toBe("instance_deployed"); // Not stamped
  });

  it("422 mode (no_instance): raises non-retryable PolicyApiError when deploy-instance was not run", async () => {
    const { client, seedPolicy } = await createSeamClient(async () => ({ status: "SUCCESS" }));
    const policyId = await seedPolicy(false); // No instance

    try {
      await client.recordDeployment(
        policyId,
        "some_hash",
        POLICY_CONTRACT,
      );
      expect.fail("Expected PolicyApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyApiError);
      const apiErr = err as PolicyApiError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.retryable).toBe(false);
    }
  });

  it("503 mode (attach_unconfirmed): raises retryable PolicyApiError when tx is pending on-chain", async () => {
    const { client, seedPolicy, policies } = await createSeamClient(async () => ({
      status: "NOT_FOUND",
    }));

    const policyId = await seedPolicy(true);
    try {
      await client.recordDeployment(
        policyId,
        "pending_hash",
        POLICY_CONTRACT,
      );
      expect.fail("Expected PolicyApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyApiError);
      const apiErr = err as PolicyApiError;
      expect(apiErr.status).toBe(503);
      expect(apiErr.retryable).toBe(true); // Retryable! Must wait for tx to clear or retry
    }

    const stored = await policies.find(policyId);
    expect(stored?.status).toBe("instance_deployed"); // Not stamped
  });

  it("503 mode (rpc_unreachable): raises retryable PolicyApiError on network failure", async () => {
    const { client, seedPolicy } = await createSeamClient(async () => {
      throw new Error("RPC timeout or network drop");
    });

    const policyId = await seedPolicy(true);
    try {
      await client.recordDeployment(
        policyId,
        "hash_during_outage",
        POLICY_CONTRACT,
      );
      expect.fail("Expected PolicyApiError to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyApiError);
      const apiErr = err as PolicyApiError;
      expect(apiErr.status).toBe(503);
      expect(apiErr.retryable).toBe(true);
    }
  });
});
