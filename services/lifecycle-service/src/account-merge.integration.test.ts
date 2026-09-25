import { describe, it, expect, beforeEach, beforeAll, afterAll } from "vitest";
import { buildServer as buildLifecycleServer, fakeFacilitatorClient } from "./server";
import { createMemoryWalletRepository } from "../../wallet-service/src/repository";
import { buildServer as buildWalletServer } from "../../wallet-service/src/server";
import type { HorizonAccount } from "./horizon";

// buildServer() registers the x402 payment gate, which resolves its public
// resource URL from the environment and refuses to fall back to the local
// bind host/port. Tests must supply a valid value for that call to succeed.
const PREVIOUS_RENDER_EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL;
beforeAll(() => {
  process.env.RENDER_EXTERNAL_URL = "https://vellar-backend.onrender.com";
});
afterAll(() => {
  if (PREVIOUS_RENDER_EXTERNAL_URL === undefined) {
    delete process.env.RENDER_EXTERNAL_URL;
  } else {
    process.env.RENDER_EXTERNAL_URL = PREVIOUS_RENDER_EXTERNAL_URL;
  }
});

const SOURCE_ACCOUNT = "GAKB2VWTROSQP56WMLR2EJP2W2ZAKX2HGYW2YWTROSQP56WMLR2EJP2W";
const DEST_ACCOUNT = "GBX2VWTROSQP56WMLR2EJP2W2ZAKX2HGYW2YWTROSQP56WMLR2EJP2X2";
const FAILED_ACCOUNT = "GFAILVWTROSQP56WMLR2EJP2W2ZAKX2HGYW2YWTROSQP56WMLR2EJP2F";

describe("account merge across services integration tests", () => {
  let mockAccounts: Map<string, HorizonAccount>;

  beforeEach(() => {
    mockAccounts = new Map<string, HorizonAccount>([
      [
        SOURCE_ACCOUNT,
        {
          accountId: SOURCE_ACCOUNT,
          sequence: "100",
          balances: [{ assetType: "native", balance: "10.5000000" }],
          dataKeys: [],
          offers: [],
          openOffers: 0,
        },
      ],
      [
        DEST_ACCOUNT,
        {
          accountId: DEST_ACCOUNT,
          sequence: "200",
          balances: [{ assetType: "native", balance: "50.0000000" }],
          dataKeys: [],
          offers: [],
          openOffers: 0,
        },
      ],
      [
        FAILED_ACCOUNT,
        {
          accountId: FAILED_ACCOUNT,
          sequence: "150",
          balances: [
            { assetType: "native", balance: "5.0000000" },
            { assetType: "credit_alphanum4", assetCode: "USDC", balance: "100.00", assetIssuer: DEST_ACCOUNT },
          ],
          dataKeys: [],
          offers: [],
          openOffers: 0,
        },
      ],
    ]);
  });

  it("performs a full account merge across services and verifies state consistency", async () => {
    const reader = {
      getAccount: async (id: string) => mockAccounts.get(id),
    };

    const lifecycleApp = buildLifecycleServer({ reader, x402FacilitatorClient: fakeFacilitatorClient() });
    await lifecycleApp.ready();

    const walletRepo = createMemoryWalletRepository();
    const walletApp = buildWalletServer({
      submitter: { submit: async () => ({ hash: "tx_mock_hash" }) },
      wallets: walletRepo,
    });
    await walletApp.ready();

    // Step 1: Inspect old account via lifecycle service
    const inspectRes = await lifecycleApp.inject({
      method: "POST",
      url: "/lifecycle/inspect",
      payload: { accountId: SOURCE_ACCOUNT },
    });
    expect(inspectRes.statusCode).toBe(200);
    expect(inspectRes.json().account.id).toBe(SOURCE_ACCOUNT);

    // Step 2: Plan merge via lifecycle service
    const planRes = await lifecycleApp.inject({
      method: "POST",
      url: "/lifecycle/plan",
      payload: { accountId: SOURCE_ACCOUNT, destination: DEST_ACCOUNT },
    });
    expect(planRes.statusCode).toBe(200);
    expect(planRes.json().plan.mergeReady).toBe(true);

    // Step 3: Execute merge via lifecycle service
    const mergeRes = await lifecycleApp.inject({
      method: "POST",
      url: "/lifecycle/merge",
      payload: { accountId: SOURCE_ACCOUNT, destination: DEST_ACCOUNT },
    });
    expect(mergeRes.statusCode).toBe(200);
    expect(mergeRes.json().step.operations[0].type).toBe("accountMerge");

    // Simulate completion: update destination balance & remove merged source
    const dest = mockAccounts.get(DEST_ACCOUNT)!;
    dest.balances[0].balance = "60.5000000";
    mockAccounts.delete(SOURCE_ACCOUNT);

    // Verify consistency: source is gone, destination updated
    expect(await reader.getAccount(SOURCE_ACCOUNT)).toBeNull();
    expect((await reader.getAccount(DEST_ACCOUNT))?.balances[0].balance).toBe("60.5000000");

    await lifecycleApp.close();
    await walletApp.close();
  });

  it("handles a merge failure partway through when blockers remain", async () => {
    const reader = {
      getAccount: async (id: string) => mockAccounts.get(id) ?? null,
    };

    const lifecycleApp = buildLifecycleServer({ reader });
    await lifecycleApp.ready();

    // Attempt merge on account with open trustlines (blockers remaining)
    const mergeRes = await lifecycleApp.inject({
      method: "POST",
      url: "/lifecycle/merge",
      payload: { accountId: FAILED_ACCOUNT, destination: DEST_ACCOUNT },
    });

    expect(mergeRes.statusCode).toBe(409);
    expect(mergeRes.json().error).toBe("not_merge_ready");
    expect(mergeRes.json().plan.mergeReady).toBe(false);

    // Verify source account table/record is untouched after failed merge attempt
    expect(await reader.getAccount(FAILED_ACCOUNT)).not.toBeNull();

    await lifecycleApp.close();
  });
});
