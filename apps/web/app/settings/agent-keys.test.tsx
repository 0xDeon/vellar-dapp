import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Settings from "./page";
import {
  fetchOnChainAgentKeys,
  revokeOnChainAgentKey,
  saveAgentKeyMetadata,
} from "@/lib/agent-keys";

// Mock wallet session
const mockSession = {
  accountId: "CSMARTWALLET_TEST",
  network: "testnet" as const,
  connected: true,
  authMethod: "passkey" as const,
  createdAt: "2026-09-25T00:00:00.000Z",
  lastActiveAt: "2026-09-25T00:00:00.000Z",
  serverSessionId: "sess-1",
};

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/settings",
}));

vi.mock("@/lib/wallet-context", () => ({
  useWalletSession: () => mockSession,
  useWalletStatus: () => "connected",
  useWalletActions: () => ({
    disconnect: vi.fn(),
  }),
}));

vi.mock("@/lib/sessions", () => ({
  useSessions: () => ({ data: [], isPending: false, isError: false }),
  useRevokeSession: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("@/lib/extension-pairing", () => ({
  getInjectedProvider: () => undefined,
  checkPairingStatus: vi.fn().mockResolvedValue(false),
  recallPairing: vi.fn().mockReturnValue(null),
  pairExtension: vi.fn(),
}));

describe("Agent Session Keys: List + Revoke (#395)", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
    window.localStorage.clear();
    vi.clearAllMocks();
  });

  function renderWithClient(ui: React.ReactElement) {
    return render(
      <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
    );
  }

  it("lists agent keys with live on-chain status, distinguishing active, expired, and revoked", async () => {
    const accountId = "CSMARTWALLET_TEST";

    // 1. Active key
    saveAgentKeyMetadata(accountId, "GACTIVE_AGENT_KEY_1", {
      label: "Trading Bot",
      boundToken: "USDC",
      budget: "100.00 USDC",
      window: "24h rolling",
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      status: "active",
      policyContractId: "CPOLICY_1",
    });

    // 2. Expired key
    saveAgentKeyMetadata(accountId, "GEXPIRED_AGENT_KEY_2", {
      label: "Research Crawler",
      boundToken: "USDC",
      budget: "10.00 USDC",
      window: "7d rolling",
      expiresAt: new Date(Date.now() - 3600000).toISOString(), // expired 1h ago
      status: "active",
    });

    // 3. Revoked key
    saveAgentKeyMetadata(accountId, "GREVOKED_AGENT_KEY_3", {
      label: "Compromised Agent",
      boundToken: "XLM",
      budget: "50.00 XLM",
      status: "revoked",
    });

    const keys = await fetchOnChainAgentKeys(accountId, "testnet");
    expect(keys).toHaveLength(3);

    const active = keys.find((k) => k.publicKey === "GACTIVE_AGENT_KEY_1");
    expect(active?.status).toBe("active");

    const expired = keys.find((k) => k.publicKey === "GEXPIRED_AGENT_KEY_2");
    expect(expired?.status).toBe("expired");

    const revoked = keys.find((k) => k.publicKey === "GREVOKED_AGENT_KEY_3");
    expect(revoked?.status).toBe("revoked");
  });

  it("revokes an individual key on-chain with passkey approval, detaching both signer and policy", async () => {
    const accountId = "CSMARTWALLET_TEST";
    const publicKey = "GAGENT_TO_REVOKE";
    const policyContractId = "CPOLICY_TO_DETACH";

    saveAgentKeyMetadata(accountId, publicKey, {
      label: "Data Pipeline",
      boundToken: "USDC",
      status: "active",
      policyContractId,
    });

    const mockKit = {
      remove: vi.fn().mockImplementation((key) => Promise.resolve({ toXDR: () => "mock_tx_xdr" })),
      sign: vi.fn().mockImplementation((tx) => Promise.resolve("mock_signed_xdr")),
    };

    const res = await revokeOnChainAgentKey({
      accountId,
      publicKey,
      policyContractId,
      kit: mockKit,
    });

    expect(res.hash).toBeDefined();
    // Verify signer removal was called first
    expect(mockKit.remove).toHaveBeenCalledWith(
      expect.objectContaining({ key: "Ed25519", value: publicKey }),
    );
    // Verify policy detachment was called
    expect(mockKit.remove).toHaveBeenCalledWith(
      expect.objectContaining({ key: "Policy", value: policyContractId }),
    );

    // Verify key status changed to revoked
    const updatedKeys = await fetchOnChainAgentKeys(accountId, "testnet");
    const found = updatedKeys.find((k) => k.publicKey === publicKey);
    expect(found?.status).toBe("revoked");
  });

  it("is idempotent when revoking a key that is already removed or gone", async () => {
    const accountId = "CSMARTWALLET_TEST";
    const publicKey = "GAGENT_ALREADY_GONE";

    const res = await revokeOnChainAgentKey({
      accountId,
      publicKey,
    });

    expect(res.hash).toBeDefined();
    const updatedKeys = await fetchOnChainAgentKeys(accountId, "testnet");
    const found = updatedKeys.find((k) => k.publicKey === publicKey);
    expect(found?.status).toBe("revoked");
  });

  it("renders agent keys section and triggers revocation via the UI", async () => {
    const accountId = "CSMARTWALLET_TEST";
    saveAgentKeyMetadata(accountId, "GACTIVE_AGENT_KEY_1", {
      label: "Autonomous Trader",
      status: "active",
    });

    renderWithClient(<Settings />);

    await waitFor(() => {
      expect(screen.getByText("Agent session keys")).toBeDefined();
      expect(screen.getByText("Autonomous Trader")).toBeDefined();
    });

    const revokeBtn = screen.getByRole("button", { name: /revoke \(kill switch\)/i });
    expect(revokeBtn).toBeDefined();

    fireEvent.click(revokeBtn);

    await waitFor(() => {
      // Status updates
      const statusPill = screen.queryByText("revoked");
      expect(statusPill || !screen.queryByRole("button", { name: /revoke/i })).toBeTruthy();
    });
  });
});
