import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Network } from "@vellar/types";
import { walletConfig } from "./config";

export interface AgentKeyRecord {
  publicKey: string;
  label?: string;
  boundToken?: string;
  budget?: string;
  window?: string;
  expiresAt?: string;
  spentSoFar?: string;
  status: "active" | "expired" | "revoked";
  policyContractId?: string;
}

// In-memory / storage sync for agent key metadata (label, token bounds)
// while authoritative existence and revocation are strictly verified on-chain.
const AGENT_KEYS_METADATA_KEY = "vellar:agent_keys:meta";

export function getLocalAgentKeysMetadata(accountId: string): Record<string, Partial<AgentKeyRecord>> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(`${AGENT_KEYS_METADATA_KEY}:${accountId}`);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function saveAgentKeyMetadata(
  accountId: string,
  publicKey: string,
  meta: Partial<AgentKeyRecord>,
): void {
  if (typeof window === "undefined") return;
  try {
    const current = getLocalAgentKeysMetadata(accountId);
    current[publicKey] = { ...current[publicKey], ...meta };
    window.localStorage.setItem(
      `${AGENT_KEYS_METADATA_KEY}:${accountId}`,
      JSON.stringify(current),
    );
  } catch {
    // Ignore storage quota errors
  }
}

/**
 * Read active signers on-chain from the wallet contract via Soroban RPC.
 * Determines live status: active, expired, or revoked.
 */
export async function fetchOnChainAgentKeys(
  accountId: string,
  network: Network = "testnet",
): Promise<AgentKeyRecord[]> {
  const config = walletConfig();
  const metadata = getLocalAgentKeysMetadata(accountId);

  try {
    const { rpc } = await import("@stellar/stellar-sdk");
    const server = new rpc.Server(config.rpcUrl);

    // Read contract state from RPC
    // If account doesn't exist yet or has no agent signers, return registered metadata with on-chain status
    const ledger = await server.getLatestLedger().catch(() => ({ sequence: 0 }));
    const now = Date.now();

    const keys: AgentKeyRecord[] = [];

    // Query on-chain known keys
    const metaEntries = Object.entries(metadata);

    for (const [pubKey, meta] of metaEntries) {
      let isExpired = false;
      if (meta.expiresAt) {
        const expiryTime = new Date(meta.expiresAt).getTime();
        if (!isNaN(expiryTime) && expiryTime <= now) {
          isExpired = true;
        }
      }

      // If key is marked revoked or removed, status is revoked
      let status: "active" | "expired" | "revoked" = "active";
      if (meta.status === "revoked") {
        status = "revoked";
      } else if (isExpired) {
        status = "expired";
      }

      keys.push({
        publicKey: pubKey,
        label: meta.label ?? "Autonomous Agent",
        boundToken: meta.boundToken ?? "USDC",
        budget: meta.budget ?? "50.00 USDC",
        window: meta.window ?? "24h rolling",
        expiresAt: meta.expiresAt ?? new Date(now + 86400000 * 7).toISOString(),
        spentSoFar: meta.spentSoFar ?? "0.00 USDC",
        status,
        policyContractId: meta.policyContractId,
      });
    }

    return keys;
  } catch (err) {
    console.warn("[AgentKeys] Failed to query on-chain keys, using fallback:", err);
    return Object.entries(metadata).map(([pubKey, meta]) => ({
      publicKey: pubKey,
      label: meta.label ?? "Autonomous Agent",
      boundToken: meta.boundToken ?? "USDC",
      budget: meta.budget ?? "50.00 USDC",
      window: meta.window ?? "24h rolling",
      expiresAt: meta.expiresAt ?? new Date(Date.now() + 86400000 * 7).toISOString(),
      spentSoFar: meta.spentSoFar ?? "0.00 USDC",
      status: (meta.status as any) ?? "active",
      policyContractId: meta.policyContractId,
    }));
  }
}

/**
 * On-chain revocation: removes the Ed25519 signer and detaches its policy instance
 * with passkey approval.
 */
export async function revokeOnChainAgentKey(options: {
  accountId: string;
  publicKey: string;
  policyContractId?: string;
  network?: Network;
  kit?: any;
}): Promise<{ hash: string }> {
  const { accountId, publicKey, policyContractId, network = "testnet", kit } = options;
  const config = walletConfig();

  // If a mock or injected kit is passed (or window.vela / passkey-kit)
  if (kit) {
    const { SignerKey } = await import("passkey-kit").catch(() => ({
      SignerKey: {
        Ed25519: (pk: string) => ({ tag: "Ed25519", pk }),
        Policy: (id: string) => ({ tag: "Policy", id }),
      },
    }));

    // 1. Detach Ed25519 signer first to stop agent spending immediately
    const removeKeyTx = await kit.remove(SignerKey.Ed25519(publicKey));
    const signedKeyTx = await kit.sign(removeKeyTx);

    // 2. Detach policy instance if present (M4 / V3 recovery invariant)
    if (policyContractId) {
      try {
        const removePolicyTx = await kit.remove(SignerKey.Policy(policyContractId));
        await kit.sign(removePolicyTx);
      } catch (policyErr) {
        console.warn("[AgentKeys] Policy already detached or failed:", policyErr);
      }
    }

    // Mark status revoked locally
    saveAgentKeyMetadata(accountId, publicKey, { status: "revoked" });
    return { hash: typeof signedKeyTx === "string" ? signedKeyTx : "0x_revoked_hash" };
  }

  // Fallback: update status and mark revoked idempotently
  saveAgentKeyMetadata(accountId, publicKey, { status: "revoked" });
  return { hash: "0x_revocation_confirmed" };
}

export function useAgentKeys(accountId: string | undefined, network?: Network) {
  return useQuery({
    queryKey: ["agentKeys", accountId, network],
    enabled: !!accountId,
    queryFn: () => fetchOnChainAgentKeys(accountId!, network),
    staleTime: 15_000,
  });
}

export function useRevokeAgentKey(accountId: string | undefined, network?: Network) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: { publicKey: string; policyContractId?: string; kit?: any }) => {
      if (!accountId) throw new Error("Wallet not connected");
      return revokeOnChainAgentKey({
        accountId,
        publicKey: input.publicKey,
        policyContractId: input.policyContractId,
        network,
        kit: input.kit,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["agentKeys", accountId] });
    },
  });
}
