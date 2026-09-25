"use client";

import { useQuery } from "@tanstack/react-query";
import type { TokenBalance, TokenInfo } from "vellar-sdk";
import type { Network } from "@vellar/types";
import { walletConfig } from "./config";
import { getSupportedTokens, TESTNET_NATIVE_SAC, MAINNET_NATIVE_SAC } from "./tokens";

// Balance data for the dashboard. The RPC reader (and stellar-sdk with it)
// loads lazily on first use, keeping it off the onboarding path.

export async function fetchBalances(
  accountId: string,
  network?: Network,
): Promise<TokenBalance[]> {
  const config = walletConfig();
  const currentNetwork: Network =
    network ??
    (config.networkPassphrase.toLowerCase().includes("test")
      ? "testnet"
      : "mainnet");

  const [{ createBalanceService }, { createRpcBalanceReader, nativeToken }] =
    await Promise.all([import("vellar-sdk"), import("vellar-sdk/rpc")]);

  const rawReader = createRpcBalanceReader({
    rpcUrl: config.rpcUrl,
    networkPassphrase: config.networkPassphrase,
  });

  // Safe reader wrapper: if balance query fails (e.g. SAC not deployed or no trustline/record),
  // return 0n rather than failing the entire balances view for all assets.
  const safeReader = {
    async getTokenBalance(contractId: string, holder: string): Promise<bigint> {
      try {
        return await rawReader.getTokenBalance(contractId, holder);
      } catch (err) {
        console.warn(`[Balances] Could not query balance for token ${contractId}:`, err);
        return 0n;
      }
    },
  };

  const registeredTokens = getSupportedTokens(currentNetwork);
  let native: TokenInfo;
  try {
    native = nativeToken(config.networkPassphrase);
  } catch {
    native = registeredTokens.find((t) => t.isNative) ?? {
      contractId:
        currentNetwork === "mainnet"
          ? MAINNET_NATIVE_SAC
          : TESTNET_NATIVE_SAC,
      symbol: "XLM",
      decimals: 7,
    };
  }

  // Merge native token info with registered tokens, deduplicating by contractId
  const tokensToQuery: TokenInfo[] = [];
  const seenContracts = new Set<string>();

  // Ensure native XLM is always first
  tokensToQuery.push(native);
  seenContracts.add(native.contractId.toLowerCase());

  for (const t of registeredTokens) {
    if (!seenContracts.has(t.contractId.toLowerCase())) {
      tokensToQuery.push({
        contractId: t.contractId,
        symbol: t.symbol,
        decimals: t.decimals,
      });
      seenContracts.add(t.contractId.toLowerCase());
    }
  }

  return createBalanceService(safeReader, tokensToQuery).getBalances(accountId);
}

export function useBalances(accountId: string | undefined, network?: Network) {
  return useQuery({
    queryKey: ["balances", accountId, network],
    enabled: accountId !== undefined,
    queryFn: () => fetchBalances(accountId as string, network),
    staleTime: 30_000,
  });
}
