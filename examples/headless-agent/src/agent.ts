import { createX402Client } from "vellar-sdk";
import {
  generateNonExtractableAgentKey,
  createWebCryptoSessionKeySigner,
  type NonExtractableAgentKey,
} from "./signer.js";

export interface AgentConfig {
  /** Smart account C-address that minted this agent key */
  smartAccountAddress: string;
  /** RPC URL for Soroban queries */
  rpcUrl?: string;
  /** Stellar network: testnet only (§17.4) */
  network?: "testnet";
  /** Maximum amount in base units the agent is permitted to pay per call */
  maxAmountPerCall?: bigint;
  /** Attached policy contracts (e.g. token spending limit policy) */
  policyContracts?: string[];
  /** Custom fetch implementation (injected for tests or proxying) */
  fetchImpl?: typeof fetch;
}

export interface AgentExecutionResult {
  url: string;
  status: number;
  paid: boolean;
  data?: unknown;
  overBudget?: boolean;
  error?: string;
}

/**
 * Headless autonomous agent process.
 * Holds NO raw account secret keys (§17.4), relying exclusively on a non-extractable
 * WebCrypto Ed25519 key authorized under an on-chain budget policy.
 */
export class HeadlessAgent {
  public readonly agentKey: NonExtractableAgentKey;
  private readonly config: Required<AgentConfig>;
  private readonly x402Client: ReturnType<typeof createX402Client>;

  constructor(agentKey: NonExtractableAgentKey, config: AgentConfig) {
    this.agentKey = agentKey;
    this.config = {
      smartAccountAddress: config.smartAccountAddress,
      rpcUrl: config.rpcUrl ?? "https://soroban-testnet.stellar.org",
      network: "testnet",
      maxAmountPerCall: config.maxAmountPerCall ?? 1_000_000n, // 0.1 USDC (7 decimals)
      policyContracts: config.policyContracts ?? [],
      fetchImpl: config.fetchImpl ?? fetch,
    };

    const signer = createWebCryptoSessionKeySigner({
      address: this.config.smartAccountAddress,
      agentKey: this.agentKey,
      policies: this.config.policyContracts,
    });

    this.x402Client = createX402Client({
      signer,
      network: this.config.network,
      rpcUrl: this.config.rpcUrl,
      simulationSourceAccount: this.config.smartAccountAddress,
      fetchImpl: this.config.fetchImpl,
    });
  }

  /**
   * Request an x402-gated endpoint.
   * If a 402 Payment Required challenge is received, the x402 client transparently
   * crafts a V1 auth entry, signs it using WebCrypto, and retries.
   *
   * If the on-chain budget is exhausted, the facilitator re-simulation (__check_auth)
   * fails, and the agent catches the error gracefully rather than crashing or looping.
   */
  async requestEndpoint(url: string, init?: RequestInit): Promise<AgentExecutionResult> {
    console.log(`[Agent] Requesting ${url} using authorized agent key ${this.agentKey.stellarPublicKey}...`);

    let headers: Record<string, string> | undefined;
    if (init?.headers) {
      if (init.headers instanceof Headers) {
        headers = Object.fromEntries(init.headers.entries());
      } else if (Array.isArray(init.headers)) {
        headers = Object.fromEntries(init.headers);
      } else {
        headers = init.headers as Record<string, string>;
      }
    }

    try {
      const result = await this.x402Client.fetch(url, {
        ...init,
        headers,
        maxAmount: this.config.maxAmountPerCall,
      });

      const bodyText = await result.response.text();
      let parsedData: unknown = bodyText;
      try {
        parsedData = JSON.parse(bodyText);
      } catch {
        // use raw text
      }

      console.log(
        `[Agent] Successfully fetched ${url} (HTTP ${result.response.status}, paid: ${result.paid})`,
      );

      return {
        url,
        status: result.response.status,
        paid: result.paid,
        data: parsedData,
      };
    } catch (err: any) {
      const message = err?.message || String(err);

      // Check if rejection was due to on-chain policy budget exhaustion
      if (
        message.includes("over-budget") ||
        message.includes("policy rejected") ||
        message.includes("402")
      ) {
        console.warn(
          `[Agent] 🛑 Budget policy rejected payment for ${url}. Re-simulation failed at __check_auth.`,
        );
        console.warn(`[Agent] Reason: ${message}`);
        console.warn(`[Agent] Gracefully stopping spend to protect the wallet.`);

        return {
          url,
          status: 402,
          paid: false,
          overBudget: true,
          error: "On-chain budget policy exhausted. Agent will not retry.",
        };
      }

      console.error(`[Agent] Request failed with unexpected error: ${message}`);
      return {
        url,
        status: 500,
        paid: false,
        error: message,
      };
    }
  }
}

/**
 * Bootstrap an autonomous agent with a fresh non-extractable WebCrypto key.
 */
export async function createAutonomousAgent(config: AgentConfig): Promise<HeadlessAgent> {
  const agentKey = await generateNonExtractableAgentKey();
  console.log(`[Agent] Generated non-extractable WebCrypto Ed25519 key:`);
  console.log(`[Agent] Public Key (G...): ${agentKey.stellarPublicKey}`);
  console.log(`[Agent] Private Key Extractable: ${agentKey.keyPair.privateKey.extractable}`);
  return new HeadlessAgent(agentKey, config);
}

// Standalone execution entrypoint
if (typeof process !== "undefined" && process.argv[1]?.includes("agent.ts")) {
  void (async () => {
    console.log("=== Vellar Headless Autonomous Agent (x402) ===");
    const agent = await createAutonomousAgent({
      smartAccountAddress:
        process.env.SMART_ACCOUNT_ADDRESS || "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
      network: "testnet",
    });

    const targetUrl =
      process.env.TARGET_URL || "https://api.vellar.xyz/verification/CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";
    const res = await agent.requestEndpoint(targetUrl);
    console.log("[Agent] Final Result:", res);
  })();
}
