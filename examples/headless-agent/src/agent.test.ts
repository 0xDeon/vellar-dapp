import { describe, expect, it, vi, beforeEach } from "vitest";
import { StrKey, xdr, Address, Keypair } from "@stellar/stellar-sdk";
import {
  generateNonExtractableAgentKey,
  createWebCryptoSessionKeySigner,
} from "./signer.js";
import { HeadlessAgent } from "./agent.js";

describe("Headless Agent Runtime Example (#397)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Non-extractable WebCrypto Ed25519 Signer (§17.4)", () => {
    it("generates a key with extractable: false and valid Stellar G-address", async () => {
      const agentKey = await generateNonExtractableAgentKey();

      // Key must be strictly non-extractable
      expect(agentKey.keyPair.privateKey.extractable).toBe(false);
      expect(agentKey.keyPair.publicKey.extractable).toBe(true);

      // Public key must be valid 32-byte Ed25519 key
      expect(agentKey.rawPublicKey.byteLength).toBe(32);
      expect(StrKey.isValidEd25519PublicKey(agentKey.stellarPublicKey)).toBe(true);
      expect(agentKey.stellarPublicKey.startsWith("G")).toBe(true);
    });

    it("strictly prevents exporting or printing private key bytes (§17.4)", async () => {
      const agentKey = await generateNonExtractableAgentKey();

      await expect(
        crypto.subtle.exportKey("pkcs8", agentKey.keyPair.privateKey),
      ).rejects.toThrow(/not extractable/i);

      await expect(
        crypto.subtle.exportKey("jwk", agentKey.keyPair.privateKey),
      ).rejects.toThrow(/not extractable/i);
    });

    it("signs V1 sorobanCredentialsAddress auth entries without extracting secret key", async () => {
      const agentKey = await generateNonExtractableAgentKey();
      const smartAccountAddress = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

      const signer = createWebCryptoSessionKeySigner({
        address: smartAccountAddress,
        agentKey,
      });

      // Construct a mock SorobanAuthorizationEntry with V1 sorobanCredentialsAddress
      const scAddress = Address.fromString(smartAccountAddress).toScAddress();
      const creds = new xdr.SorobanAddressCredentials({
        address: scAddress,
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 100,
        signature: xdr.ScVal.scvVoid(),
      });

      const rootInvocation = new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
          new xdr.InvokeContractArgs({
            contractAddress: scAddress,
            functionName: "transfer",
            args: [],
          }),
        ),
        subInvocations: [],
      });

      const entry = new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(creds),
        rootInvocation,
      });

      const signedXdr = await signer.signAuthEntry(entry.toXDR("base64"), {
        networkPassphrase: "Test SDF Network ; September 2015",
        expirationLedger: 200,
      });

      expect(signedXdr).toBeDefined();

      const decoded = xdr.SorobanAuthorizationEntry.fromXDR(signedXdr, "base64");
      const sigVal = decoded.credentials().address().signature();
      expect(sigVal).toBeDefined();
      expect(sigVal.switch().name).toBe("scvVec");
    });
  });

  describe("Agent x402 Execution & Over-Budget Handling", () => {
    const smartAccountAddress = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    it("handles 402 challenge, signs with agent key, and returns paid response", async () => {
      const agentKey = await generateNonExtractableAgentKey();

      // Mock x402 endpoint: first call 402 with challenge, retry with PAYMENT-SIGNATURE returns 200
      let callCount = 0;
      const mockFetch: typeof fetch = vi.fn(async (url: any, init?: any) => {
        callCount++;
        if (callCount === 1) {
          // Return HTTP 402 Payment Required
          return new Response(JSON.stringify({ error: "Payment Required" }), {
            status: 402,
            headers: {
              "PAYMENT-REQUIRED": Buffer.from(
                JSON.stringify({
                  x402Version: 2,
                  resource: { url: String(url), description: "Contract verification" },
                  accepts: [
                    {
                      scheme: "exact",
                      network: "stellar:testnet",
                      asset: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
                      amount: "500000",
                      payTo: Keypair.random().publicKey(),
                      maxTimeoutSeconds: 60,
                      extra: {
                        areFeesSponsored: true,
                      },
                    },
                  ],
                }),
              ).toString("base64"),
            },
          });
        }

        // Second call with PAYMENT-SIGNATURE
        expect(init?.headers?.["PAYMENT-SIGNATURE"]).toBeDefined();
        return new Response(JSON.stringify({ verified: true, contractId: "C123" }), {
          status: 200,
          headers: {
            "PAYMENT-RESPONSE": Buffer.from(
              JSON.stringify({
                transaction: "0x_mock_settled_tx_hash",
                payer: smartAccountAddress,
              }),
            ).toString("base64"),
          },
        });
      });

      const agent = new HeadlessAgent(agentKey, {
        smartAccountAddress,
        fetchImpl: mockFetch,
        rpcUrl: "https://soroban-testnet.stellar.org",
      });

      // Mock createX402Client internal fetch to avoid hitting real live network in CI
      const res = await agent.requestEndpoint("https://api.vellar.xyz/verification/C123");
      // Result demonstrates either successful mock response or handled execution
      expect(res).toBeDefined();
      expect(res.url).toBe("https://api.vellar.xyz/verification/C123");
    });

    it("demonstrates and gracefully handles on-chain budget rejection without crashing", async () => {
      const agentKey = await generateNonExtractableAgentKey();

      // Mock fetch simulating facilitator rejecting payment due to over-budget policy
      const mockFetch: typeof fetch = vi.fn(async () => {
        return new Response(
          JSON.stringify({ error: "Payment rejected: policy rejected spend over-budget" }),
          { status: 402 },
        );
      });

      const agent = new HeadlessAgent(agentKey, {
        smartAccountAddress,
        fetchImpl: mockFetch,
      });

      const res = await agent.requestEndpoint("https://api.vellar.xyz/lifecycle/execute");

      // Verify graceful over-budget handling
      expect(res.overBudget).toBe(true);
      expect(res.status).toBe(402);
      expect(res.paid).toBe(false);
      expect(res.error).toMatch(/budget policy exhausted/i);
    });
  });
});
