import { describe, expect, it } from "vitest";
import {
  createSep43Provider,
  mapToSep43Error,
  passphraseToNetwork,
  VellarModule,
} from "./sep43";
import type { PageTransport } from "./page-provider";
import {
  errorPayload,
  parseRequestEnvelope,
  responseEnvelope,
  type ResponsePayload,
} from "./protocol";

function harness(answer?: (id: string, method: string, params: any) => ResponsePayload | undefined) {
  let inbound: (data: unknown) => void = () => {};
  const sent: Array<{ id: string; method: string; params: any }> = [];
  const transport: PageTransport = {
    send(data) {
      const envelope = parseRequestEnvelope(data);
      if (!envelope) throw new Error("provider sent an invalid envelope");
      sent.push({ id: envelope.id, method: envelope.request.method, params: (envelope.request as any).params });
      let payload = answer?.(envelope.id, envelope.request.method, (envelope.request as any).params);
      if (!payload && envelope.request.method === "get_network") {
        payload = {
          method: "get_network",
          result: { network: "testnet", networkPassphrase: "Test SDF Network ; September 2015" },
        };
      }
      if (payload) queueMicrotask(() => inbound(responseEnvelope(envelope.id, payload)));
    },
    listen(handler) {
      inbound = handler;
      return () => {};
    },
  };
  return { transport, sent, respond: (data: unknown) => inbound(data) };
}

describe("SEP-43 Provider", () => {
  it("passphraseToNetwork correctly parses network passphrase", () => {
    expect(passphraseToNetwork("Public Global Stellar Network ; September 2015")).toBe("mainnet");
    expect(passphraseToNetwork("Test SDF Network ; September 2015")).toBe("testnet");
    expect(passphraseToNetwork(undefined)).toBe("testnet");
  });

  it("mapToSep43Error maps standard error codes", () => {
    expect(mapToSep43Error({ code: -3, message: "rejected" })).toEqual({ code: -3, message: "rejected" });
  });

  it("getAddress connects and returns address", async () => {
    const { transport, sent } = harness((id, method) => {
      if (method === "connect") {
        return { method: "connect", result: { address: "GBXYZ", network: "testnet" } };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const result = await provider.getAddress();
    expect(result).toEqual({ address: "GBXYZ" });
    expect(sent.some((s) => s.method === "connect")).toBe(true);
  });

  it("signTransaction invokes sign_transaction and returns signedTxXdr", async () => {
    const { transport, sent } = harness((id, method) => {
      if (method === "sign_transaction") {
        return {
          method: "sign_transaction",
          result: { signedXdr: "AAAA_SIGNED", signerAddress: "GBXYZ" },
        };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const result = await provider.signTransaction("AAAA_RAW", {
      networkPassphrase: "Test SDF Network ; September 2015",
    });
    expect(result).toEqual({
      signedTxXdr: "AAAA_SIGNED",
      signerAddress: "GBXYZ",
    });
    expect(sent.some((s) => s.method === "sign_transaction")).toBe(true);
  });

  it("signAuthEntry invokes sign_auth_entry and returns signedAuthEntry", async () => {
    const { transport, sent } = harness((id, method) => {
      if (method === "sign_auth_entry") {
        return {
          method: "sign_auth_entry",
          result: { signedAuthEntry: "AUTH_ENTRY_SIGNED", signerAddress: "GBXYZ" },
        };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const result = await provider.signAuthEntry("AUTH_ENTRY_RAW");
    expect(result).toEqual({
      signedAuthEntry: "AUTH_ENTRY_SIGNED",
      signerAddress: "GBXYZ",
    });
    expect(sent.some((s) => s.method === "sign_auth_entry")).toBe(true);
  });

  it("signMessage invokes sign_message and returns signedMessage", async () => {
    const { transport, sent } = harness((id, method) => {
      if (method === "sign_message") {
        return {
          method: "sign_message",
          result: { signedMessage: "SIG_BYTES_BASE64", signerAddress: "GBXYZ" },
        };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const result = await provider.signMessage("Hello world");
    expect(result).toEqual({
      signedMessage: "SIG_BYTES_BASE64",
      signerAddress: "GBXYZ",
    });
    expect(sent.some((s) => s.method === "sign_message")).toBe(true);
  });

  it("getNetwork returns network and networkPassphrase", async () => {
    const { transport, sent } = harness((id, method) => {
      if (method === "get_network") {
        return {
          method: "get_network",
          result: {
            network: "testnet",
            networkPassphrase: "Test SDF Network ; September 2015",
          },
        };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const result = await provider.getNetwork();
    expect(result).toEqual({
      network: "testnet",
      networkPassphrase: "Test SDF Network ; September 2015",
    });
    expect(sent.some((s) => s.method === "get_network")).toBe(true);
  });

  it("maps user rejection error to code -3", async () => {
    const { transport } = harness((id, method) => {
      if (method === "sign_message") {
        return errorPayload("rejected", "User declined");
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    await expect(provider.signMessage("test")).rejects.toMatchObject({
      code: -3,
    });
  });

  it("VellarModule satisfies Stellar Wallets Kit interface", async () => {
    const { transport } = harness((id, method) => {
      if (method === "connect") {
        return { method: "connect", result: { address: "GBXYZ", network: "testnet" } };
      }
      return undefined;
    });
    const provider = createSep43Provider({ transport });
    const module = new VellarModule(provider);
    expect(module.moduleType).toBe("HOT_WALLET");
    expect(module.productId).toBe("vellar");
    expect(await module.isAvailable()).toBe(true);
    const addressRes = await module.getAddress();
    expect(addressRes.address).toBe("GBXYZ");
  });
});
