import {
  errorPayload,
  parseResponseEnvelope,
  ProviderError,
  requestEnvelope,
  type ProviderRequest,
  type ResponsePayload,
} from "./protocol";
import type { PageProviderOptions, PageTransport } from "./page-provider";

// SEP-43 standard wallet interface (SEP-0043: Standard Web Wallet API Interface).
// Exposes the standard methods expected by Stellar Wallets Kit and stock Stellar dApps:
// getAddress, signTransaction, signAuthEntry, signMessage, getNetwork.

export interface Sep43Error {
  code: number;
  message: string;
  ext?: string[];
}

export interface Sep43GetAddressOptions {
  path?: string;
  skipRequestAccess?: boolean;
}

export interface Sep43SignTransactionOptions {
  networkPassphrase?: string;
  address?: string;
  path?: string;
  submit?: boolean;
  submitUrl?: string;
}

export interface Sep43SignAuthEntryOptions {
  networkPassphrase?: string;
  address?: string;
  path?: string;
}

export interface Sep43SignMessageOptions {
  networkPassphrase?: string;
  address?: string;
  path?: string;
}

export interface Sep43Provider {
  getAddress(opts?: Sep43GetAddressOptions): Promise<{ address: string }>;
  signTransaction(
    xdr: string,
    opts?: Sep43SignTransactionOptions,
  ): Promise<{ signedTxXdr: string; signerAddress?: string }>;
  signAuthEntry(
    authEntry: string,
    opts?: Sep43SignAuthEntryOptions,
  ): Promise<{ signedAuthEntry: string; signerAddress?: string }>;
  signMessage(
    message: string,
    opts?: Sep43SignMessageOptions,
  ): Promise<{ signedMessage: string; signerAddress?: string }>;
  getNetwork(): Promise<{ network: string; networkPassphrase: string }>;
  isConnected(): Promise<{ isConnected: boolean }>;
  isAvailable(): Promise<boolean>;
  requestAccess(): Promise<{ address?: string; error?: string }>;
  disconnect(): Promise<void>;
}

export function passphraseToNetwork(passphrase?: string): "testnet" | "mainnet" {
  if (passphrase && passphrase.includes("Public Global Stellar Network")) {
    return "mainnet";
  }
  return "testnet";
}

export function mapToSep43Error(err: unknown): Sep43Error {
  if (err && typeof err === "object" && "code" in err && typeof (err as Sep43Error).code === "number") {
    return err as Sep43Error;
  }
  if (err instanceof ProviderError) {
    switch (err.code) {
      case "rejected":
        return { code: -3, message: err.message || "User declined the request" };
      case "unauthorized":
        return { code: -3, message: err.message || "Unauthorized" };
      case "invalid_request":
        return { code: -3, message: err.message || "Invalid request" };
      case "disconnected":
        return { code: -2, message: err.message || "No wallet paired or connected" };
      case "internal":
      default:
        return { code: -1, message: err.message || "Internal wallet error" };
    }
  }
  return { code: -1, message: err instanceof Error ? err.message : String(err) };
}

interface Pending {
  method: ProviderRequest["method"];
  resolve(payload: ResponsePayload): void;
}

export function createSep43Provider(options: PageProviderOptions): Sep43Provider {
  const timeoutMs = options.timeoutMs ?? 300_000;
  const newId =
    options.newId ??
    (() =>
      typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`);
  const pending = new Map<string, Pending>();

  options.transport.listen((data) => {
    const envelope = parseResponseEnvelope(data);
    if (!envelope) return;
    const entry = pending.get(envelope.id);
    if (!entry) return;
    pending.delete(envelope.id);
    entry.resolve(envelope.payload);
  });

  function call(request: ProviderRequest): Promise<ResponsePayload> {
    return new Promise((resolve) => {
      const id = newId();
      const timer = setTimeout(() => {
        if (pending.delete(id)) {
          resolve(errorPayload("rejected", `Request timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);
      pending.set(id, {
        method: request.method,
        resolve: (payload) => {
          clearTimeout(timer);
          resolve(payload);
        },
      });
      options.transport.send(requestEnvelope(id, request));
    });
  }

  function unwrap<T>(payload: ResponsePayload, method: ProviderRequest["method"]): T {
    if ("error" in payload) {
      throw mapToSep43Error(new ProviderError(payload.error.code, payload.error.message));
    }
    if (payload.method !== method) {
      throw { code: -1, message: `Mismatched response method: ${payload.method}` };
    }
    return payload.result as T;
  }

  return {
    async isAvailable(): Promise<boolean> {
      return true;
    },

    async isConnected(): Promise<{ isConnected: boolean }> {
      try {
        const net = await this.getNetwork();
        const network = net.network as "testnet" | "mainnet";
        const addrPayload = await call({ method: "get_address", params: { network } });
        if ("result" in addrPayload && addrPayload.result) {
          return { isConnected: true };
        }
        return { isConnected: false };
      } catch {
        return { isConnected: false };
      }
    },

    async requestAccess(): Promise<{ address?: string; error?: string }> {
      try {
        const netPayload = await call({ method: "get_network", params: {} });
        const network =
          "result" in netPayload && netPayload.result
            ? (netPayload.result.network as "testnet" | "mainnet")
            : "testnet";
        const connectPayload = await call({ method: "connect", params: { network } });
        const res = unwrap<{ address: string }>(connectPayload, "connect");
        return { address: res.address };
      } catch (err) {
        const mapped = mapToSep43Error(err);
        return { error: mapped.message };
      }
    },

    async getAddress(opts?: Sep43GetAddressOptions): Promise<{ address: string }> {
      try {
        let network: "testnet" | "mainnet" = "testnet";
        try {
          const net = await this.getNetwork();
          network = net.network as "testnet" | "mainnet";
        } catch {
          // fallback to testnet if get_network fails
        }

        if (opts?.skipRequestAccess !== true) {
          const connectPayload = await call({ method: "connect", params: { network } });
          const res = unwrap<{ address: string }>(connectPayload, "connect");
          return { address: res.address };
        }

        const payload = await call({ method: "get_address", params: { network } });
        const res = unwrap<{ address: string }>(payload, "get_address");
        return { address: res.address };
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },

    async signTransaction(
      xdr: string,
      opts?: Sep43SignTransactionOptions,
    ): Promise<{ signedTxXdr: string; signerAddress?: string }> {
      try {
        const network = opts?.networkPassphrase
          ? passphraseToNetwork(opts.networkPassphrase)
          : (await this.getNetwork()).network as "testnet" | "mainnet";
        const payload = await call({ method: "sign_transaction", params: { xdr, network } });
        const res = unwrap<{ signedXdr: string; signedTxXdr?: string; signerAddress?: string }>(
          payload,
          "sign_transaction",
        );
        return {
          signedTxXdr: res.signedTxXdr ?? res.signedXdr,
          signerAddress: res.signerAddress,
        };
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },

    async signAuthEntry(
      authEntry: string,
      opts?: Sep43SignAuthEntryOptions,
    ): Promise<{ signedAuthEntry: string; signerAddress?: string }> {
      try {
        const network = opts?.networkPassphrase
          ? passphraseToNetwork(opts.networkPassphrase)
          : (await this.getNetwork()).network as "testnet" | "mainnet";
        const payload = await call({ method: "sign_auth_entry", params: { authEntry, network } });
        const res = unwrap<{ signedAuthEntry: string; signerAddress?: string }>(
          payload,
          "sign_auth_entry",
        );
        return {
          signedAuthEntry: res.signedAuthEntry,
          signerAddress: res.signerAddress,
        };
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },

    async signMessage(
      message: string,
      opts?: Sep43SignMessageOptions,
    ): Promise<{ signedMessage: string; signerAddress?: string }> {
      try {
        const network = opts?.networkPassphrase
          ? passphraseToNetwork(opts.networkPassphrase)
          : (await this.getNetwork()).network as "testnet" | "mainnet";
        const payload = await call({ method: "sign_message", params: { message, network } });
        const res = unwrap<{ signedMessage: string; signerAddress?: string }>(
          payload,
          "sign_message",
        );
        return {
          signedMessage: res.signedMessage,
          signerAddress: res.signerAddress,
        };
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },

    async getNetwork(): Promise<{ network: string; networkPassphrase: string }> {
      try {
        const payload = await call({ method: "get_network", params: {} });
        return unwrap<{ network: string; networkPassphrase: string }>(payload, "get_network");
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },

    async disconnect(): Promise<void> {
      try {
        const payload = await call({ method: "disconnect", params: {} });
        unwrap(payload, "disconnect");
      } catch (err) {
        throw mapToSep43Error(err);
      }
    },
  };
}

// Module for Stellar Wallets Kit
export const VELLAR_WALLET_ID = "vellar";

export class VellarModule {
  readonly moduleType = "HOT_WALLET";
  readonly productId = VELLAR_WALLET_ID;
  readonly productName = "Vellar";
  readonly productUrl = "https://vellar.xyz";
  readonly productIcon = "https://vellar.xyz/icon.png";

  private provider?: Sep43Provider;

  constructor(provider?: Sep43Provider) {
    this.provider = provider;
  }

  private getProvider(): Sep43Provider {
    if (this.provider) return this.provider;
    if (typeof window !== "undefined") {
      const w = window as unknown as { stellar?: Sep43Provider; vela?: { sep43?: Sep43Provider } };
      if (w.stellar) return w.stellar;
      if (w.vela?.sep43) return w.vela.sep43;
    }
    throw { code: -3, message: "Vellar wallet extension is not installed" };
  }

  async isAvailable(): Promise<boolean> {
    if (this.provider) return this.provider.isAvailable();
    if (typeof window === "undefined") return false;
    const w = window as unknown as { stellar?: Sep43Provider; vela?: unknown };
    return !!(w.stellar || w.vela);
  }

  async getAddress(params?: Sep43GetAddressOptions): Promise<{ address: string }> {
    return this.getProvider().getAddress(params);
  }

  async signTransaction(
    xdr: string,
    opts?: Sep43SignTransactionOptions,
  ): Promise<{ signedTxXdr: string; signerAddress?: string }> {
    return this.getProvider().signTransaction(xdr, opts);
  }

  async signAuthEntry(
    authEntry: string,
    opts?: Sep43SignAuthEntryOptions,
  ): Promise<{ signedAuthEntry: string; signerAddress?: string }> {
    return this.getProvider().signAuthEntry(authEntry, opts);
  }

  async signMessage(
    message: string,
    opts?: Sep43SignMessageOptions,
  ): Promise<{ signedMessage: string; signerAddress?: string }> {
    return this.getProvider().signMessage(message, opts);
  }

  async getNetwork(): Promise<{ network: string; networkPassphrase: string }> {
    return this.getProvider().getNetwork();
  }

  async disconnect(): Promise<void> {
    return this.getProvider().disconnect();
  }
}
