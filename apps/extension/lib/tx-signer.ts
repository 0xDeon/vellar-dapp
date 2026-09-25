import { Buffer } from "buffer";
import type { xdr } from "@stellar/stellar-sdk";
import type { Signer } from "passkey-kit";
import { signWithDeviceKey } from "./device-key";
import {
  boundedExpirationLedger,
  configuredMainnetRpcUrl,
  resolveTrustedRpcUrl,
} from "./signer-expiration";
import type { PairedWallet } from "./state";

// Transaction signing with the device signer (docs/decisions.md option 1A).
// passkey-kit does the auth-entry mechanics (payload hashing, expiration,
// contract-ABI signature encoding); we supply a Signer backed by the
// NON-EXTRACTABLE WebCrypto key. Mirrors passkey-kit's own Ed25519Signer
// (dist/signers.js): key/value = { tag: "Ed25519", values: [bytes] }.

const NETWORK_PASSPHRASES = {
  testnet: "Test SDF Network ; September 2015",
  mainnet: "Public Global Stellar Network ; September 2015",
} as const;

export function createDeviceSigner(pair: CryptoKeyPair, rawPublicKey: Uint8Array): Signer {
  return {
    async sign(payload: Buffer) {
      const signature = await signWithDeviceKey(pair, new Uint8Array(payload));
      return {
        key: { tag: "Ed25519", values: [Buffer.from(rawPublicKey)] },
        value: { tag: "Ed25519", values: [Buffer.from(signature)] },
      };
    },
  };
}

export class PairedWalletMismatchError extends Error {
  constructor(expected: string, actual: string | undefined) {
    super(`Paired wallet is ${expected} but the passkey resolves to ${actual ?? "nothing"}`);
    this.name = "PairedWalletMismatchError";
  }
}

/**
 * Signs every auth entry of the transaction that the paired wallet must
 * authorize, using the device key, and returns the signed XDR. Attaches the
 * kit via connectWallet({ keyId }) — no WebAuthn ceremony; the kit verifies
 * on-chain that the keyId is a live signer of the resolved wallet.
 */
export async function signTransactionXdr(input: {
  xdr: string;
  wallet: PairedWallet;
  deviceKeyPair: CryptoKeyPair;
  deviceRawPublicKey: Uint8Array;
  /** Fetch the current ledger sequence from the TRUSTED per-network RPC (L4).
   * Injectable for tests; defaults to a live getLatestLedger against the
   * pinned/configured trusted endpoint — never the caller-supplied rpcUrl. */
  getTrustedLatestLedger?: (rpcUrl: string) => Promise<number>;
  /** Build-time mainnet trusted RPC (WXT_PUBLIC_MAINNET_RPC_URL). Injectable
   * for tests; defaults to the env value. */
  mainnetRpcUrl?: string;
}): Promise<string> {
  const { wallet } = input;
  const networkPassphrase = NETWORK_PASSPHRASES[wallet.network];

  const [{ PasskeyKit }, { Address, TransactionBuilder, xdr }] = await Promise.all([
    import("passkey-kit"),
    import("@stellar/stellar-sdk"),
  ]);

  const kit = new PasskeyKit({
    rpcUrl: wallet.rpcUrl,
    networkPassphrase,
    walletWasmHash: wallet.walletWasmHash,
  });
  await kit.connectWallet({ keyId: wallet.keyId });
  if (kit.contractId !== wallet.address) {
    throw new PairedWalletMismatchError(wallet.address, kit.contractId);
  }

  // L4: anchor the signature-expiration ledger on a TRUSTED RPC, then cap the
  // window — so the caller-supplied wallet.rpcUrl can never widen it. Fails
  // closed if no trusted RPC exists (e.g. mainnet with none configured).
  const trustedRpcUrl = resolveTrustedRpcUrl(
    wallet.network,
    input.mainnetRpcUrl ?? configuredMainnetRpcUrl(),
  );
  const fetchLedger = input.getTrustedLatestLedger ?? defaultTrustedLatestLedger;
  const anchorLedger = await fetchLedger(trustedRpcUrl);
  const expiration = boundedExpirationLedger(anchorLedger);

  const tx = TransactionBuilder.fromXDR(input.xdr, networkPassphrase);
  if (!("operations" in tx)) {
    throw new Error("Fee-bump transactions cannot be signed by the extension");
  }

  // The SorobanAddressCredentials across every address-bound variant, or
  // undefined for source-account. passkey-kit@0.14 signs V2 (upgrades V1 in
  // place, auth-payload.js:67), so a V1-only match (RA-1) skipped the wallet's
  // real entries and signed nothing. All three arms wrap the same struct.
  const addrCreds = (
    creds: ReturnType<xdr.SorobanAuthorizationEntry["credentials"]>,
  ): xdr.SorobanAddressCredentials | undefined => {
    switch (creds.switch().name) {
      case "sorobanCredentialsAddress":
        return creds.address();
      case "sorobanCredentialsAddressV2":
        return creds.addressV2();
      case "sorobanCredentialsAddressWithDelegates":
        return creds.addressWithDelegates().addressCredentials();
      default:
        return undefined; // sorobanCredentialsSourceAccount — not a wallet subject
    }
  };

  const signer = createDeviceSigner(input.deviceKeyPair, input.deviceRawPublicKey);
  let signedAny = false;

  for (const operation of tx.operations) {
    if (operation.type !== "invokeHostFunction" || !operation.auth) continue;
    for (let i = 0; i < operation.auth.length; i++) {
      const entry = operation.auth[i]!;
      const creds = addrCreds(entry.credentials());
      if (!creds) continue;
      if (Address.fromScAddress(creds.address()).toString() !== wallet.address) continue;
      // Explicit expiration ⇒ the kit does NOT call getLatestLedger on the
      // caller's rpcUrl (L4).
      operation.auth[i] = await kit.signAuthEntry(entry, signer, { expiration });
      signedAny = true;
    }
  }

  if (!signedAny) {
    throw new Error("The transaction has no auth entries for the paired wallet");
  }

  return tx.toXDR();
}

/** Live getLatestLedger against the trusted RPC. A transport failure PROPAGATES
 * (fail closed) — we never fall back to the caller-supplied rpcUrl (L4). */
async function defaultTrustedLatestLedger(rpcUrl: string): Promise<number> {
  const { rpc } = await import("@stellar/stellar-sdk");
  const server = new rpc.Server(rpcUrl);
  const { sequence } = await server.getLatestLedger();
  return sequence;
}

/**
 * Signs a single SorobanAuthorizationEntry XDR for the paired wallet.
 */
export async function signAuthEntryXdr(input: {
  authEntry: string;
  wallet: PairedWallet;
  deviceKeyPair: CryptoKeyPair;
  deviceRawPublicKey: Uint8Array;
  getTrustedLatestLedger?: (rpcUrl: string) => Promise<number>;
  mainnetRpcUrl?: string;
}): Promise<string> {
  const { wallet } = input;
  const networkPassphrase = NETWORK_PASSPHRASES[wallet.network];

  const [{ PasskeyKit }, { xdr }] = await Promise.all([
    import("passkey-kit"),
    import("@stellar/stellar-sdk"),
  ]);

  const kit = new PasskeyKit({
    rpcUrl: wallet.rpcUrl,
    networkPassphrase,
    walletWasmHash: wallet.walletWasmHash,
  });
  await kit.connectWallet({ keyId: wallet.keyId });
  if (kit.contractId !== wallet.address) {
    throw new PairedWalletMismatchError(wallet.address, kit.contractId);
  }

  const trustedRpcUrl = resolveTrustedRpcUrl(
    wallet.network,
    input.mainnetRpcUrl ?? configuredMainnetRpcUrl(),
  );
  const fetchLedger = input.getTrustedLatestLedger ?? defaultTrustedLatestLedger;
  const anchorLedger = await fetchLedger(trustedRpcUrl);
  const expiration = boundedExpirationLedger(anchorLedger);

  const entry = xdr.SorobanAuthorizationEntry.fromXDR(input.authEntry, "base64");
  const signer = createDeviceSigner(input.deviceKeyPair, input.deviceRawPublicKey);
  const signed = await kit.signAuthEntry(entry, signer, { expiration });
  return signed.toXDR("base64");
}

/**
 * Signs an arbitrary message using the non-extractable device key.
 */
export async function signMessageBytes(input: {
  message: string;
  deviceKeyPair: CryptoKeyPair;
}): Promise<string> {
  const bytes = new TextEncoder().encode(input.message);
  const signature = await signWithDeviceKey(input.deviceKeyPair, bytes);
  return Buffer.from(signature).toString("base64");
}
