import {
  Address,
  StrKey,
  buildAuthorizationEntryPreimage,
  hash,
  xdr,
} from "@stellar/stellar-sdk";

export interface NonExtractableAgentKey {
  /** The Ed25519 CryptoKeyPair held in memory with extractable: false */
  keyPair: CryptoKeyPair;
  /** Raw 32-byte public key buffer */
  rawPublicKey: Uint8Array;
  /** Stellar G... public key string */
  stellarPublicKey: string;
}

/**
 * Generate a non-extractable Ed25519 signing key using the WebCrypto API (§17.4).
 * The private key has `extractable: false`, meaning private key bytes CANNOT be
 * exported, printed, or saved to disk.
 */
export async function generateNonExtractableAgentKey(): Promise<NonExtractableAgentKey> {
  const keyPair = (await crypto.subtle.generateKey("Ed25519", false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  if (keyPair.privateKey.extractable) {
    throw new Error("Security violation: private key must be non-extractable (§17.4)");
  }

  const rawPublicKeyBuffer = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const rawPublicKey = new Uint8Array(rawPublicKeyBuffer);
  const stellarPublicKey = StrKey.encodeEd25519PublicKey(Buffer.from(rawPublicKey));

  return {
    keyPair,
    rawPublicKey,
    stellarPublicKey,
  };
}

export interface WebCryptoSignerOptions {
  /** The C-address of the paying Vellar smart account */
  address: string;
  /** The non-extractable agent key */
  agentKey: NonExtractableAgentKey;
  /** Optional policy contract IDs attached to this agent key */
  policies?: string[];
}

export interface SmartAccountX402Signer {
  readonly address: string;
  signAuthEntry(
    entryXdr: string,
    opts: { networkPassphrase: string; expirationLedger: number },
  ): Promise<string>;
}

function comparePolicyAddresses(a: string, b: string): number {
  const ab = new Address(a).toBuffer();
  const bb = new Address(b).toBuffer();
  for (let i = 0; i < Math.min(ab.length, bb.length); i++) {
    const diff = (ab[i] ?? 0) - (bb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return ab.length - bb.length;
}

function ed25519SignerKey(rawPk: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("Ed25519"),
    xdr.ScVal.scvBytes(Buffer.from(rawPk)),
  ]);
}

function ed25519Signature(sig: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("Ed25519"),
    xdr.ScVal.scvBytes(Buffer.from(sig)),
  ]);
}

function policySignerKey(policyAddress: string): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("Policy"),
    new Address(policyAddress).toScVal(),
  ]);
}

function policySignature(): xdr.ScVal {
  return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Policy")]);
}

/**
 * Creates a SmartAccountX402Signer backed by a non-extractable WebCrypto key.
 * Signs V1 (sorobanCredentialsAddress) auth entries as required by x402 facilitators (§17.5).
 */
export function createWebCryptoSessionKeySigner(
  options: WebCryptoSignerOptions,
): SmartAccountX402Signer {
  const { address, agentKey, policies = [] } = options;

  return {
    address,
    async signAuthEntry(entryXdr, { networkPassphrase, expirationLedger }) {
      const entry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, "base64");
      const creds = entry.credentials();

      if (creds.switch().name !== "sorobanCredentialsAddress") {
        throw new Error(
          `x402 signer expects V1 sorobanCredentialsAddress, got ${creds.switch().name} (§17.5)`,
        );
      }

      creds.address().signatureExpirationLedger(expirationLedger);
      const preimage = buildAuthorizationEntryPreimage(
        entry,
        expirationLedger,
        networkPassphrase,
      );
      const payloadHash = hash(preimage.toXDR());

      // Sign the payload hash using the non-extractable WebCrypto private key
      const signatureBuffer = await crypto.subtle.sign(
        "Ed25519",
        agentKey.keyPair.privateKey,
        new Uint8Array(payloadHash),
      );
      const signature = new Uint8Array(signatureBuffer);

      // Build signature map: [Ed25519 -> sig, Policy -> policySig...]
      const entries: xdr.ScMapEntry[] = [
        new xdr.ScMapEntry({
          key: ed25519SignerKey(agentKey.rawPublicKey),
          val: ed25519Signature(signature),
        }),
      ];

      for (const policy of [...policies].sort(comparePolicyAddresses)) {
        entries.push(
          new xdr.ScMapEntry({
            key: policySignerKey(policy),
            val: policySignature(),
          }),
        );
      }

      entry
        .credentials()
        .address()
        .signature(xdr.ScVal.scvVec([xdr.ScVal.scvMap(entries)]));

      return entry.toXDR("base64");
    },
  };
}
