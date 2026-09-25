import {
  BASE_FEE,
  Operation,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
  scValToNative,
  xdr,
  hash,
  rpc,
  Address,
} from "@stellar/stellar-sdk";
import type { AttestationSubmitter } from "./attestor";

// Threshold attestor key management and submission (#422).
//
// In M5, the single G-address attestor is replaced by a Soroban smart-account
// (C-address) implementing CustomAccountInterface with M-of-N threshold auth.
// Submitting an attestation (upsert/revoke) requires building a Soroban
// authorization entry with threshold signatures from distinct configured
// signers.
//
// Fast-path revocation is supported: the contract can enforce a lower or equal
// threshold for revocation (e.g. 1-of-N or 2-of-N) so compromised or broken
// contracts can be revoked with minimal latency, while upserts strictly require
// the full M-of-N consensus.

export interface AttestorKeyInfo {
  index: number;
  keypair: Keypair;
}

export class ThresholdKeyManager {
  private readonly signers: AttestorKeyInfo[];

  constructor(secretKeys: string[]) {
    if (secretKeys.length === 0) {
      throw new Error("ThresholdKeyManager requires at least 1 signer key");
    }
    this.signers = secretKeys.map((sec, idx) => ({
      index: idx,
      keypair: Keypair.fromSecret(sec),
    }));
  }

  get count(): number {
    return this.signers.length;
  }

  getPublicKeys(): string[] {
    return this.signers.map((s) => s.keypair.publicKey());
  }

  getRawPublicKeys(): Buffer[] {
    return this.signers.map((s) => s.keypair.rawPublicKey());
  }

  /**
   * Signs a 32-byte payload hash using the first `requiredCount` signers,
   * sorted by strictly ascending `signer_index`.
   */
  signPayload(
    payloadHash: Buffer,
    requiredCount: number,
  ): Array<{ signerIndex: number; signature: Buffer }> {
    if (requiredCount > this.signers.length) {
      throw new Error(
        `Cannot produce ${requiredCount} signatures with only ${this.signers.length} configured signers`,
      );
    }

    // Sort signers by index ascending
    const selected = this.signers.slice(0, requiredCount).sort((a, b) => a.index - b.index);

    return selected.map((s) => ({
      signerIndex: s.index,
      signature: s.keypair.sign(payloadHash),
    }));
  }
}

export interface ThresholdSubmitterOptions {
  rpcUrl: string;
  networkPassphrase: string;
  registryContractId: string;
  thresholdAttestorContractId: string;
  /** Relayer / sponsor key that pays gas and sequence for the transaction envelope */
  relayerSecretKey: string;
  keyManager: ThresholdKeyManager;
  attestThreshold: number;
  revokeThreshold?: number;
  server?: Pick<
    rpc.Server,
    | "getAccount"
    | "simulateTransaction"
    | "prepareTransaction"
    | "sendTransaction"
    | "getTransaction"
    | "getLatestLedger"
  >;
}

export interface ThresholdAttestationSubmitter extends AttestationSubmitter {
  measureRevocationLatencyMs(contractId: string): Promise<number>;
}

export function createThresholdSubmitter(
  options: ThresholdSubmitterOptions,
): ThresholdAttestationSubmitter {
  const server = options.server ?? new rpc.Server(options.rpcUrl);
  const relayerKeypair = Keypair.fromSecret(options.relayerSecretKey);
  const registry = new Contract(options.registryContractId);
  const attestThreshold = options.attestThreshold;
  const revokeThreshold = options.revokeThreshold ?? options.attestThreshold;

  function buildThresholdSignaturesScVal(
    signatures: Array<{ signerIndex: number; signature: Buffer }>,
  ): xdr.ScVal {
    const sigEntries = signatures.map((s) => {
      return xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("signature"),
          val: nativeToScVal(s.signature, { type: "bytes" }),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("signer_index"),
          val: nativeToScVal(s.signerIndex, { type: "u32" }),
        }),
      ]);
    });

    return xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("signatures"),
        val: xdr.ScVal.scvVec(sigEntries),
      }),
    ]);
  }

  async function invokeWithThreshold(
    method: "upsert" | "upsert_with_publisher" | "revoke",
    args: xdr.ScVal[],
  ): Promise<{ latencyMs: number }> {
    const startTime = Date.now();
    const requiredThreshold = method === "revoke" ? revokeThreshold : attestThreshold;

    const account = await server.getAccount(relayerKeypair.publicKey());

    // Build the SorobanAuthorizationEntry for the threshold attestor smart account
    const attestorScAddress = Address.fromString(options.thresholdAttestorContractId).toScAddress();

    const rootInvocation = new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(options.registryContractId).toScAddress(),
          functionName: method,
          args,
        }),
      ),
      subInvocations: [],
    });

    const signatureExpirationLedger = (await server.getLatestLedger()).sequence + 100;
    const credsPre = new xdr.SorobanAddressCredentials({
      address: attestorScAddress,
      nonce: xdr.Int64.fromString("0"),
      signatureExpirationLedger,
      signature: xdr.ScVal.scvVoid(),
    });

    const preEntry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(credsPre),
      rootInvocation,
    });

    // Hash of the authorization entry payload according to Soroban host specs
    const payloadHash = hash(
      Buffer.concat([Buffer.from(options.networkPassphrase), preEntry.toXDR()]),
    );

    // Collect threshold signatures
    const collected = options.keyManager.signPayload(payloadHash, requiredThreshold);
    const signatureVal = buildThresholdSignaturesScVal(collected);

    const credsSigned = new xdr.SorobanAddressCredentials({
      address: attestorScAddress,
      nonce: xdr.Int64.fromString("0"),
      signatureExpirationLedger,
      signature: signatureVal,
    });

    const signedAuthEntry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(credsSigned),
      rootInvocation,
    });

    const opWithAuth = Operation.invokeContractFunction({
      contract: options.registryContractId,
      function: method,
      args,
      auth: [signedAuthEntry],
    });

    const txWithAuth = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase: options.networkPassphrase,
    })
      .addOperation(opWithAuth)
      .setTimeout(30)
      .build();

    const prepared = await server.prepareTransaction(txWithAuth);
    prepared.sign(relayerKeypair);

    const sent = await server.sendTransaction(prepared);
    if (sent.status === "ERROR") {
      throw new Error(
        `threshold registry ${method} submission rejected: ${JSON.stringify(sent.errorResult)}`,
      );
    }

    for (let i = 0; i < 30; i++) {
      const result = await server.getTransaction(sent.hash);
      if (result.status === "SUCCESS") {
        const latencyMs = Date.now() - startTime;
        return { latencyMs };
      }
      if (result.status === "FAILED") {
        throw new Error(`threshold registry ${method} failed on-chain (tx ${sent.hash})`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    throw new Error(`threshold registry ${method} not final after 15s (tx ${sent.hash})`);
  }

  async function simulateRead(method: string, args: xdr.ScVal[]) {
    const account = await server.getAccount(relayerKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase: options.networkPassphrase,
    })
      .addOperation(registry.call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await server.simulateTransaction(tx);
    if (!rpc.Api.isSimulationSuccess(sim)) {
      throw new Error(`threshold registry ${method} simulation failed`);
    }
    return sim.result?.retval;
  }

  return {
    async upsert(contractId, wasmHashHex, expiresLedger) {
      const hashBuf = Buffer.from(wasmHashHex, "hex");
      if (hashBuf.length !== 32) {
        throw new Error(`attested wasm hash must be 32 bytes, got ${hashBuf.length}`);
      }
      await invokeWithThreshold("upsert", [
        nativeToScVal(contractId, { type: "address" }),
        nativeToScVal(hashBuf, { type: "bytes" }),
        nativeToScVal(expiresLedger, { type: "u32" }),
      ]);
    },

    async upsertWithPublisher(contractId, wasmHashHex, publisherIdHex, expiresLedger) {
      const hashBuf = Buffer.from(wasmHashHex, "hex");
      if (hashBuf.length !== 32) {
        throw new Error(`attested wasm hash must be 32 bytes, got ${hashBuf.length}`);
      }
      const publisher = Buffer.from(publisherIdHex, "hex");
      if (publisher.length !== 32) {
        throw new Error(`publisher id must be 32 bytes, got ${publisher.length}`);
      }
      await invokeWithThreshold("upsert_with_publisher", [
        nativeToScVal(contractId, { type: "address" }),
        nativeToScVal(hashBuf, { type: "bytes" }),
        nativeToScVal(publisher, { type: "bytes" }),
        nativeToScVal(expiresLedger, { type: "u32" }),
      ]);
    },

    async revoke(contractId) {
      await invokeWithThreshold("revoke", [nativeToScVal(contractId, { type: "address" })]);
    },

    async measureRevocationLatencyMs(contractId: string): Promise<number> {
      const { latencyMs } = await invokeWithThreshold("revoke", [
        nativeToScVal(contractId, { type: "address" }),
      ]);
      return latencyMs;
    },

    async isAttested(contractId) {
      const retval = await simulateRead("attestation", [
        nativeToScVal(contractId, { type: "address" }),
      ]);
      if (!retval) return false;
      const native = scValToNative(retval);
      return native !== null && native !== undefined;
    },

    async currentLedger() {
      const latest = await server.getLatestLedger();
      return latest.sequence;
    },
  };
}
