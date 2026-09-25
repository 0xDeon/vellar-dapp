import { publisherIdFor } from "@vellar/service-kit";
import type { ContractArtifactResolver } from "./resolver";
import { ArtifactResolveError } from "./resolver";
import type { VerificationOutcome } from "./verify";

// The attestor: mirrors verification outcomes into the on-chain
// AttestationRegistry (docs/design-provenance-gated-spending.md §Component 3).
//
//   verified (with a rebuilt hash)  → upsert(contract, hash, now + TTL), or
//                                     upsertWithPublisher(...) when the record's
//                                     repoUrl attributes the source to an owner
//   failed                          → revoke IF currently attested
//   upgrade sweep                   → revoke when the live on-chain wasm hash
//                                     no longer matches the attested one, or
//                                     the contract vanished
//
// Attestation is strictly best-effort relative to the verification pipeline:
// a registry outage or a bad submission must NEVER fail or retry-loop the
// verification job itself (the record is the system of record; the registry
// is a mirror). Every entry point here therefore swallows its own errors and
// reports them via log/metrics only.
//
// Honesty rule carried from the design doc: attestations follow REAL
// verification runs. The sweep only ever revokes — it never re-attests or
// extends expiry, so an attestation can only be renewed by a fresh rebuild.
// Silence decays to unverified on-chain by expiry.

/** The narrow on-chain surface the attestor needs. Implemented for real by
 * `registry-submitter.ts`; faked in tests. */
export interface AttestationSubmitter {
  upsert(contractId: string, wasmHashHex: string, expiresLedger: number): Promise<void>;
  /** Attributed attestation: same as `upsert` plus the 32-byte publisher id
   * (hex) derived from the verified source's owner (`publisherIdFor`). Consumed
   * by the verified-recipient policy's trusted-publishers mode. */
  upsertWithPublisher(
    contractId: string,
    wasmHashHex: string,
    publisherIdHex: string,
    expiresLedger: number,
  ): Promise<void>;
  revoke(contractId: string): Promise<void>;
  /** Whether the registry currently holds an attestation for the contract
   * (live or logically expired). Used to avoid paying for no-op revokes. */
  isAttested(contractId: string): Promise<boolean>;
  currentLedger(): Promise<number>;
}

/** Watch-list source for the upgrade sweep: the latest terminal verification
 * per contract, where that latest run is `verified`. */
export interface AttestableSource {
  listLatestVerified(limit: number): Promise<Array<{ contractId: string; outputHash: string }>>;
}

export interface AttestorMetrics {
  attestation(outcome: "upserted" | "revoked" | "error"): void;
}

export interface AttestorDeps {
  submitter: AttestationSubmitter;
  /** Attestation lifetime in ledgers. Default ~7 days at the historical 5s
   * close time — short by design (fail-closed decay). */
  ttlLedgers?: number;
  log?: { info: (msg: string) => void; error: (msg: string, err?: unknown) => void };
  metrics?: AttestorMetrics;
}

/** Where the verified source came from — drives publisher attribution. */
export interface AttestationSource {
  /** The record's repository URL (repo-sourced verifications only). */
  repoUrl?: string;
}

export interface Attestor {
  /** Mirror one verification outcome. Never throws. When `source.repoUrl`
   * identifies a repository owner the attestation is attributed to that
   * publisher; otherwise it is written unattributed (verified, never trusted). */
  reportOutcome(
    contractId: string,
    outcome: VerificationOutcome,
    source?: AttestationSource,
  ): Promise<void>;
  /** Revoke attestations whose contract was upgraded (live hash drift) or
   * deleted. Never throws; returns how many were revoked. */
  runUpgradeSweep(
    source: AttestableSource,
    resolver: ContractArtifactResolver,
    limit?: number,
  ): Promise<number>;
}

const DEFAULT_TTL_LEDGERS = (60 * 60 * 24 * 7) / 5;
const silentLog = { info: () => {}, error: () => {} };
const noopMetrics: AttestorMetrics = { attestation: () => {} };

export function createAttestor(deps: AttestorDeps): Attestor {
  const ttl = deps.ttlLedgers ?? DEFAULT_TTL_LEDGERS;
  const log = deps.log ?? silentLog;
  const metrics = deps.metrics ?? noopMetrics;

  return {
    async reportOutcome(contractId, outcome, source) {
      try {
        if (outcome.status === "verified") {
          if (!outcome.outputHash) {
            // A verified outcome always carries the rebuilt hash today; guard
            // anyway — attesting without a hash would be an empty claim.
            log.error(`attestor: verified outcome for ${contractId} lacks outputHash; skipping`);
            return;
          }
          const now = await deps.submitter.currentLedger();
          const publisher = source?.repoUrl ? publisherIdFor(source.repoUrl) : undefined;
          if (publisher) {
            await deps.submitter.upsertWithPublisher(
              contractId,
              outcome.outputHash,
              publisher,
              now + ttl,
            );
          } else {
            await deps.submitter.upsert(contractId, outcome.outputHash, now + ttl);
          }
          metrics.attestation("upserted");
          log.info(
            `attestor: attested ${contractId} (${publisher ? "attributed" : "unattributed"}, expires in ${ttl} ledgers)`,
          );
          return;
        }

        // failed: kill any live attestation fast (the expiry backstop would
        // get there eventually; this is the fast path). Check first so the
        // common case — a failed verification for a never-attested contract —
        // costs a read, not a transaction.
        if (await deps.submitter.isAttested(contractId)) {
          await deps.submitter.revoke(contractId);
          metrics.attestation("revoked");
          log.info(`attestor: revoked ${contractId} (verification now failing)`);
        }
      } catch (err) {
        metrics.attestation("error");
        log.error(
          `attestor: mirroring outcome for ${contractId} failed (pipeline unaffected)`,
          err,
        );
      }
    },

    async runUpgradeSweep(source, resolver, limit = 100) {
      let revoked = 0;
      try {
        const watch = await source.listLatestVerified(limit);
        for (const { contractId, outputHash } of watch) {
          try {
            if (!(await deps.submitter.isAttested(contractId))) continue;

            let liveHash: string | undefined;
            try {
              liveHash = await resolver.resolveDeployedHash(contractId);
            } catch (err) {
              if (err instanceof ArtifactResolveError && err.code !== "rpc_error") {
                // not_found / not_wasm: the attested contract is gone or no
                // longer a wasm contract — the attestation is stale, kill it.
                liveHash = undefined;
              } else {
                // Transient RPC trouble: skip, never revoke on uncertainty.
                continue;
              }
            }

            if (liveHash !== outputHash) {
              await deps.submitter.revoke(contractId);
              metrics.attestation("revoked");
              revoked += 1;
              log.info(
                `attestor: revoked ${contractId} (live hash ${liveHash ?? "absent"} != attested ${outputHash})`,
              );
            }
          } catch (err) {
            metrics.attestation("error");
            log.error(`attestor: sweep failed for ${contractId} (continuing)`, err);
          }
        }
      } catch (err) {
        metrics.attestation("error");
        log.error("attestor: upgrade sweep failed", err);
      }
      return revoked;
    },
  };
}
