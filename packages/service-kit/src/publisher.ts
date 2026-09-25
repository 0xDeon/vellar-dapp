import { createHash } from "node:crypto";

// Publisher identity for provenance attribution (verified-recipient policy,
// trusted-publishers mode; docs/design-provenance-gated-spending.md).
//
// A "publisher" is the party a verified contract's SOURCE is attributed to:
// the owner (user or org) of the repository the verification pipeline rebuilt
// from. It is derived deterministically from the record's repoUrl so that the
// attestor (worker-service) and the policy builder (policy-service) agree on
// the same 32-byte id without sharing state:
//
//   canonicalPublisher("https://github.com/Vellar-Wallet/vellar-dapp.git")
//     → "github.com/vellar-wallet"
//   publisherIdHex(...) → sha256 of that string, hex
//
// Attribution is exactly as strong as the verification pipeline's repoUrl
// handling: it says WHOSE source reproduced the deployed bytes, nothing about
// whether that source is benign or audited. Off-chain consumers must carry
// that framing (verified ≠ safe).

/**
 * Canonical publisher string for a source location: lower-cased host + first
 * path segment (the repository owner). Accepts a full URL, a scheme-less
 * `host/owner[/repo]`, or an already-canonical `host/owner`. Returns
 * `undefined` when no owner segment can be identified — an unattributable
 * source must never be attested to a publisher.
 */
export function canonicalPublisher(input: string): string | undefined {
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return undefined;
  }
  const host = url.hostname.toLowerCase();
  const owner = url.pathname
    .split("/")
    .map((s) => s.trim())
    .filter(Boolean)[0];
  if (!host || !owner) return undefined;
  const cleaned = owner.toLowerCase().replace(/\.git$/, "");
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(cleaned)) return undefined;
  return `${host}/${cleaned}`;
}

/** 32-byte publisher id (hex) for a canonical publisher string. */
export function publisherIdHex(canonical: string): string {
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/** Convenience: repoUrl / publisher string → 32-byte id (hex), or undefined
 * when the input cannot be attributed. */
export function publisherIdFor(input: string): string | undefined {
  const canonical = canonicalPublisher(input);
  return canonical ? publisherIdHex(canonical) : undefined;
}
