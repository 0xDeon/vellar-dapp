import type { AgentKeyMaterial } from "./agent-mint";

// Agent key generation (#394, technical-doc.md §17.4). The agent's ed25519
// keypair is generated in the browser from the platform CSPRNG
// (`crypto.getRandomValues`) and handed to the operator exactly once; this
// module never stores it, never logs it, and zeroes the seed after use.
//
// Why not a non-extractable WebCrypto key: the whole point of a session key
// is that the OPERATOR runs it headlessly elsewhere (`createSessionKeySigner`
// takes the S… secret), so the material must leave this page once. A
// non-extractable key would make the mint flow useless to the agent it is for.
// The non-extractable recommendation applies to the agent RUNTIME holding the
// key (open-work-catalogue 2.3), not to the mint UI. What this module
// guarantees instead: CSPRNG entropy, no persistence, no logging, one reveal.

export async function generateAgentKey(): Promise<AgentKeyMaterial> {
  const { Keypair } = await import("@stellar/stellar-sdk");
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  try {
    const kp = Keypair.fromRawEd25519Seed(Buffer.from(seed));
    return { publicKey: kp.publicKey(), secret: kp.secret() };
  } finally {
    seed.fill(0);
  }
}

/** Never let key material reach a log line or an error message. */
export function redactSecrets(text: string): string {
  return text.replace(/S[A-Z2-7]{55}/g, "S…[redacted]");
}
