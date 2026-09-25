import { describe, expect, it } from "vitest";
import {
  canonicalizeJobPayload,
  signJobPayload,
  verifyJobSignature,
  type VerificationJobPayload,
} from "./job-signature";

describe("Job Payload Signature Hardening (Phase 7 / #421)", () => {
  const secret = "super-secret-build-worker-key-12345678";
  const validJob: VerificationJobPayload = {
    contractId: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    sourceType: "repo",
    repoUrl: "https://github.com/example/contract",
    commitHash: "0123456789abcdef0123456789abcdef01234567",
    toolchainVersion: "1.94.0",
    buildFlags: ["--release"],
    timestamp: 1720000000000,
  };

  it("canonicalizes job payload deterministically", () => {
    const str1 = canonicalizeJobPayload(validJob);
    const str2 = canonicalizeJobPayload({ ...validJob });
    expect(str1).toBe(str2);
  });

  it("generates and verifies valid HMAC-SHA256 signature", () => {
    const signature = signJobPayload(validJob, secret);
    const jobWithSig: VerificationJobPayload = {
      ...validJob,
      signature,
    };
    const result = verifyJobSignature(jobWithSig, secret);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("fails closed when signature is missing", () => {
    const result = verifyJobSignature(validJob, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("missing_signature");
  });

  it("fails closed when job payload is tampered (e.g. modified commitHash)", () => {
    const signature = signJobPayload(validJob, secret);
    const tamperedJob: VerificationJobPayload = {
      ...validJob,
      commitHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      signature,
    };
    const result = verifyJobSignature(tamperedJob, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  it("fails closed when verified with wrong secret", () => {
    const signature = signJobPayload(validJob, secret);
    const jobWithSig: VerificationJobPayload = {
      ...validJob,
      signature,
    };
    const result = verifyJobSignature(jobWithSig, "wrong-secret-key-0000000000000000");
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  it("detects expired signatures when maxAgeMs is configured", () => {
    const now = 1720000000000;
    const oldJob: VerificationJobPayload = {
      ...validJob,
      timestamp: now - 3600_000, // 1 hour ago
    };
    const signature = signJobPayload(oldJob, secret);
    const jobWithSig: VerificationJobPayload = {
      ...oldJob,
      signature,
    };

    const result = verifyJobSignature(jobWithSig, secret, {
      maxAgeMs: 300_000, // 5 minute max age
      nowMs: now,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
  });
});
