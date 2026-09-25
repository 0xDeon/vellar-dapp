import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalPublisher, publisherIdFor, publisherIdHex } from "./publisher";

describe("canonicalPublisher", () => {
  it("reduces a repo URL to lower-cased host/owner", () => {
    expect(canonicalPublisher("https://github.com/Vellar-Wallet/vellar-dapp.git")).toBe(
      "github.com/vellar-wallet",
    );
    expect(canonicalPublisher("https://GitHub.com/Vellar-Wallet/vellar-dapp/")).toBe(
      "github.com/vellar-wallet",
    );
    expect(canonicalPublisher("github.com/vellar-wallet")).toBe("github.com/vellar-wallet");
    expect(canonicalPublisher("  github.com/Vellar-Wallet/  ")).toBe("github.com/vellar-wallet");
  });

  it("is the same id for every repo under one owner and different across owners", () => {
    const a = publisherIdFor("https://github.com/acme/one");
    const b = publisherIdFor("https://github.com/acme/two");
    const c = publisherIdFor("https://github.com/other/one");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses inputs without an owner segment (never attribute the unattributable)", () => {
    expect(canonicalPublisher("https://github.com")).toBeUndefined();
    expect(canonicalPublisher("https://github.com/")).toBeUndefined();
    expect(canonicalPublisher("")).toBeUndefined();
    expect(canonicalPublisher("not a url at all ???")).toBeUndefined();
    expect(publisherIdFor("https://github.com/")).toBeUndefined();
  });

  it("does not let userinfo, port or query smuggle a different owner", () => {
    expect(canonicalPublisher("https://evil@github.com:443/acme/repo?x=1#f")).toBe(
      "github.com/acme",
    );
  });

  it("publisherIdHex is sha256 of the canonical string", () => {
    const expected = createHash("sha256").update("github.com/acme", "utf8").digest("hex");
    expect(publisherIdHex("github.com/acme")).toBe(expected);
    expect(publisherIdFor("https://github.com/ACME/repo")).toBe(expected);
  });
});
