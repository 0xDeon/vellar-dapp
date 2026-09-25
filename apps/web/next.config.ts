import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Workspace packages ship raw TypeScript (exports point at src/), so Next
  // must transpile them. passkey-kit and its SDK deps also ship raw TS.
  transpilePackages: [
    "passkey-kit",
    "passkey-kit-sdk",
    "sac-sdk",
    "@vellar/types",
    "@vellar/ui",
    "vellar-sdk",
    "@vellar/passkey",
    "@vellar/provider-sdk",
    "@vellar/verification-sdk",
  ],
};

export default nextConfig;
