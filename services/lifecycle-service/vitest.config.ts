import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    server: {
      deps: {
        inline: ["passkey-kit", "passkey-kit-sdk", "sac-sdk"],
      },
    },
  },
});
