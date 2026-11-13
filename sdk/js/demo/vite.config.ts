import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// The demo uses the SDK's source directly (no build step): `@blox/sdk` → ../src.
export default defineConfig({
  // Relative asset paths, so the build works under any path (relay.example.com/demo/).
  base: "./",
  resolve: {
    alias: {
      "@blox/sdk/wagmi": fileURLToPath(new URL("../src/wagmi.ts", import.meta.url)),
      "@blox/sdk": fileURLToPath(new URL("../src/index.ts", import.meta.url)),
    },
    dedupe: ["@noble/curves", "@noble/hashes", "@wagmi/core", "viem"],
  },
});
