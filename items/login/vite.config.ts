import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// The page is served by Konklav at `/login/`. Assets are referenced
// relative to it, so a reverse proxy may mount Konklav under a prefix.
// `npm run dev` serves the page on :5174 and proxies Konklav's
// subject-facing surface from `mise run serve`.
const konklav = process.env.KONKLAV_SUBJECT_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  base: "./",
  plugins: [svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Konklav's Content-Security-Policy allows no inline scripts or styles.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    target: "es2022",
  },
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      "/v1": { target: konklav, changeOrigin: false },
      // The page is at / here, and at /login/ on Konklav.
      "/config.json": { target: konklav, changeOrigin: false, rewrite: () => "/login/config.json" },
    },
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
