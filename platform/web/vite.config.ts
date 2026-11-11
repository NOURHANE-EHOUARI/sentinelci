/// <reference types="vitest/config" />
// The dashboard (task B7). In development and preview, /api and /metrics go to the platform API
// (SENTINEL_API_URL, default the local Compose API on 127.0.0.1:8000): same origin, so the API needs no CORS.
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

declare const process: { env: Record<string, string | undefined> }; // Node, which runs this file

const api = process.env.SENTINEL_API_URL ?? "http://127.0.0.1:8000";
const proxy = { "/api": api, "/metrics": api };

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy },
  preview: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
  build: { sourcemap: false },
  test: { environment: "jsdom", include: ["src/**/*.test.{ts,tsx}"], setupFiles: ["src/setup-tests.ts"], restoreMocks: true },
});
