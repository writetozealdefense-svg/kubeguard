import { defineConfig, devices } from "@playwright/test";

// E2E config. Runs the dashboard in mock mode (VITE_USE_MOCK=1) so the login
// flow + role gating are exercised end-to-end in a real browser without a live
// backend. Backend auth/RBAC is covered separately by the Go tests.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "list" : "list",
  use: {
    baseURL: "http://localhost:4173",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // VITE_USE_MOCK (from env below) is inlined at BUILD time, so build + preview
    // run under it. env applies to the whole command cross-platform.
    command: "npm run build && npm run preview -- --port 4173 --strictPort",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    env: { VITE_USE_MOCK: "1" },
  },
});
