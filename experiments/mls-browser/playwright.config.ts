import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  outputDir: "./test-results",
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
  webServer: {
    command: "npm run serve",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 10_000,
  },
  use: {
    baseURL: "http://127.0.0.1:4173",
    headless: true,
  },
});
