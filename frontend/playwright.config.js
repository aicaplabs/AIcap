// Wave 12: Playwright E2E configuration.
//
// Skeleton suite — runs against `npm run dev` in local mode (no
// Supabase env vars set), which renders LocalDashboard directly. Specs
// that need the cloud-mode landing page or an authenticated session
// are scaffolded with `test.fixme` and a TODO pointing at the missing
// fixture, so a future wave can wire real Supabase test creds without
// rewriting the suite.
//
// Run locally:   npm run test:e2e
// In CI:         the .github/workflows/go-test.yml `e2e` job invokes
//                playwright with --reporter=line, after installing the
//                Chromium browser bundle.

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'line' : 'html',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    actionTimeout: 5_000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run dev -- --port 5173',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
