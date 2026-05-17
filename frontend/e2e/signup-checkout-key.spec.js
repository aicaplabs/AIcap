// Wave 12 critical path: signup → Stripe checkout → key reveal.
//
// Currently scaffolded but not exercised. The path crosses two third-
// party boundaries (Supabase auth, Stripe Checkout) and the cloud-mode
// LandingAuth screen is keyed on `VITE_API_URL !== "http://localhost:8080"`
// — the Playwright config runs the dev server in local mode so the
// landing page never appears.
//
// To enable this test:
//   1. Add a second playwright project that starts a Vite server with
//      VITE_API_URL set to a non-localhost value (cloud mode).
//   2. Mock supabase-js's `/auth/v1/*` endpoints so signInWithPassword
//      / signUp return a fake session, and the supabase client never
//      reaches the real Supabase host.
//   3. Mock /api/me, /api/generate-key, /api/verify-checkout to drive
//      the checkout-return fallback chain to completion.
//   4. Mock /api/create-checkout-session to return a Playwright-served
//      stub page that simulates the Stripe redirect.
//
// Until then this spec runs as a fixme so CI surfaces the gap without
// failing the build.

import { test, expect } from '@playwright/test';

test.describe('signup → checkout → key reveal', () => {
  test.fixme('completes the Pro upgrade flow end-to-end', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: /sign in|sign up/i })).toBeVisible();
    // TODO(W12.5): drive the form, mock Supabase + Stripe, assert key reveal.
  });
});
