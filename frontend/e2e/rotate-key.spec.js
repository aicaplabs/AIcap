// Wave 12 critical path: rotate the API key from the Pro dashboard.
//
// Currently scaffolded but not exercised. The rotate-key button lives
// inside KeyVault → ProDashboard which only renders when an
// authenticated Supabase session exists. Until the Supabase auth
// mocking layer is in place (see signup-checkout-key.spec.js), this
// spec runs as a fixme so the gap is visible without failing CI.

import { test, expect } from '@playwright/test';

test.describe('rotate-key', () => {
  test.fixme('rotates the API key from the Pro dashboard', async ({ page }) => {
    await page.goto('/');
    // TODO(W12.5): seed a fake Pro session, mock /api/rotate-key,
    // click the rotate CTA in KeyVault, assert the new key is revealed
    // exactly once and the previous key UI is replaced.
    await expect(page.getByRole('button', { name: /rotate/i })).toBeVisible();
  });
});
