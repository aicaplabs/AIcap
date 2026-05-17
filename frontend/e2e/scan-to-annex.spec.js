// Wave 12 critical path: open the local dashboard, observe the
// mocked scan render, generate the Annex IV preview, and trigger the
// download. Backend is fully mocked via Playwright route handlers so
// no Go server or Postgres is required.

import { test, expect } from '@playwright/test';
import { installLocalBackend } from './helpers.js';

test.describe('scan → Annex IV download', () => {
  test('renders mocked scan data and downloads the Annex IV markdown', async ({ page }) => {
    const scan = await installLocalBackend(page);

    await page.goto('/');

    // BOM table must surface the high-risk model from the fixture so
    // we know the LocalDashboard actually hydrated from /api/scan.
    await expect(page.getByText(scan.projectName)).toBeVisible();
    await expect(page.getByText('Llama-3-8B').first()).toBeVisible();

    // FinOps spot column (Wave 11) should render the spot $/mo cell.
    await expect(page.getByText('Spot $/mo')).toBeVisible();

    // Trigger Annex IV generation. The local-dev path is synchronous
    // when dbConfig.connected is false (no /api/save-proof round-trip),
    // so the preview block appears immediately.
    const generate = page.getByRole('button', { name: /generate markdown/i });
    await expect(generate).toBeVisible();
    await generate.click();

    // The preview header is the strongest visible signal that the
    // markdown builder ran successfully.
    await expect(
      page.getByRole('heading', { name: /annex iv/i }).first(),
    ).toBeVisible();

    // Download CTA must be clickable and produce a download event.
    const downloadButton = page.getByRole('button', { name: /download/i }).first();
    await expect(downloadButton).toBeVisible();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      downloadButton.click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/annex-iv.*\.md$/i);
  });
});
