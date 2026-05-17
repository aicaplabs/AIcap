// Shared Playwright helpers for the AIcap E2E suite.
//
// installLocalBackend installs route mocks for the endpoints the
// LocalDashboard hits on mount + interaction. Returns the mocked scan
// payload so specs can assert against it without re-importing the
// fixture.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export async function loadScanFixture() {
  const buf = await readFile(join(here, 'fixtures', 'scan.json'));
  return JSON.parse(buf.toString('utf8'));
}

export async function installLocalBackend(page, { scan } = {}) {
  const scanPayload = scan || (await loadScanFixture());

  await page.route('**/api/db-config', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ connected: false, enabled: false }),
    }),
  );
  await page.route('**/api/scan', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(scanPayload),
    }),
  );
  await page.route('**/api/history', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: '[]',
    }),
  );

  return scanPayload;
}
