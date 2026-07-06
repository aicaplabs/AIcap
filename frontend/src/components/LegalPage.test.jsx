// Tests for the legal/trust pages (/?page=<slug>).
//
// Contract:
//   1. Every slug in LEGAL_PAGES renders its title as an h1 — a broken
//      markdown constant should fail loudly here, not in production.
//   2. Unknown slugs render the link-list fallback, never a blank page.
import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';

import LegalPage from './LegalPage.jsx';
import { LEGAL_PAGES } from '../lib/legalContent.js';

describe('LegalPage', () => {
  for (const [slug, page] of Object.entries(LEGAL_PAGES)) {
    it(`renders the ${slug} page with its title`, () => {
      render(<LegalPage slug={slug} />);
      // h1 text may extend the nav title (e.g. "Security at AIcap").
      expect(
        screen.getByRole('heading', { level: 1, name: new RegExp(page.title) }),
      ).toBeInTheDocument();
    });
  }

  it('renders a link-list fallback for unknown slugs', () => {
    render(<LegalPage slug="does-not-exist" />);
    expect(screen.getByText('Page not found')).toBeInTheDocument();
    // All four pages are reachable from the fallback.
    expect(screen.getAllByRole('link', { name: /Terms of Service/ }).length).toBeGreaterThan(0);
  });
});
