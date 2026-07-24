// Pricing-tier copy test.
//
// This exists because the tier lists drifted out of sync with the
// product once already: the Free column claimed Annex IV generation the
// CLI did not do, while the Pro column claimed OSV enrichment and GPU
// cost estimates that in fact run for free. Both directions are damaging
// — one overpromises to a buyer, the other hides value from them — and
// neither is caught by any other test, because pricing copy is the one
// part of the app with no runtime behaviour to fail.
//
// These assertions pin the free/paid boundary as decided: generation is
// free, attestation is paid.
import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';

import PricingSection from './PricingSection.jsx';

/** Returns the <article> card whose heading matches `name`. */
function card(name) {
  const heading = screen.getByRole('heading', { name });
  const article = heading.closest('article');
  if (!article) throw new Error(`no card found for heading "${name}"`);
  return within(article);
}

describe('PricingSection', () => {
  it('renders all three tiers', () => {
    render(<PricingSection />);
    expect(screen.getByRole('heading', { name: /free cli/i })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^pro$/i })).toBeTruthy();
  });

  it('lists the analysis features under Free, not Pro', () => {
    // Everything the CLI computes locally is free. Listing any of it as
    // a Pro feature understates the free tier and misrepresents the
    // product to someone comparing columns.
    render(<PricingSection />);
    const free = card(/free cli/i);

    expect(free.getByText(/annex iv/i)).toBeTruthy();
    expect(free.getByText(/risk register/i)).toBeTruthy();
    expect(free.getByText(/osv/i)).toBeTruthy();
    expect(free.getByText(/finops/i)).toBeTruthy();
  });

  it('marks the free Annex IV draft as unattested', () => {
    // The honest half of the bargain: the free document is real, and it
    // says on its face that it cannot be independently verified.
    render(<PricingSection />);
    expect(card(/free cli/i).getByText(/unattested/i)).toBeTruthy();
  });

  it('sells Pro on provenance rather than on analysis', () => {
    render(<PricingSection />);
    const pro = card(/^pro$/i);

    expect(pro.getAllByText(/ledger/i).length).toBeGreaterThan(0);
    expect(pro.getByText(/shareable report links/i)).toBeTruthy();
    expect(pro.getByText(/hash-chained/i)).toBeTruthy();
  });
});
