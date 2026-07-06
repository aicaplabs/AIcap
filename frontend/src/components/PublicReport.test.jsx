// Tests for the public shared-report view (Wave 15).
//
// Contract:
//   1. A resolvable token renders the report markdown, provenance strip,
//      and the "generate yours" CTA (the distribution loop).
//   2. A 404 (revoked/invalid token) renders the error state, never a
//      blank page — recipients are non-users and get no second chance.
import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

import PublicReport from './PublicReport.jsx';

beforeEach(() => {
  globalThis.fetch = vi.fn();
});

describe('PublicReport', () => {
  it('renders the report, provenance, and CTA for a valid token', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      markdown: '# EU AI Act - Annex IV Technical Documentation\n- **System Name:** demo/repo',
      commitSha: 'deadbeefcafe1234',
      cryptoHash: 'ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890',
      createdAt: '2026-07-01T10:00:00Z',
      projectName: 'demo/repo',
    }), { status: 200 }));

    render(<PublicReport token={'a'.repeat(64)} />);

    expect(await screen.findByText('EU AI Act - Annex IV Technical Documentation')).toBeInTheDocument();
    expect(screen.getByText('deadbeefcafe')).toBeInTheDocument();
    expect(screen.getByText('Immutable Ledger Record')).toBeInTheDocument();
    expect(screen.getByText(/Generate reports like this in your CI/)).toBeInTheDocument();
    // The fetch hit the public endpoint with the token, unauthenticated.
    expect(globalThis.fetch.mock.calls[0][0]).toContain('/api/public/report?token=' + 'a'.repeat(64));
  });

  it('renders the revoked/invalid state on a 404', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response('Report not found', { status: 404 }));

    render(<PublicReport token={'b'.repeat(64)} />);

    expect(
      await screen.findByText('This report link is invalid or has been revoked.'),
    ).toBeInTheDocument();
  });
});
