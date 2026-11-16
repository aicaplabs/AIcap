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

// --- Attestation notice (Wave 17) ---------------------------------------
//
// The share link is what an auditor actually receives. A signed record is
// only useful to them if the page hands over the material to check it —
// otherwise "signed" is decoration.
describe('PublicReport attestation', () => {
  const baseReport = {
    markdown: '# Annex IV',
    commitSha: 'deadbeefcafe1234',
    cryptoHash: 'ab12cd34ef567890',
    createdAt: '2026-07-01T10:00:00Z',
    projectName: 'demo/repo',
  };

  it('publishes the material a recipient needs to verify a signed record', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      ...baseReport,
      attestation: {
        signature: 'c2lnbmF0dXJlLWJ5dGVz',
        signedMessage: 'YWljYXAtbGVkZ2VyLXYxfHV8Y3xo',
        algorithm: 'Ed25519',
        signingKeyId: '57ClNmBrM43IYL20',
        publicKeyPath: '/api/ledger/public-key',
      },
    }), { status: 200 }));

    render(<PublicReport token={'c'.repeat(64)} />);

    expect(await screen.findByText(/Cryptographically signed/)).toBeInTheDocument();
    // The bytes and the signature must both be on the page — a recipient
    // cannot verify without them.
    expect(screen.getByText('YWljYXAtbGVkZ2VyLXYxfHV8Y3xo')).toBeInTheDocument();
    expect(screen.getByText('c2lnbmF0dXJlLWJ5dGVz')).toBeInTheDocument();
    // And where to get the key.
    expect(screen.getByText('/api/ledger/public-key')).toBeInTheDocument();
  });

  const signedAttestation = {
    signature: 'c2lnbmF0dXJlLWJ5dGVz',
    signedMessage: 'YWljYXAtbGVkZ2VyLXYyfHR8Y3xo',
    algorithm: 'Ed25519',
    publicKeyPath: '/api/ledger/public-key',
  };

  // What a signature proves depends on the ledger version. For months this
  // notice said the record "has not been altered since" for every entry,
  // including ones whose signed hash never covered the document text.
  it('claims the document is covered only when the ledger hash covers it', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      ...baseReport,
      attestation: signedAttestation,
      integrity: {
        chainVersion: 2,
        documentCovered: true,
        prevHash: '',
        bomSha256: 'b'.repeat(64),
        annexIvSha256: 'a'.repeat(64),
        riskRegisterSha256: 'f'.repeat(64),
      },
    }), { status: 200 }));

    render(<PublicReport token={'f'.repeat(64)} />);

    expect(await screen.findByText(/The ledger hash covers the document below/)).toBeInTheDocument();
    expect(screen.queryByText(/What this does not cover/)).not.toBeInTheDocument();
    // The digests a recipient needs to recompute the hash are on the page.
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText(/first entry/)).toBeInTheDocument();
  });

  it('says what a version 1 signature does not cover', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      ...baseReport,
      attestation: signedAttestation,
      integrity: { chainVersion: 1, documentCovered: false, note: 'Version 1: the document is not covered.' },
    }), { status: 200 }));

    render(<PublicReport token={'1'.repeat(64)} />);

    expect(await screen.findByText(/What this does not cover/)).toBeInTheDocument();
    expect(screen.getByText(/Version 1: the document is not covered\./)).toBeInTheDocument();
    expect(screen.queryByText(/The ledger hash covers the document below/)).not.toBeInTheDocument();
    expect(screen.queryByText(/has not been altered/)).not.toBeInTheDocument();
  });

  it('does not claim document coverage when the backend sends no integrity block', async () => {
    // An older backend. Absence of the block must read as "not covered",
    // never as the stronger claim.
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      ...baseReport,
      attestation: signedAttestation,
    }), { status: 200 }));

    render(<PublicReport token={'2'.repeat(64)} />);

    expect(await screen.findByText(/What this does not cover/)).toBeInTheDocument();
    expect(screen.queryByText(/The ledger hash covers the document below/)).not.toBeInTheDocument();
  });

  it('says plainly when a record is unsigned', async () => {
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify({
      ...baseReport,
      attestation: {
        signature: '',
        note: 'This entry is unsigned.',
      },
    }), { status: 200 }));

    render(<PublicReport token={'d'.repeat(64)} />);

    expect(await screen.findByText(/Not cryptographically signed/)).toBeInTheDocument();
    expect(screen.queryByText(/verify this yourself/)).not.toBeInTheDocument();
  });

  it('renders without an attestation block at all', async () => {
    // Backwards compatibility: an older backend returns no attestation
    // field. The page must still render rather than crashing.
    globalThis.fetch.mockResolvedValueOnce(new Response(JSON.stringify(baseReport), { status: 200 }));

    render(<PublicReport token={'e'.repeat(64)} />);

    expect(await screen.findByText('Annex IV')).toBeInTheDocument();
    expect(screen.queryByText(/Cryptographically signed/)).not.toBeInTheDocument();
  });
});
