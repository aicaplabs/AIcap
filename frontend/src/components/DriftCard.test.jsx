// Drift card tests (Wave 18).
//
// The card has three states that matter and are easy to confuse: not
// enough history, nothing changed, and something changed that the user
// should look at. Rendering the second when the truth is the first, or
// burying an advisory under dependency churn, would each quietly defeat
// the feature.
import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

const apiFetch = vi.fn();
vi.mock('../lib/supabase.js', () => ({
  apiFetch: (...args) => apiFetch(...args),
}));

import DriftCard from './DriftCard.jsx';

function respond(body) {
  apiFetch.mockResolvedValueOnce({ ok: true, json: async () => body });
}

beforeEach(() => {
  apiFetch.mockReset();
});

describe('DriftCard', () => {
  it('explains that drift needs a baseline rather than showing an empty card', async () => {
    respond({
      available: false,
      reason: 'Fewer than two scans recorded for this project — drift needs a baseline to compare against.',
    });

    render(<DriftCard />);

    expect(await screen.findByText(/needs a baseline/)).toBeInTheDocument();
    // Must not read as "nothing changed".
    expect(screen.queryByText(/No change to the AI surface/)).not.toBeInTheDocument();
  });

  it('says plainly when nothing changed', async () => {
    respond({
      available: true,
      drift: {
        from: { commitSha: 'aaaaaaa1' },
        to: { commitSha: 'bbbbbbb2' },
        summary: {},
        dependencies: {},
        risk: {},
      },
    });

    render(<DriftCard />);

    expect(await screen.findByText(/No change to the AI surface/)).toBeInTheDocument();
    expect(screen.queryByText(/Needs review/)).not.toBeInTheDocument();
  });

  it('leads with new advisories and shows the fix version', async () => {
    // The category the user did not cause. If this ever renders below
    // dependency churn, the most valuable signal is the easiest to miss.
    respond({
      available: true,
      drift: {
        from: { commitSha: 'aaaaaaa1' },
        to: { commitSha: 'bbbbbbb2' },
        summary: { regressed: true, newAdvisories: 1 },
        dependencies: {},
        risk: {
          newAdvisories: [
            {
              component: 'transformers',
              version: '4.44.0',
              vulns: [{ id: 'GHSA-new', fixedVersion: '4.48.1' }],
            },
          ],
        },
      },
    });

    render(<DriftCard />);

    expect(await screen.findByText(/New advisories since last scan/)).toBeInTheDocument();
    expect(screen.getByText(/GHSA-new/)).toBeInTheDocument();
    expect(screen.getByText(/fixed in 4.48.1/)).toBeInTheDocument();
    expect(screen.getByText(/Needs review/)).toBeInTheDocument();
  });

  it('shows a compliance regression and the component that caused it', async () => {
    respond({
      available: true,
      drift: {
        from: { commitSha: 'aaaaaaa1' },
        to: { commitSha: 'bbbbbbb2' },
        summary: { regressed: true, dependenciesAdded: 1, highRiskAdded: 1 },
        complianceChange: {
          from: 'Passed',
          to: 'Action Required (Annex IV Documentation Missing)',
          regressed: true,
        },
        dependencies: {
          added: [{ name: 'vllm', version: '0.6.0', riskLevel: 'High' }],
        },
        risk: {},
      },
    });

    render(<DriftCard />);

    expect(await screen.findByText(/Action Required/)).toBeInTheDocument();
    expect(screen.getByText(/vllm 0.6.0/)).toBeInTheDocument();
    expect(screen.getByText(/Needs review/)).toBeInTheDocument();
  });

  it('renders nothing when the drift request fails', async () => {
    // A failed drift fetch must not take the dashboard down with it.
    apiFetch.mockResolvedValueOnce({ ok: false, status: 500 });

    const { container } = render(<DriftCard />);
    await new Promise((r) => setTimeout(r, 0));

    expect(container).toBeEmptyDOMElement();
  });
});
