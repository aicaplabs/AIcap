// KeyVault state-machine test.
//
// The component drives the three-state UI that the user sees: no-key,
// has-key, or revealed. Each state has a distinct CTA and the
// transitions between them depend on backend responses (201 / 409 /
// success on rotate). We mock apiFetch and assert on rendered text
// + which callbacks fire.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

const apiFetch = vi.fn();

// Mock the lib so the component sees a controllable apiFetch.
// Note: KeyVault imports `{ apiFetch }` from `../lib/supabase.js`.
vi.mock('../lib/supabase.js', () => ({
  apiFetch: (...args) => apiFetch(...args),
}));

import KeyVault from './KeyVault.jsx';

beforeEach(() => {
  apiFetch.mockReset();
  // jsdom has no native window.confirm; mock to auto-accept rotates.
  vi.stubGlobal('confirm', () => true);
});

describe('KeyVault state machine', () => {
  it('renders the no-key state and generates on click', async () => {
    apiFetch.mockResolvedValueOnce(new Response(
      JSON.stringify({ apiKey: 'aicap_pro_sk_test_abc' }),
      { status: 201, headers: { 'Content-Type': 'application/json' } },
    ));
    const onSetRevealedKey = vi.fn();
    const onHasKeyChange = vi.fn();

    render(
      <KeyVault
        session={{ user: { email: 'a@b.c' }, hasKey: false }}
        revealedKey=""
        onSetRevealedKey={onSetRevealedKey}
        onHasKeyChange={onHasKeyChange}
        onTokenRefresh={() => {}}
      />,
    );

    const btn = screen.getByRole('button', { name: /generate api key/i });
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);

    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(1));
    expect(apiFetch.mock.calls[0][0]).toBe('/api/generate-key');
    expect(onSetRevealedKey).toHaveBeenCalledWith('aicap_pro_sk_test_abc');
    expect(onHasKeyChange).toHaveBeenCalledWith(true);
  });

  it('handles a 409 from generate-key as "already exists"', async () => {
    apiFetch.mockResolvedValueOnce(new Response('conflict', { status: 409 }));
    const onSetRevealedKey = vi.fn();
    const onHasKeyChange = vi.fn();
    vi.stubGlobal('alert', vi.fn());

    render(
      <KeyVault
        session={{ user: {}, hasKey: false }}
        revealedKey=""
        onSetRevealedKey={onSetRevealedKey}
        onHasKeyChange={onHasKeyChange}
        onTokenRefresh={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /generate api key/i }));
    await waitFor(() => expect(onHasKeyChange).toHaveBeenCalledWith(true));
    expect(onSetRevealedKey).not.toHaveBeenCalled();
  });

  it('renders the has-key state and offers rotate', async () => {
    apiFetch.mockResolvedValueOnce(new Response(
      JSON.stringify({ apiKey: 'aicap_pro_sk_rotated' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));
    const onSetRevealedKey = vi.fn();
    const onHasKeyChange = vi.fn();

    render(
      <KeyVault
        session={{ user: {}, hasKey: true }}
        revealedKey=""
        onSetRevealedKey={onSetRevealedKey}
        onHasKeyChange={onHasKeyChange}
        onTokenRefresh={() => {}}
      />,
    );

    expect(screen.getByText(/an api key is active/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /rotate key/i }));

    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(1));
    expect(apiFetch.mock.calls[0][0]).toBe('/api/rotate-key');
    expect(onSetRevealedKey).toHaveBeenCalledWith('aicap_pro_sk_rotated');
  });

  it('renders the revealed state and dismiss clears it', () => {
    const onSetRevealedKey = vi.fn();

    render(
      <KeyVault
        session={{ user: {}, hasKey: true }}
        revealedKey="aicap_pro_sk_just_made"
        onSetRevealedKey={onSetRevealedKey}
        onHasKeyChange={() => {}}
        onTokenRefresh={() => {}}
      />,
    );

    // The plaintext is shown verbatim, in a select-all <code> block.
    expect(screen.getByTestId('revealed-key')).toHaveTextContent('aicap_pro_sk_just_made');
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /i've saved the key/i }));
    expect(onSetRevealedKey).toHaveBeenCalledWith('');
  });
});
