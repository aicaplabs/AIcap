// Tests for apiFetch — the 401-recovery wrapper added in Wave 4.
//
// The contract under test:
//   1. Successful fetch passes through untouched.
//   2. Non-401 error pass through untouched (no surprise refresh).
//   3. 401 → refreshSession() called → retry with new token.
//   4. 401 then refresh fails → original 401 returned (caller decides).
//   5. The onTokenRefresh callback fires once with the new token on
//      successful recovery, never on 200 paths.
//
// We mock the @supabase/supabase-js module so the wrapper sees a fake
// auth client whose getSession/refreshSession we control per-test.
import { describe, it, expect, beforeEach, vi } from 'vitest';

const getSession = vi.fn();
const refreshSession = vi.fn();

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({ auth: { getSession, refreshSession } }),
}));

// Import AFTER the mock is registered so the module under test sees
// our fake supabase client.
const { apiFetch } = await import('./supabase.js');

beforeEach(() => {
  getSession.mockReset();
  refreshSession.mockReset();
  globalThis.fetch = vi.fn();
});

describe('apiFetch', () => {
  it('returns a 200 response untouched and never refreshes', async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: 't1' } } });
    globalThis.fetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const onRefresh = vi.fn();
    const resp = await apiFetch('/api/me', {}, onRefresh);

    expect(resp.status).toBe(200);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(refreshSession).not.toHaveBeenCalled();
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('passes a non-401 error through (no refresh on 500)', async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: 't1' } } });
    globalThis.fetch.mockResolvedValueOnce(new Response('boom', { status: 500 }));

    const resp = await apiFetch('/api/me');
    expect(resp.status).toBe(500);
    expect(refreshSession).not.toHaveBeenCalled();
  });

  it('on 401 it refreshes the session and retries with the new token', async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: 'stale' } } });
    refreshSession.mockResolvedValue({
      data: { session: { access_token: 'fresh' } },
      error: null,
    });
    globalThis.fetch
      .mockResolvedValueOnce(new Response('expired', { status: 401 }))
      .mockResolvedValueOnce(new Response('ok', { status: 200 }));

    const onRefresh = vi.fn();
    const resp = await apiFetch('/api/history', {}, onRefresh);

    expect(resp.status).toBe(200);
    expect(refreshSession).toHaveBeenCalledTimes(1);
    expect(onRefresh).toHaveBeenCalledExactlyOnceWith('fresh');

    // Second call must use the freshly-refreshed token, not the stale one.
    const [, retryArgs] = globalThis.fetch.mock.calls;
    expect(retryArgs[1].headers.Authorization).toBe('Bearer fresh');
  });

  it('returns the original 401 if refresh itself fails', async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: 'stale' } } });
    refreshSession.mockResolvedValue({
      data: { session: null },
      error: { message: 'refresh token expired' },
    });
    globalThis.fetch.mockResolvedValueOnce(new Response('expired', { status: 401 }));

    const onRefresh = vi.fn();
    const resp = await apiFetch('/api/history', {}, onRefresh);

    expect(resp.status).toBe(401);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1); // no retry
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('omits Authorization header when no session is present', async () => {
    getSession.mockResolvedValue({ data: { session: null } });
    globalThis.fetch.mockResolvedValueOnce(new Response('ok', { status: 200 }));

    await apiFetch('/api/livez');
    const [, args] = globalThis.fetch.mock.calls[0];
    expect(args.headers.Authorization).toBeUndefined();
  });
});
