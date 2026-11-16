import { describe, it, expect, vi } from 'vitest';

vi.mock('@vercel/analytics', () => ({ inject: vi.fn(), track: vi.fn() }));

import { track as vercelTrack } from '@vercel/analytics';
import { redactUrl, track } from './analytics.js';

// The address bar of this app carries credentials. An analytics script
// reports the page URL by default, so these tests are the thing standing
// between a share token and a third party's dashboard.
describe('redactUrl', () => {
  const token = 'a'.repeat(64);

  it('never reports a share token', () => {
    const out = redactUrl(`https://aicap.dev/?report=${token}`);
    expect(out).not.toContain(token);
    // ...but keeps the fact that this was a shared-report view.
    expect(out).toBe('https://aicap.dev/?report=redacted');
  });

  it('never reports a Stripe checkout session id', () => {
    const out = redactUrl('https://aicap.dev/?session_id=cs_live_a1B2c3');
    expect(out).not.toContain('cs_live');
    expect(out).toBe('https://aicap.dev/?session_id=redacted');
  });

  it('drops the fragment, where the email-confirmation redirect puts a session token', () => {
    const out = redactUrl('https://aicap.dev/#access_token=eyJhbGciOi.secret&refresh_token=r1&type=signup');
    expect(out).toBe('https://aicap.dev/');
  });

  it('keeps the parameters that only name a page', () => {
    expect(redactUrl('https://aicap.dev/?page=privacy')).toBe('https://aicap.dev/?page=privacy');
    expect(redactUrl('https://aicap.dev/guides/ai-bom-vs-sbom-difference.html'))
      .toBe('https://aicap.dev/guides/ai-bom-vs-sbom-difference.html');
  });

  it('drops parameters it does not know — private by default', () => {
    const out = redactUrl('https://aicap.dev/?page=terms&code=abc123&email=someone%40example.com&utm_source=hn');
    expect(out).toBe('https://aicap.dev/?page=terms');
  });

  it('redacts every secret when several are present', () => {
    const out = redactUrl(`https://aicap.dev/?report=${token}&session_id=cs_test_9#access_token=zzz`);
    expect(out).not.toContain(token);
    expect(out).not.toContain('cs_test_9');
    expect(out).not.toContain('zzz');
  });

  it('reports the bare origin for input it cannot parse', () => {
    expect(redactUrl('http://[not a url')).toBe('https://aicap.dev/');
  });
});

describe('track', () => {
  it('sends nothing before analytics has been started', () => {
    // Tests, local dev and self-hosted builds never call initAnalytics
    // with the production conditions met, so an event must not go out.
    track('signup_submitted');
    expect(vercelTrack).not.toHaveBeenCalled();
  });
});
