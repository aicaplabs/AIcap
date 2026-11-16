// Web analytics (Vercel Web Analytics): cookieless, aggregate page views
// and a handful of funnel events. No identifiers of ours are attached to
// anything sent — no user id, no email, no project name.
//
// The part that needs care is the URL. This app carries secrets in the
// address bar:
//
//   ?report=<token>      a share link. The token IS the credential: anyone
//                        holding it can read the report.
//   ?session_id=<id>     the Stripe Checkout return.
//   #access_token=…      the Supabase email-confirmation redirect, which
//                        puts a session token in the fragment.
//
// An analytics script reports the page URL by default. Left alone it would
// hand every one of those to a third party and file them in a dashboard.
// So every event passes through redactUrl first, which keeps only what is
// needed to tell page types apart.

import { inject, track as vercelTrack } from '@vercel/analytics';

import { IS_CLOUD_SAAS } from './supabase.js';

// Query parameters whose value is safe to report as-is. Anything not
// listed here is either reduced to a presence marker or dropped — an
// allowlist, so a parameter added later is private by default.
const SAFE_PARAMS = new Set(['page']);

// Parameters worth knowing were present (they define the page type) but
// whose value must never leave the browser.
const MARKER_PARAMS = new Set(['report', 'session_id']);

// redactUrl returns the URL as it may be reported: same origin and path,
// the fragment removed, and the query reduced to allowlisted parameters
// plus value-less markers. Anything unparseable is reported as the bare
// origin rather than passed through.
export function redactUrl(raw) {
  let url;
  try {
    url = new URL(raw, typeof window !== 'undefined' ? window.location.origin : 'https://aicap.dev');
  } catch {
    return 'https://aicap.dev/';
  }
  const kept = new URLSearchParams();
  for (const [key, value] of url.searchParams) {
    if (SAFE_PARAMS.has(key)) kept.set(key, value);
    else if (MARKER_PARAMS.has(key)) kept.set(key, 'redacted');
  }
  const query = kept.toString();
  return `${url.origin}${url.pathname}${query ? `?${query}` : ''}`;
}

let started = false;

// initAnalytics loads the script once, in the hosted production build
// only. A local `npm run dev` and a self-hosted deployment send nothing.
export function initAnalytics() {
  if (started || !import.meta.env.PROD || !IS_CLOUD_SAAS) return;
  started = true;
  try {
    inject({
      beforeSend: event => ({ ...event, url: redactUrl(event.url) }),
    });
  } catch {
    // Analytics must never be able to break the app.
  }
}

// Funnel events. Names only, plus at most a coarse label — never anything
// that identifies a user, a project or a report.
export const EVENTS = {
  SIGNUP_SUBMITTED: 'signup_submitted',
  SIGNED_IN: 'signed_in',
  CHECKOUT_STARTED: 'checkout_started',
  REPORT_SHARED: 'report_shared',
  SHARED_REPORT_VIEWED: 'shared_report_viewed',
  PDF_EXPORTED: 'pdf_exported',
};

// track records a funnel event. Safe to call anywhere: it is a no-op
// until initAnalytics has run, and it swallows every error.
export function track(name, data) {
  if (!started) return;
  try {
    vercelTrack(name, data);
  } catch {
    // see initAnalytics
  }
}
