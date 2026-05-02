// Supabase client + authenticated fetch wrapper.
//
// Both used to live inline in App.jsx. They are pure I/O — no React
// state, no hooks — so they sit in `lib/` rather than `components/`,
// and the React layer just calls them as plain functions.
//
// IMPORTANT: this file deliberately does NOT touch React state on
// refresh. Callers that want to mirror the freshly-refreshed token
// into their own `session` state pass an `onTokenRefresh` callback.
// That keeps `apiFetch` reusable from places (tests, future hooks)
// that don't have a `setSession` to call.

import { createClient } from '@supabase/supabase-js';

export const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";
export const IS_CLOUD_SAAS = API_BASE_URL !== "http://localhost:8080";

export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL || "https://placeholder.supabase.co",
  import.meta.env.VITE_SUPABASE_ANON_KEY || "placeholder",
);

// Authenticated fetch wrapper. Always reads the current access_token from
// supabase-js's cache (which is kept fresh by background auto-refresh)
// rather than from React state, so a request initiated just after a
// silent refresh doesn't fire with the stale token. On 401 we explicitly
// call refreshSession() once and retry — this covers the race where the
// request flies just after the JWT expires but before the auto-refresh
// has run. If the refresh fails (truly expired refresh token), we
// surface the original 401 to the caller; the resulting SIGNED_OUT
// event from supabase-js will route the user back to the login screen
// via the App's onAuthStateChange handler.
//
// `onTokenRefresh(newAccessToken)` is invoked exactly once when a 401
// retry recovered with a fresh token. The App passes a function that
// patches `session.accessToken` so other React-state-coupled code sees
// the new value without waiting for the next TOKEN_REFRESHED event.
export async function apiFetch(path, options = {}, onTokenRefresh) {
  const { data: { session: live } } = await supabase.auth.getSession();
  const headers = { ...(options.headers || {}) };
  if (live?.access_token) headers["Authorization"] = `Bearer ${live.access_token}`;

  const resp = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
  if (resp.status !== 401) return resp;

  const { data, error } = await supabase.auth.refreshSession();
  if (error || !data?.session) return resp;
  if (typeof onTokenRefresh === 'function') onTokenRefresh(data.session.access_token);
  headers["Authorization"] = `Bearer ${data.session.access_token}`;
  return await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
}
