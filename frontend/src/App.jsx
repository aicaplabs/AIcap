import React, { useState, useEffect, useRef } from 'react';

import {
  API_BASE_URL,
  IS_CLOUD_SAAS,
  apiFetch,
  supabase,
} from './lib/supabase.js';
import Header from './components/Header.jsx';
import LandingAuth from './components/LandingAuth.jsx';
import CheckoutProcessing from './components/CheckoutProcessing.jsx';
import Paywall from './components/Paywall.jsx';
import ProDashboard from './components/ProDashboard.jsx';
import LocalDashboard from './components/LocalDashboard.jsx';

// Default state before fetch.
const defaultScanData = {
  projectName: 'Loading...',
  scannedFiles: 0,
  complianceStatus: 'Pending',
  dependencies: [],
  finOps: [],
};

// Top-level state machine + view router.
//
// After the Wave 5 split this file deliberately holds NO UI markup
// beyond the router. Anything that renders pixels lives under
// `components/`; anything that talks to the backend lives under
// `lib/`. The split mirrors how the App actually thinks: a small set
// of state (auth, scan, history) drives a small set of view branches.
export default function App() {
  // --- Scan / DB / history state (local-dev path)
  const [scanData, setScanData] = useState(defaultScanData);
  const [historyData, setHistoryData] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [markdownGenerated, setMarkdownGenerated] = useState(false);
  const [historicalProof, setHistoricalProof] = useState(null);
  const [dbConfig, setDbConfig] = useState({ enabled: false, url: '', connected: false });

  // --- Auth state (cloud-SaaS path)
  // After Wave 3b `session` never contains a raw API key — only:
  //   accessToken: Supabase session JWT (used for every authenticated backend call)
  //   hasKey:      whether api_keys has a materialised token_hash for this user
  //   tier:        'free' | 'pro' (drives paywall)
  // The one-and-only time we know the raw key is inside `revealedKey`,
  // populated by a successful /api/generate-key or /api/rotate-key.
  const [session, setSession] = useState(null);
  const [revealedKey, setRevealedKey] = useState('');

  // True while we're waiting for the Stripe webhook to mark the user Pro.
  // Initialised from the URL so the processing screen shows immediately on
  // the checkout-return page load, before auth state fires.
  const [checkoutProcessing, setCheckoutProcessing] = useState(
    IS_CLOUD_SAAS && !!new URLSearchParams(window.location.search).get('session_id'),
  );

  // Prevents concurrent executions of fetchAndSetUserSession —
  // onAuthStateChange can emit both INITIAL_SESSION and TOKEN_REFRESHED
  // on the same page load.
  const fetchSessionRef = useRef(false);

  // --- Local-dev DB status -------------------------------------------------
  const fetchDbStatus = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/db-config`);
      const data = await response.json();
      setDbConfig(prev => ({ ...prev, enabled: data.connected, connected: data.connected }));
      if (data.connected) fetchHistoryData();
    } catch (error) {
      console.error('Failed to fetch DB status:', error);
    }
  };

  // --- History fetch (both modes) ------------------------------------------
  // tokenOverride is honoured for the bootstrap call from
  // fetchAndSetUserSession (which has the freshly-decoded token in hand
  // and runs before apiFetch's supabase-js read returns the new session).
  // Subsequent calls go through apiFetch so a mid-session 401 triggers a
  // refresh-and-retry instead of failing silently.
  const fetchHistoryData = async (tokenOverride = '') => {
    try {
      let response;
      if (tokenOverride) {
        response = await fetch(`${API_BASE_URL}/api/history`, {
          headers: { Authorization: `Bearer ${tokenOverride}` },
        });
      } else if (IS_CLOUD_SAAS) {
        response = await apiFetch('/api/history', {}, onTokenRefresh);
      } else {
        response = await fetch(`${API_BASE_URL}/api/history`);
      }
      if (!response.ok) return;
      const data = await response.json();
      setHistoryData(data || []);
    } catch (error) {
      console.error('Failed to fetch history:', error);
    }
  };

  // --- Local-dev scan ------------------------------------------------------
  const fetchScanData = async () => {
    setIsScanning(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan`);
      const data = await response.json();
      setScanData(data);
    } catch (error) {
      console.error('Failed to fetch scan data:', error);
      setScanData({ ...defaultScanData, projectName: 'Error: Is Go Server Running?' });
    } finally {
      setIsScanning(false);
    }
  };

  // --- Cloud-SaaS session bootstrap ---------------------------------------
  // After Wave 3b we no longer pull the raw token from api_keys — the
  // column doesn't exist anymore. We only read the subscription tier and
  // whether a token_hash is materialised; the plaintext key is only ever
  // visible in the response to /api/generate-key or /api/rotate-key.
  const fetchAndSetUserSession = async (supabaseSession) => {
    if (fetchSessionRef.current) return;
    fetchSessionRef.current = true;
    try {
      const user = supabaseSession.user;
      const accessToken = supabaseSession.access_token;

      const urlParams = new URLSearchParams(window.location.search);
      const sessionId = urlParams.get('session_id');

      // Initial read goes through /api/me (RLS-independent) so session
      // correctness doesn't depend on Supabase RLS configuration.
      const readMe = async () => {
        const resp = await fetch(`${API_BASE_URL}/api/me`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!resp.ok) return { hasKey: false, tier: 'free' };
        return resp.json();
      };
      const me = await readMe();
      let nextSession = {
        user,
        accessToken,
        hasKey: !!me.hasKey,
        tier: me.tier || 'free',
        trialDaysRemaining: me.trialDaysRemaining ?? null,
      };

      if (sessionId) {
        // Step 1: materialise the key immediately. The generate-key
        // UPSERT preserves whatever tier the webhook later writes.
        if (!nextSession.hasKey) {
          try {
            const response = await fetch(`${API_BASE_URL}/api/generate-key`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${accessToken}`,
              },
            });
            if (response.ok) {
              const data = await response.json();
              setRevealedKey(data.apiKey);
              nextSession = { ...nextSession, hasKey: true };
            } else if (response.status === 409) {
              nextSession = { ...nextSession, hasKey: true };
            }
          } catch (keyError) {
            console.error('Failed to materialise API key:', keyError);
          }
        }

        // Step 2: short backend poll (3 × 1.5 s) for the normal webhook path.
        if (nextSession.tier !== 'pro') {
          for (let attempt = 0; attempt < 3; attempt++) {
            await new Promise(r => setTimeout(r, 1500));
            const fresh = await readMe();
            if (fresh.tier === 'pro') {
              nextSession = { ...nextSession, tier: 'pro', hasKey: !!fresh.hasKey };
              break;
            }
          }
        }

        // Step 3: webhook fallback — verify payment via the Stripe API directly.
        if (nextSession.tier !== 'pro') {
          try {
            const vResp = await fetch(
              `${API_BASE_URL}/api/verify-checkout?session_id=${encodeURIComponent(sessionId)}`,
              { headers: { Authorization: `Bearer ${accessToken}` } },
            );
            if (vResp.ok) {
              const vData = await vResp.json();
              if (vData.tier === 'pro') {
                const afterVerify = await readMe();
                nextSession = { ...nextSession, tier: 'pro', hasKey: !!afterVerify.hasKey };
              }
            }
          } catch (verifyError) {
            console.error('Failed to verify checkout:', verifyError);
          }
        }

        window.history.replaceState({}, document.title, '/');
        setCheckoutProcessing(false);
      }

      setSession(nextSession);
      fetchHistoryData(accessToken);
    } catch (error) {
      console.error('Failed to load user session:', error);
      setCheckoutProcessing(false);
    } finally {
      fetchSessionRef.current = false;
    }
  };

  // Token-refresh callback handed to apiFetch — mirrors a freshly-refreshed
  // access token into React state so other components see the new value.
  const onTokenRefresh = (newAccessToken) => {
    setSession(prev => prev ? { ...prev, accessToken: newAccessToken } : prev);
  };

  // --- Mount: wire up scan/history (local) or auth listener (cloud) -------
  useEffect(() => {
    if (!IS_CLOUD_SAAS) {
      fetchScanData();
      fetchDbStatus();
      return undefined;
    }

    // TOKEN_REFRESHED: silent background refresh of the JWT. Patch the
    // accessToken in place; do NOT re-run fetchAndSetUserSession — that
    // would re-fire the checkout-return polling and reset hasKey/tier.
    // Other events (INITIAL_SESSION, SIGNED_IN) run the full bootstrap.
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, sbSession) => {
      if (!sbSession || !sbSession.user) {
        setSession(null);
        return;
      }
      if (event === 'TOKEN_REFRESHED') {
        setSession(prev => prev ? { ...prev, accessToken: sbSession.access_token } : prev);
        return;
      }
      fetchAndSetUserSession(sbSession);
    });

    return () => subscription.unsubscribe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Historical proof drill fetch (both modes) ---------------------------
  const fetchHistoricalProof = async (hash) => {
    try {
      const response = IS_CLOUD_SAAS
        ? await apiFetch(`/api/proof?hash=${encodeURIComponent(hash)}`, {}, onTokenRefresh)
        : await fetch(`${API_BASE_URL}/api/proof?hash=${encodeURIComponent(hash)}`);
      if (response.ok) {
        const data = await response.json();
        setHistoricalProof({ hash, markdown: data.markdown });
        setMarkdownGenerated(false);
      }
    } catch (error) {
      console.error('Failed to fetch historical proof:', error);
    }
  };

  // --- View router ---------------------------------------------------------
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans p-6">
      <Header
        session={session}
        scanData={scanData}
        isScanning={isScanning}
        onRescan={fetchScanData}
        onSignOut={() => setSession(null)}
      />

      {IS_CLOUD_SAAS ? (
        checkoutProcessing ? (
          <CheckoutProcessing />
        ) : !session ? (
          <LandingAuth />
        ) : session.tier !== 'pro' && !(session.trialDaysRemaining > 0) ? (
          <Paywall
            onTokenRefresh={onTokenRefresh}
            trialExpired={session.trialDaysRemaining === 0}
          />
        ) : (
          <ProDashboard
            session={session}
            revealedKey={revealedKey}
            onSetRevealedKey={setRevealedKey}
            onHasKeyChange={(hasKey) => setSession(prev => prev ? { ...prev, hasKey } : prev)}
            onTokenRefresh={onTokenRefresh}
            historyData={historyData}
            onHistoryRowClick={fetchHistoricalProof}
            historicalProof={historicalProof}
            trialDaysRemaining={session.trialDaysRemaining}
          />
        )
      ) : (
        <LocalDashboard
          scanData={scanData}
          historyData={historyData}
          fetchHistoryData={fetchHistoryData}
          isGenerating={isGenerating}
          setIsGenerating={setIsGenerating}
          markdownGenerated={markdownGenerated}
          setMarkdownGenerated={setMarkdownGenerated}
          historicalProof={historicalProof}
          setHistoricalProof={setHistoricalProof}
          onHistoryRowClick={fetchHistoricalProof}
          dbConfig={dbConfig}
          setDbConfig={setDbConfig}
        />
      )}
    </div>
  );
}
