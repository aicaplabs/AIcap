import React, { useState } from 'react';
import { Key } from 'lucide-react';

import { apiFetch } from '../lib/supabase.js';

// Three-state API-key panel:
//   1. revealed   — the plaintext key has just come back from
//                   /api/generate-key or /api/rotate-key. Show it once,
//                   make the user click "I've saved the key" to dismiss.
//   2. hasKey     — a token_hash exists in the DB but the plaintext is
//                   not recoverable. Offer "Rotate Key".
//   3. no-key     — Pro tier marker exists (or free tier) but no key
//                   has been materialised yet. Offer "Generate API Key".
//
// `revealedKey` is owned by the parent App because the checkout-return
// flow inside fetchAndSetUserSession also writes into it (the raw key
// auto-generated when the user lands back from Stripe). KeyVault is
// therefore controlled — it never holds revealedKey in its own state.
//
// `onSetRevealedKey(raw | "")` lets KeyVault push a freshly-issued key
// up to the App, or clear it on user dismissal.
// `onHasKeyChange(true)`     marks api_keys row as materialised so the
//                            session reflects it without a /api/me roundtrip.
// `onTokenRefresh(token)`    forwarded to apiFetch's 401 retry path.
export default function KeyVault({
  session,
  revealedKey,
  onSetRevealedKey,
  onHasKeyChange,
  onTokenRefresh,
}) {
  const [keyBusy, setKeyBusy] = useState(false);

  const handleGenerate = async () => {
    if (!session) return;
    setKeyBusy(true);
    try {
      const response = await apiFetch(
        '/api/generate-key',
        { method: 'POST', headers: { 'Content-Type': 'application/json' } },
        onTokenRefresh,
      );
      if (response.status === 409) {
        alert("An API key already exists. Use 'Rotate Key' to replace it.");
        onHasKeyChange(true);
        return;
      }
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      onSetRevealedKey(data.apiKey);
      onHasKeyChange(true);
    } catch (error) {
      alert(`Failed to generate key: ${error.message}`);
    } finally {
      setKeyBusy(false);
    }
  };

  const handleRotate = async () => {
    if (!session) return;
    if (!window.confirm(
      'Rotating will immediately invalidate your current key. Any CI pipelines using it will start failing until you update the secret. Continue?',
    )) return;
    setKeyBusy(true);
    try {
      const response = await apiFetch(
        '/api/rotate-key',
        { method: 'POST', headers: { 'Content-Type': 'application/json' } },
        onTokenRefresh,
      );
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      onSetRevealedKey(data.apiKey);
      onHasKeyChange(true);
    } catch (error) {
      alert(`Failed to rotate key: ${error.message}`);
    } finally {
      setKeyBusy(false);
    }
  };

  return (
    <div className="bg-indigo-800/50 p-5 rounded-xl border border-indigo-400/30 w-full md:w-auto shrink-0 max-w-sm">
      <div className="flex items-center gap-2 mb-3 text-indigo-100">
        <Key className="w-4 h-4" />
        <h3 className="text-sm font-bold uppercase tracking-wider">API Key</h3>
      </div>
      {revealedKey ? (
        <RevealedState rawKey={revealedKey} onDismiss={() => onSetRevealedKey('')} />
      ) : session?.hasKey ? (
        <HasKeyState busy={keyBusy} onRotate={handleRotate} />
      ) : (
        <NoKeyState busy={keyBusy} onGenerate={handleGenerate} />
      )}
    </div>
  );
}

function RevealedState({ rawKey, onDismiss }) {
  return (
    <div>
      <code
        data-testid="revealed-key"
        className="block bg-slate-900 text-emerald-400 px-4 py-2.5 rounded-lg text-xs select-all font-mono border border-emerald-500/40 break-all"
      >
        {rawKey}
      </code>
      <p className="text-amber-300 text-xs mt-3 font-semibold">
        Copy this key now. It will not be shown again.
      </p>
      <p className="text-indigo-200 text-xs mt-1">
        Paste it into your GitHub repository secrets as <code className="font-mono">AICAP_API_KEY</code>.
      </p>
      <button
        onClick={onDismiss}
        className="mt-4 w-full bg-emerald-600 text-white text-sm font-bold py-2 rounded-lg hover:bg-emerald-700 transition"
      >
        I've saved the key
      </button>
    </div>
  );
}

function HasKeyState({ busy, onRotate }) {
  return (
    <div>
      <p className="text-indigo-100 text-xs mb-3">
        An API key is active. The raw value cannot be shown again — if you lost it, rotate to issue a new one.
      </p>
      <button
        onClick={onRotate}
        disabled={busy}
        className="w-full bg-slate-900/60 text-white text-sm font-bold py-2 rounded-lg hover:bg-slate-900 transition disabled:opacity-50 border border-indigo-400/30"
      >
        {busy ? 'Rotating…' : 'Rotate Key'}
      </button>
    </div>
  );
}

function NoKeyState({ busy, onGenerate }) {
  return (
    <div>
      <p className="text-indigo-100 text-xs mb-3">
        Generate your API key to use the AIcap GitHub Action.
      </p>
      <button
        onClick={onGenerate}
        disabled={busy}
        className="w-full bg-emerald-600 text-white text-sm font-bold py-2 rounded-lg hover:bg-emerald-700 transition disabled:opacity-50"
      >
        {busy ? 'Generating…' : 'Generate API Key'}
      </button>
    </div>
  );
}
