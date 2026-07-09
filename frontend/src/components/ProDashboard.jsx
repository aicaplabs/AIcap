import React from 'react';

import { apiFetch } from '../lib/supabase.js';
import KeyVault from './KeyVault.jsx';
import HistoryTable from './HistoryTable.jsx';
import AnnexIVPreview from './AnnexIVPreview.jsx';
import ManageSubscriptionButton from './ManageSubscriptionButton.jsx';

// Composition layer for the cloud-SaaS Pro view: welcome banner with
// CI snippet, KeyVault, audit ledger, optional historical Annex IV
// preview. All state is owned by the App and passed down — this
// component is mostly layout.
export default function ProDashboard({
  session,
  revealedKey,
  onSetRevealedKey,
  onHasKeyChange,
  onTokenRefresh,
  historyData,
  onHistoryRowClick,
  historicalProof,
  trialDaysRemaining,
}) {
  return (
    <div className="space-y-6 max-w-5xl mx-auto animate-in fade-in duration-500">
      {trialDaysRemaining > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 flex items-center justify-between">
          <span className="text-amber-800 text-sm">
            <strong>{trialDaysRemaining} day{trialDaysRemaining !== 1 ? 's' : ''} left</strong> in your free trial
          </span>
          <a href="#pricing" className="text-amber-700 text-sm font-medium underline hover:text-amber-900">
            Subscribe to Pro →
          </a>
        </div>
      )}

      {/* Welcome banner + CI snippet + KeyVault */}
      <div className="bg-indigo-600 p-8 rounded-xl shadow-sm text-white flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="max-w-2xl">
          <div className="flex items-start justify-between gap-4 mb-2">
            <h2 className="text-2xl font-bold">
              Welcome back, {session.user.email.split('@')[0]}
            </h2>
            {/* Wave 7e: Stripe customer portal — self-serve cancel,
               payment-method update, invoice history. */}
            <ManageSubscriptionButton onTokenRefresh={onTokenRefresh} />
          </div>
          <p className="text-indigo-100 text-sm">
            To maintain EU AI Act compliance without exposing your proprietary source code, the AIcap scanner runs natively inside your own CI/CD infrastructure. Connect your repository using your secret API key.
          </p>

          <div className="mt-6 bg-slate-900/80 p-4 rounded-lg font-mono text-sm text-indigo-300 overflow-x-auto border border-indigo-500/30">
            <p className="text-slate-500 mb-2"># Add this to your .github/workflows/build.yml</p>
            <p><span className="text-pink-400">-</span> <span className="text-blue-400">name</span>: Run EU AI Act Compliance Scan</p>
            <p>  <span className="text-blue-400">uses</span>: istrategeorge/AIcap@v1.3.0</p>
            <p>  <span className="text-blue-400">with</span>:</p>
            <p>    <span className="text-blue-400">api-key</span>: {'${{ secrets.AICAP_API_KEY }}'}</p>
          </div>
        </div>

        {/* API key panel — one-time reveal model (Wave 3b).
           The plaintext key is only ever shown once, immediately after
           generation or rotation, and is stored nowhere the browser can
           re-read. If the user loses it, they rotate to issue a new one. */}
        <KeyVault
          session={session}
          revealedKey={revealedKey}
          onSetRevealedKey={onSetRevealedKey}
          onHasKeyChange={onHasKeyChange}
          onTokenRefresh={onTokenRefresh}
        />
      </div>

      <HistoryTable
        records={historyData}
        onRowClick={onHistoryRowClick}
        emptyHint="No proof drills recorded yet. Install the GitHub Action to begin syncing!"
      />

      {historicalProof && (
        <AnnexIVPreview
          scanData={null}
          historicalProof={historicalProof}
          mode="historical"
          // Mint (or re-fetch, it's idempotent) the public share token
          // for this proof and hand back the recipient-facing URL.
          onShare={async () => {
            const resp = await apiFetch('/api/share-report', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ hash: historicalProof.hash }),
            }, onTokenRefresh);
            if (!resp.ok) throw new Error(`share failed: ${resp.status}`);
            const { token } = await resp.json();
            return `${window.location.origin}/?report=${token}`;
          }}
        />
      )}
    </div>
  );
}
