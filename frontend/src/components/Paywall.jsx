import React, { useState } from 'react';
import { DollarSign, CheckCircle } from 'lucide-react';

import { apiFetch } from '../lib/supabase.js';

// Pro upgrade screen shown to authenticated free-tier users.
// trialExpired=true renders a "trial ended" variant instead of the generic CTA.
export default function Paywall({ onTokenRefresh, trialExpired = false }) {
  const [isCheckoutLoading, setIsCheckoutLoading] = useState(false);

  const handleCheckout = async () => {
    setIsCheckoutLoading(true);
    try {
      // Backend derives userID + email from the verified JWT, so the
      // request body intentionally carries nothing.
      const response = await apiFetch(
        '/api/create-checkout-session',
        { method: 'POST', headers: { 'Content-Type': 'application/json' } },
        onTokenRefresh,
      );
      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Checkout Error: ${errText}`);
      }
      const data = await response.json();
      if (data.url) {
        window.location.href = data.url; // Redirect to Stripe
      }
    } catch (error) {
      alert(error.message);
      setIsCheckoutLoading(false);
    }
  };

  return (
    <div className="max-w-lg mx-auto mt-16 bg-white p-8 rounded-2xl shadow-sm border border-slate-200 text-center animate-in fade-in zoom-in-95 duration-300">
      <div className="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mx-auto mb-4">
        <DollarSign className="w-8 h-8 text-amber-600" />
      </div>
      {trialExpired ? (
        <>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Your free trial has ended</h2>
          <p className="text-slate-500 text-sm mb-6">
            Subscribe to Pro to keep your Immutable Audit Ledger, pipeline integration, and Annex IV sync.
          </p>
        </>
      ) : (
        <>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Upgrade to AIcap Pro</h2>
          <p className="text-slate-500 text-sm mb-6">
            Unlock the Immutable Audit Ledger, GitOps pipeline integration, and automated EU AI Act Annex IV documentation sync.
          </p>
        </>
      )}
      <div className="bg-slate-50 border border-slate-100 rounded-xl p-6 mb-6 text-left">
        <ul className="space-y-3">
          <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500" /> Unlimited CI/CD scans</li>
          <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500" /> Cryptographic Proof Drills</li>
          <li className="flex items-center gap-2 text-sm text-slate-700"><CheckCircle className="w-4 h-4 text-emerald-500" /> FinOps & GPU Cost Warnings</li>
        </ul>
      </div>
      <button
        onClick={handleCheckout}
        disabled={isCheckoutLoading}
        className="w-full bg-indigo-600 text-white font-bold py-3 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
      >
        {isCheckoutLoading ? 'Redirecting to Stripe...' : 'Subscribe now for $49/mo'}
      </button>
    </div>
  );
}
