import React from 'react';
import { RefreshCw } from 'lucide-react';

// Shown immediately on the Stripe success redirect (initialised from
// the `session_id` URL param so it appears before the Supabase session
// is even restored). Without this card, users would briefly see the
// login form between the Stripe redirect and the session mount.
export default function CheckoutProcessing() {
  return (
    <div className="max-w-lg mx-auto mt-16 bg-white p-8 rounded-2xl shadow-sm border border-slate-200 text-center animate-in fade-in zoom-in-95 duration-300">
      <div className="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center mx-auto mb-4">
        <RefreshCw className="w-8 h-8 text-indigo-600 animate-spin" />
      </div>
      <h2 className="text-2xl font-bold text-slate-900 mb-2">Activating your subscription…</h2>
      <p className="text-slate-500 text-sm">
        We're confirming your payment and setting up your Pro account. This usually takes a few seconds.
      </p>
    </div>
  );
}
