import React, { useState } from 'react';
import { CreditCard } from 'lucide-react';

import { apiFetch } from '../lib/supabase.js';

// "Manage subscription" button — opens the Stripe-hosted customer
// portal in the same window. Used by Pro users to self-serve
// cancellations, payment-method updates, and invoice history.
//
// Backend `/api/customer-portal` returns 400 for users with no
// stripe_customer_id (free tier, or Pro users where the webhook
// hasn't fired yet). We surface that as an alert rather than a
// silent no-op so the user knows why nothing happened.
export default function ManageSubscriptionButton({ onTokenRefresh }) {
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    setLoading(true);
    try {
      const resp = await apiFetch(
        '/api/customer-portal',
        { method: 'POST', headers: { 'Content-Type': 'application/json' } },
        onTokenRefresh,
      );
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(text || `Portal Error: ${resp.status}`);
      }
      const data = await resp.json();
      if (data.url) {
        // Same-tab navigation; Stripe sends the user back via the
        // ReturnURL configured server-side.
        window.location.href = data.url;
        return;
      }
      throw new Error('Stripe portal session returned no URL');
    } catch (err) {
      alert(err.message);
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className="inline-flex items-center gap-2 text-xs px-3 py-1.5 bg-slate-900/60 hover:bg-slate-900 text-indigo-100 rounded-lg border border-indigo-400/30 transition disabled:opacity-50"
    >
      <CreditCard className="w-3.5 h-3.5" />
      {loading ? 'Opening portal…' : 'Manage subscription'}
    </button>
  );
}
