import { useState } from 'react';

import { apiFetch } from './supabase.js';

// Shared Stripe-checkout starter used by both the Paywall and the
// trial-banner "Subscribe" control, so there is a single, tested path
// to payment rather than two drifting copies.
//
// Backend derives userID + email from the verified JWT, so the POST
// body intentionally carries nothing. On success the backend returns a
// Stripe Checkout URL and we redirect the whole tab to it.
export function useCheckout(onTokenRefresh) {
  const [isCheckoutLoading, setIsCheckoutLoading] = useState(false);

  const startCheckout = async () => {
    setIsCheckoutLoading(true);
    try {
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
      } else {
        throw new Error('Checkout session did not return a URL.');
      }
    } catch (error) {
      alert(error.message);
      setIsCheckoutLoading(false);
    }
  };

  return { startCheckout, isCheckoutLoading };
}
