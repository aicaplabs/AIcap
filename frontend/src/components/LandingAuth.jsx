import React, { useState } from 'react';
import { Shield, CheckCircle, AlarmClock, MailCheck } from 'lucide-react';

import { supabase } from '../lib/supabase.js';
import { daysUntilAIAct } from '../lib/deadline.js';
import SampleReportSection from './SampleReportSection.jsx';
import PricingSection from './PricingSection.jsx';
import FAQSection from './FAQSection.jsx';
import MarketingFooter from './MarketingFooter.jsx';

// Deadline urgency chip: counts down to 2 August 2026 (EU AI Act
// application date) and flips to "in force" copy once it passes, so
// the landing page never shows a stale countdown.
function DeadlineBadge() {
  const days = daysUntilAIAct();
  if (days > 0) {
    return (
      <div className="inline-flex items-center gap-2 px-3 py-1 bg-amber-100 text-amber-800 text-sm font-bold rounded-full">
        <AlarmClock className="w-4 h-4" />
        {days} day{days === 1 ? '' : 's'} until EU AI Act obligations apply — 2 August 2026
      </div>
    );
  }
  return (
    <div className="inline-flex items-center gap-2 px-3 py-1 bg-red-100 text-red-700 text-sm font-bold rounded-full">
      <AlarmClock className="w-4 h-4" /> EU AI Act obligations are now in force
    </div>
  );
}

// Public landing page + login/signup form. Self-contained: owns its own
// form state and the supabase signUp/signInWithPassword call. The App
// only needs to know "session exists or not" — onAuthStateChange takes
// over once Supabase emits SIGNED_IN.
export default function LandingAuth() {
  const [authForm, setAuthForm] = useState({ email: '', password: '', loading: false });
  const [isSignUp, setIsSignUp] = useState(false);
  // Set when signUp succeeds but returns no session — i.e. email
  // confirmation is enabled and the user must click the link first.
  const [emailSent, setEmailSent] = useState(false);

  const handleAuth = async (e) => {
    e.preventDefault();
    setAuthForm(prev => ({ ...prev, loading: true }));
    try {
      if (isSignUp) {
        const { data, error } = await supabase.auth.signUp({
          email: authForm.email,
          password: authForm.password,
        });
        if (error) throw error;
        // With email confirmation on, signUp returns a user but no
        // session — nothing else happens until the link is clicked, so
        // show a "check your email" panel instead of silently resetting
        // the form. With confirmation off, a session is present and
        // onAuthStateChange takes over exactly as before.
        if (!data.session) setEmailSent(true);
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email: authForm.email,
          password: authForm.password,
        });
        if (error) throw error;
      }
    } catch (err) {
      alert(err.message);
    } finally {
      setAuthForm(prev => ({ ...prev, loading: false }));
    }
  };

  return (
    <div className="max-w-6xl mx-auto mt-8 animate-in fade-in duration-500">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">

        {/* Marketing Copy */}
        <div className="space-y-6">
          <DeadlineBadge />
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-100 text-indigo-700 text-sm font-bold rounded-full ml-2">
            <Shield className="w-4 h-4" /> EU AI Act Ready
          </div>
          <h2 className="text-4xl lg:text-5xl font-extrabold text-slate-900 leading-tight">
            Secure your AI supply chain. <span className="text-indigo-600">Automate compliance.</span>
          </h2>
          <p className="text-lg text-slate-600 leading-relaxed">
            Every AI system shipped to the EU market must comply with the AI Act by August 2026. AIcap runs natively inside your CI/CD pipeline to generate your AI-BOM, track risks, and maintain an Immutable Audit Ledger.
          </p>
          <div className="space-y-4 pt-4">
            <div className="flex items-start gap-3">
              <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
              <p className="text-slate-700"><strong>Shift-Left Compliance:</strong> Automatic Annex IV documentation generation.</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
              <p className="text-slate-700"><strong>DevSecOps Ready:</strong> Native CycloneDX SBOM & OWASP ML Top 10 enrichment.</p>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle className="w-6 h-6 text-emerald-500 shrink-0" />
              <p className="text-slate-700"><strong>FinOps Tracking:</strong> Identify expensive unoptimized GPU requests before deployment.</p>
            </div>
          </div>
        </div>

        {/* Login/Signup Form */}
        <div id="signup" className="bg-white p-8 rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.12)] border border-slate-100 relative scroll-mt-8">
          <div className="absolute -top-6 -right-6 text-7xl opacity-5">🛡️</div>
          {emailSent ? (
            <div className="text-center py-6 relative z-10">
              <div className="w-14 h-14 bg-indigo-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <MailCheck className="w-7 h-7 text-indigo-600" />
              </div>
              <h3 className="text-2xl font-bold text-slate-900 mb-2">Check your email</h3>
              <p className="text-slate-600 text-sm">
                We sent a confirmation link to <strong>{authForm.email}</strong>.
                Click it to activate your 14-day Pro trial — no card required.
              </p>
              <p className="text-slate-400 text-xs mt-4">
                Didn't get it? Check your spam folder, or{' '}
                <button
                  onClick={() => { setEmailSent(false); setIsSignUp(true); }}
                  className="text-indigo-600 hover:text-indigo-800 font-medium"
                >
                  try a different email
                </button>.
              </p>
            </div>
          ) : (
          <>
          <div className="text-center mb-8 relative z-10">
            <h3 className="text-2xl font-bold text-slate-900">{isSignUp ? 'Start your Pro trial' : 'Sign in to AIcap Pro'}</h3>
            <p className="text-slate-500 text-sm mt-2">{isSignUp ? 'Generate your API key and connect your repositories.' : 'Access your immutable audit ledger.'}</p>
          </div>
          <form onSubmit={handleAuth} className="space-y-5 relative z-10">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Work Email</label>
              <input
                type="email" required
                value={authForm.email}
                onChange={e => setAuthForm({ ...authForm, email: e.target.value })}
                className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none transition"
                placeholder="devsecops@company.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <input
                type="password" required
                value={authForm.password}
                onChange={e => setAuthForm({ ...authForm, password: e.target.value })}
                className="w-full p-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none transition"
                placeholder="••••••••"
              />
            </div>
            <button
              type="submit"
              disabled={authForm.loading}
              className="w-full bg-indigo-600 text-white font-bold py-3.5 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 mt-4 shadow-md shadow-indigo-200"
            >
              {authForm.loading ? 'Authenticating...' : (isSignUp ? 'Create Free Account' : 'Sign In')}
            </button>
          </form>
          <div className="mt-6 text-center relative z-10">
            <p className="text-slate-500 text-sm mb-2">
              {isSignUp ? 'Already have an account?' : "Don't have an account yet?"}
            </p>
            <button
              onClick={() => setIsSignUp(!isSignUp)}
              className="text-sm text-indigo-600 hover:text-indigo-800 font-bold transition"
            >
              {isSignUp ? 'Sign In' : 'Sign up for AIcap Pro'}
            </button>
          </div>
          </>
          )}
        </div>
      </div>

      {/* Trust/Social Proof Section */}
      <div className="mt-20 pt-10 border-t border-slate-200 text-center">
        <p className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-6">Built for Modern Tech Stacks</p>
        <div className="flex flex-wrap justify-center gap-8 md:gap-16 opacity-60 grayscale filter">
          <span className="text-xl font-bold font-mono">Python</span>
          <span className="text-xl font-bold font-mono">Node.js</span>
          <span className="text-xl font-bold font-mono">Golang</span>
          <span className="text-xl font-bold font-mono">Kubernetes</span>
          <span className="text-xl font-bold font-mono">Terraform</span>
        </div>
      </div>

      <SampleReportSection />
      <PricingSection />
      <FAQSection />
      <MarketingFooter />
    </div>
  );
}
