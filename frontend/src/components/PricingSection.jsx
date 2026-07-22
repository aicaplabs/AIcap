import React from 'react';
import { Check, Zap, Building2 } from 'lucide-react';

// Public pricing surface — rendered under LandingAuth on the unauthed
// path so the prices are visible to crawlers and prospects without
// requiring an account. The Stripe checkout itself still lives behind
// auth (Paywall.jsx) — this component is purely informational.
export default function PricingSection() {
  return (
    <section
      id="pricing"
      aria-labelledby="pricing-heading"
      className="mt-24 pt-12 border-t border-slate-200"
    >
      <div className="text-center mb-12">
        <p className="text-sm font-bold text-indigo-600 uppercase tracking-widest mb-2">
          Pricing
        </p>
        <h2
          id="pricing-heading"
          className="text-3xl lg:text-4xl font-extrabold text-slate-900"
        >
          Free for the CLI. Pay for the audit ledger.
        </h2>
        <p className="text-slate-600 mt-3 max-w-2xl mx-auto">
          The scanner is open source and runs anywhere. Pro adds the
          immutable proof-drill ledger, hosted Annex IV reports, and the
          self-serve billing portal.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto">
        {/* Free / CLI */}
        <article className="bg-white p-8 rounded-2xl border border-slate-200 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-slate-500" />
            <h3 className="text-lg font-bold text-slate-900">Free CLI</h3>
          </div>
          <p className="text-3xl font-extrabold text-slate-900">$0</p>
          <p className="text-sm text-slate-500 mb-6">forever, MIT licensed</p>
          <ul className="space-y-3 text-sm text-slate-700 flex-grow">
            <PricingFeature>Full AI-BOM scan (Python, Node, Go, Docker, K8s, Terraform)</PricingFeature>
            <PricingFeature>CycloneDX 1.5 SBOM output</PricingFeature>
            <PricingFeature>Annex IV markdown generation</PricingFeature>
            <PricingFeature>OWASP ML Top 10 risk register</PricingFeature>
            <PricingFeature>GitHub Action distribution</PricingFeature>
            <PricingFeature>Up to 10 cloud-synced scans / month</PricingFeature>
          </ul>
          <a
            href="https://github.com/aicaplabs/AIcap"
            className="block mt-6 text-center bg-slate-100 hover:bg-slate-200 text-slate-900 font-bold py-3 rounded-lg transition"
          >
            Get the CLI
          </a>
        </article>

        {/* Pro */}
        <article className="bg-white p-8 rounded-2xl border-2 border-indigo-500 shadow-lg shadow-indigo-100 flex flex-col relative">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-indigo-600 text-white text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wide">
            Most popular
          </div>
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-indigo-600" />
            <h3 className="text-lg font-bold text-slate-900">Pro</h3>
          </div>
          <p className="text-3xl font-extrabold text-slate-900">
            $49<span className="text-base text-slate-500 font-normal"> / month</span>
          </p>
          <p className="text-sm text-slate-500 mb-6">per workspace, billed monthly</p>
          <ul className="space-y-3 text-sm text-slate-700 flex-grow">
            <PricingFeature>Everything in Free</PricingFeature>
            <PricingFeature>Unlimited cloud-synced scans</PricingFeature>
            <PricingFeature>Hash-chained immutable audit ledger</PricingFeature>
            <PricingFeature>Hosted Annex IV reports per commit</PricingFeature>
            <PricingFeature>Live OSV.dev CVE / GHSA enrichment</PricingFeature>
            <PricingFeature>GPU FinOps cost estimates</PricingFeature>
            <PricingFeature>Stripe self-serve billing portal</PricingFeature>
          </ul>
          <a
            href="#signup"
            className="block mt-6 text-center bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-lg transition shadow-md shadow-indigo-200"
          >
            Start Pro
          </a>
        </article>

        {/* Enterprise / self-host */}
        <article className="bg-white p-8 rounded-2xl border border-slate-200 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <Building2 className="w-5 h-5 text-slate-500" />
            <h3 className="text-lg font-bold text-slate-900">Enterprise</h3>
          </div>
          <p className="text-3xl font-extrabold text-slate-900">Custom</p>
          <p className="text-sm text-slate-500 mb-6">self-hosted, EU sovereignty</p>
          <ul className="space-y-3 text-sm text-slate-700 flex-grow">
            <PricingFeature>Everything in Pro</PricingFeature>
            <PricingFeature>Helm chart for Kubernetes deployment</PricingFeature>
            <PricingFeature>Bring your own Postgres (RDS / Cloud SQL / Supabase)</PricingFeature>
            <PricingFeature>EU data residency (Hetzner, Scaleway, OVH)</PricingFeature>
            <PricingFeature>SAML / OIDC SSO (roadmap)</PricingFeature>
            <PricingFeature>Procurement-grade SLA &amp; DPA</PricingFeature>
          </ul>
          <a
            href="mailto:enterprise@aicap.dev?subject=AIcap%20Enterprise%20enquiry"
            className="block mt-6 text-center bg-slate-100 hover:bg-slate-200 text-slate-900 font-bold py-3 rounded-lg transition"
          >
            Contact sales
          </a>
        </article>
      </div>
    </section>
  );
}

function PricingFeature({ children }) {
  return (
    <li className="flex items-start gap-2">
      <Check className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
      <span>{children}</span>
    </li>
  );
}
