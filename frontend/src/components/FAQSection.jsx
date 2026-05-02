import React from 'react';

// Public FAQ surface — answers the questions a prospect would ask before
// signing up. Plain HTML <details> elements rather than a custom
// accordion: keyboard-accessible by default, search-engine-readable,
// and the FAQPage JSON-LD in index.html could one day be hooked up to
// these answers for rich-result eligibility.
const FAQS = [
  {
    q: 'Do I need to use the SaaS to comply?',
    a: 'No. The CLI is MIT-licensed and runs anywhere. It generates the AI-BOM, CycloneDX SBOM, and Annex IV markdown locally. The SaaS adds the hash-chained audit ledger, hosted reports, and live CVE/GHSA enrichment — useful for audits, not strictly required to scan.',
  },
  {
    q: 'How does AIcap detect AI dependencies?',
    a: 'Multi-layer parsing. Layer 1 reads dependency manifests (requirements.txt, pyproject.toml, Pipfile.lock, package.json, pnpm-lock.yaml, yarn.lock, go.mod, environment.yml). Layer 2 scans source code for imports and hardcoded model strings via Go AST and Python regex. Layer 3 detects model weight files (.safetensors, .onnx, .pt, .h5, .gguf) and Dockerfile base images.',
  },
  {
    q: 'What does the Annex IV output cover?',
    a: 'Section 1 (general info), Section 2 (system description, including auto-populated hardware requirements with monthly USD estimates), Section 3(a) (cross-referenced risk register against OWASP ML Top 10, MITRE ATLAS, and live OSV.dev CVEs/GHSAs), Section 3(c) (prompt-injection defences), and Section 4 (HITL, training data provenance, bias monitoring — auto-populated from IaC when signals are present, explicit [REQUIRES MANUAL INPUT] otherwise).',
  },
  {
    q: 'How is the audit ledger immutable?',
    a: 'Every save-proof writes a row whose crypto_hash is sha256(commit_sha || ai_bom_json || prev_hash). Each row links to the previous one for that user, so a tampered or deleted historical row breaks the chain at every later link. GET /api/verify-chain walks your chain and reports the first divergence. The hash formula is documented and the ledger schema is public.',
  },
  {
    q: 'Where is my data stored?',
    a: 'Cloud SaaS: Supabase (Postgres), region configurable. Enterprise / self-host: anywhere you can run the Helm chart and a Postgres — Hetzner, Scaleway, OVH, AWS Frankfurt, an air-gapped on-prem cluster. The CLI never sends data anywhere unless AICAP_API_KEY is set.',
  },
  {
    q: 'What happens if my Stripe payment fails?',
    a: 'Stripe retries 3 times. After the third failure, your subscription tier flips to free and the rolling-window rate limiter kicks in (10 cloud-synced scans per 30 days). Your API key is preserved — when you re-subscribe, your tier flips back without forcing key rotation. Manage payment methods, invoices, and cancellation through the Stripe self-serve portal.',
  },
  {
    q: 'Does the scanner phone home?',
    a: 'The CLI only contacts the AIcap API when AICAP_API_KEY is set, and only contacts api.osv.dev for CVE/GHSA enrichment when AICAP_OSV_DISABLED is unset. Both can be turned off. There is no telemetry beyond those two opt-in flows.',
  },
  {
    q: 'Can I block the build on policy violations?',
    a: 'Yes. Drop a .aicap.yml in your repo root with blocked_models, allowed_models, allowed_licenses, and block_on_high_risk: true. The scanner exits non-zero on any violation, which fails the CI step.',
  },
];

export default function FAQSection() {
  return (
    <section
      id="faq"
      aria-labelledby="faq-heading"
      className="mt-24 pt-12 border-t border-slate-200"
    >
      <div className="text-center mb-10">
        <p className="text-sm font-bold text-indigo-600 uppercase tracking-widest mb-2">
          FAQ
        </p>
        <h2
          id="faq-heading"
          className="text-3xl lg:text-4xl font-extrabold text-slate-900"
        >
          Frequently asked questions
        </h2>
      </div>

      <div className="max-w-3xl mx-auto space-y-3">
        {FAQS.map(({ q, a }) => (
          <details
            key={q}
            className="bg-white border border-slate-200 rounded-xl px-5 py-4 group open:shadow-sm"
          >
            <summary className="flex items-center justify-between cursor-pointer list-none font-semibold text-slate-900">
              <span>{q}</span>
              <span
                aria-hidden="true"
                className="text-slate-400 group-open:rotate-45 transition-transform text-xl leading-none"
              >
                +
              </span>
            </summary>
            <p className="mt-3 text-slate-600 leading-relaxed text-sm">{a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
