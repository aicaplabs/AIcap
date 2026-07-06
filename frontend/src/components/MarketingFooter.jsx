import React from 'react';

// Public footer — rendered under the unauthed landing only. Provides
// the legal / nav links a prospect (and a search-engine crawler)
// expects on a marketing surface.
export default function MarketingFooter() {
  return (
    <footer className="mt-24 pt-10 border-t border-slate-200 pb-10">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-8 max-w-5xl mx-auto text-sm">
        <div>
          <h3 className="font-bold text-slate-900 mb-3">Product</h3>
          <ul className="space-y-2 text-slate-600">
            <li><a className="hover:text-indigo-600" href="#pricing">Pricing</a></li>
            <li><a className="hover:text-indigo-600" href="#faq">FAQ</a></li>
            <li>
              <a
                className="hover:text-indigo-600"
                href="https://github.com/marketplace/actions/continuous-ai-bom-scanner"
              >GitHub Action</a>
            </li>
          </ul>
        </div>
        <div>
          <h3 className="font-bold text-slate-900 mb-3">Resources</h3>
          <ul className="space-y-2 text-slate-600">
            <li>
              <a className="hover:text-indigo-600" href="/guides/">Compliance guides</a>
            </li>
            <li>
              <a className="hover:text-indigo-600" href="https://github.com/istrategeorge/AIcap">Source</a>
            </li>
            <li>
              <a className="hover:text-indigo-600" href="https://github.com/istrategeorge/AIcap/blob/main/CHANGELOG.md">Changelog</a>
            </li>
            <li>
              <a className="hover:text-indigo-600" href="https://github.com/istrategeorge/AIcap/blob/main/CONTRIBUTING.md">Contributing</a>
            </li>
          </ul>
        </div>
        <div>
          <h3 className="font-bold text-slate-900 mb-3">Compliance</h3>
          <ul className="space-y-2 text-slate-600">
            <li>EU AI Act (Aug 2026)</li>
            <li>CycloneDX 1.5</li>
            <li>OWASP ML Top 10</li>
            <li>MITRE ATLAS</li>
          </ul>
        </div>
        <div>
          <h3 className="font-bold text-slate-900 mb-3">Legal</h3>
          <ul className="space-y-2 text-slate-600">
            <li><a className="hover:text-indigo-600" href="/?page=terms">Terms of Service</a></li>
            <li><a className="hover:text-indigo-600" href="/?page=privacy">Privacy Policy</a></li>
            <li><a className="hover:text-indigo-600" href="/?page=dpa">DPA</a></li>
            <li><a className="hover:text-indigo-600" href="/?page=security">Security</a></li>
          </ul>
        </div>
        <div>
          <h3 className="font-bold text-slate-900 mb-3">Contact</h3>
          <ul className="space-y-2 text-slate-600">
            <li>
              <a className="hover:text-indigo-600" href="mailto:hello@aicap.dev">hello@aicap.dev</a>
            </li>
            <li>
              <a className="hover:text-indigo-600" href="mailto:enterprise@aicap.dev">enterprise@aicap.dev</a>
            </li>
            <li>
              <a
                className="hover:text-indigo-600"
                href="https://github.com/istrategeorge/AIcap"
              >
                GitHub
              </a>
            </li>
          </ul>
        </div>
      </div>

      <p className="text-center text-xs text-slate-400 mt-10">
        © {new Date().getFullYear()} AIcap. MIT-licensed CLI. SaaS terms apply
        for the hosted dashboard.
      </p>
    </footer>
  );
}
