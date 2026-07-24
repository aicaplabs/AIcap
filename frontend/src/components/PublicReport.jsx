import React, { useState, useEffect } from 'react';
import { Shield, FileText, ArrowRight, ShieldAlert } from 'lucide-react';

import { API_BASE_URL } from '../lib/supabase.js';
import { markdownToHtml, exportAnnexIVPdf } from '../lib/annexIVPdf.js';

// Public, unauthenticated view of a shared Annex IV report — the page an
// auditor or customer lands on when a proof-drill owner sends them a
// share link (/?report=<token>). No session, no dashboard chrome: just
// the document, its ledger provenance, and an AIcap CTA. Every shared
// report doubles as a product demo for the recipient.
export default function PublicReport({ token }) {
  const [state, setState] = useState({ status: 'loading', report: null });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await fetch(
          `${API_BASE_URL}/api/public/report?token=${encodeURIComponent(token)}`,
        );
        if (!resp.ok) throw new Error(`status ${resp.status}`);
        const report = await resp.json();
        if (!cancelled) setState({ status: 'loaded', report });
      } catch {
        if (!cancelled) setState({ status: 'error', report: null });
      }
    })();
    return () => { cancelled = true; };
  }, [token]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      {/* Minimal public header — brand + CTA, no session state. */}
      <header className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between">
        <a href="/" className="flex items-center gap-2 font-extrabold text-slate-900">
          <Shield className="w-5 h-5 text-indigo-600" /> AIcap
          <span className="hidden sm:inline text-xs font-normal text-slate-500 ml-2">
            Continuous AI-BOM &amp; EU AI Act Compliance
          </span>
        </a>
        <a
          href="/"
          className="text-sm bg-indigo-600 hover:bg-indigo-700 text-white font-bold px-4 py-2 rounded-lg transition"
        >
          Generate yours free
        </a>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-10">
        {state.status === 'loading' && (
          <p className="text-center text-slate-500 py-24">Loading report…</p>
        )}

        {state.status === 'error' && (
          <div className="text-center py-24">
            <ShieldAlert className="w-10 h-10 text-slate-400 mx-auto mb-4" />
            <h1 className="text-xl font-bold text-slate-900">
              This report link is invalid or has been revoked.
            </h1>
            <p className="text-slate-500 mt-2 text-sm">
              Ask the report owner for a fresh link, or{' '}
              <a href="/" className="text-indigo-600 font-bold hover:underline">
                generate your own compliance report
              </a>.
            </p>
          </div>
        )}

        {state.status === 'loaded' && (
          <ReportBody report={state.report} />
        )}
      </main>
    </div>
  );
}

function ReportBody({ report }) {
  const created = report.createdAt
    ? new Date(report.createdAt).toLocaleDateString('en-GB', {
        day: 'numeric', month: 'long', year: 'numeric',
      })
    : null;

  return (
    <>
      {/* Provenance strip — the ledger anchoring is the trust story. */}
      <div className="bg-white rounded-xl border border-slate-200 px-5 py-4 mb-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
        <Provenance label="Project" value={report.projectName || '—'} />
        <Provenance label="Commit" value={report.commitSha?.substring(0, 12) || '—'} mono />
        <Provenance label="Recorded" value={created || '—'} />
        <Provenance label="Ledger hash" value={report.cryptoHash?.substring(0, 12) + '…'} mono />
      </div>

      <AttestationNotice attestation={report.attestation} />

      <div className="bg-white rounded-2xl border border-slate-200 shadow-[0_8px_30px_rgb(0,0,0,0.06)] overflow-hidden">
        <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <span className="text-xs px-2 py-1 rounded text-blue-700 bg-blue-50 font-bold">
            Immutable Ledger Record
          </span>
          <button
            onClick={() => exportAnnexIVPdf(report.markdown, { hash: report.cryptoHash })}
            className="text-xs flex items-center gap-1 text-white bg-indigo-600 hover:bg-indigo-500 px-3 py-1 rounded transition"
          >
            <FileText className="w-3 h-3" /> Export PDF
          </button>
        </div>
        <div
          className="p-8 text-sm text-slate-700 [&_h1]:text-xl [&_h1]:font-extrabold [&_h1]:text-slate-900 [&_h1]:border-b-2 [&_h1]:border-indigo-500 [&_h1]:pb-2 [&_h2]:text-base [&_h2]:font-bold [&_h2]:text-slate-900 [&_h2]:mt-6 [&_h3]:text-sm [&_h3]:font-bold [&_h3]:text-slate-800 [&_h3]:mt-4 [&_p]:my-2 [&_blockquote]:my-3 [&_blockquote]:border-l-4 [&_blockquote]:border-amber-400 [&_blockquote]:bg-amber-50 [&_blockquote]:text-amber-900 [&_blockquote]:px-4 [&_blockquote]:py-2 [&_blockquote]:rounded-r [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:my-2 [&_li]:my-1 [&_code]:bg-slate-100 [&_code]:px-1 [&_code]:rounded [&_code]:text-xs [&_code]:font-mono [&_table]:w-full [&_table]:text-xs [&_table]:my-3 [&_table]:block [&_table]:overflow-x-auto [&_th]:border [&_th]:border-slate-300 [&_th]:bg-indigo-50 [&_th]:p-1.5 [&_th]:text-left [&_td]:border [&_td]:border-slate-200 [&_td]:p-1.5"
          // Safe by construction: markdownToHtml escapes all report
          // content before adding markup.
          dangerouslySetInnerHTML={{ __html: markdownToHtml(report.markdown) }}
        />
      </div>

      <div className="text-center mt-10 pb-10">
        <p className="text-slate-500 text-sm mb-3">
          This Annex IV report was generated automatically from a CI pipeline
          and anchored to a tamper-evident audit ledger.
        </p>
        <a
          href="/"
          className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold px-6 py-3 rounded-lg transition shadow-md shadow-indigo-200"
        >
          Generate reports like this in your CI <ArrowRight className="w-4 h-4" />
        </a>
      </div>
    </>
  );
}

// AttestationNotice tells the recipient whether this record can be
// checked independently, and how.
//
// A shared report is only evidence if the person receiving it can verify
// it without trusting the person who sent it. Stating "signed" without
// saying how to check the signature would be decoration; the point is
// that the recipient has everything they need — the signed bytes, the
// signature, and a public key served without authentication.
//
// The unsigned case is shown just as plainly. A recipient who sees no
// notice at all should never have to wonder whether it was absent or
// merely not rendered.
function AttestationNotice({ attestation }) {
  if (!attestation) return null;

  const signed = Boolean(attestation.signature);

  if (!signed) {
    return (
      <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-4 mb-6 text-xs text-amber-900">
        <p className="font-bold mb-1">Not cryptographically signed</p>
        <p>
          {attestation.note ||
            'This entry predates ledger signing. Its hash chain is intact, but the record cannot be attributed to AIcap.'}
        </p>
      </div>
    );
  }

  return (
    <details className="bg-emerald-50 border border-emerald-200 rounded-xl px-5 py-4 mb-6 text-xs text-emerald-900">
      <summary className="font-bold cursor-pointer">
        Cryptographically signed — verify this yourself
      </summary>
      <p className="mt-2">
        This record carries an {attestation.algorithm || 'Ed25519'} signature made with a key
        held by AIcap and never stored in the database. A valid signature proves the record
        was produced by AIcap and has not been altered since — including by whoever sent you
        this link.
      </p>
      <p className="mt-2">
        Base64-decode the signed message and signature below, then check them against the
        public key published at{' '}
        <code className="bg-white/60 px-1 rounded font-mono">
          {attestation.publicKeyPath || '/api/ledger/public-key'}
        </code>{' '}
        using any Ed25519 implementation.
      </p>
      <dl className="mt-3 space-y-2">
        <AttestationField label="Signed message (base64)" value={attestation.signedMessage} />
        <AttestationField label="Signature (base64)" value={attestation.signature} />
        {attestation.signingKeyId && (
          <AttestationField label="Signing key" value={attestation.signingKeyId} />
        )}
      </dl>
    </details>
  );
}

function AttestationField({ label, value }) {
  return (
    <div>
      <dt className="uppercase tracking-wide font-bold text-emerald-700">{label}</dt>
      <dd className="font-mono break-all bg-white/60 rounded px-2 py-1 mt-0.5">{value}</dd>
    </div>
  );
}

function Provenance({ label, value, mono }) {
  return (
    <div>
      <p className="text-slate-400 uppercase tracking-wide font-bold">{label}</p>
      <p className={`text-slate-800 mt-0.5 truncate ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  );
}
