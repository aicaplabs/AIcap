import React from 'react';
import { Shield } from 'lucide-react';

import { markdownToHtml } from '../lib/annexIVPdf.js';
import { LEGAL_PAGES } from '../lib/legalContent.js';

// Public legal/trust page (/?page=terms|privacy|dpa|security). Same
// pattern as PublicReport: standalone view, no auth machinery, minimal
// branded header. Unknown slugs fall back to a link list rather than a
// dead end.
export default function LegalPage({ slug }) {
  const page = LEGAL_PAGES[slug];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      <header className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between">
        <a href="/" className="flex items-center gap-2 font-extrabold text-slate-900">
          <Shield className="w-5 h-5 text-indigo-600" /> AIcap
        </a>
        <nav className="flex items-center gap-4 text-sm text-slate-600">
          {Object.entries(LEGAL_PAGES).map(([key, p]) => (
            <a
              key={key}
              href={`/?page=${key}`}
              className={key === slug ? 'text-indigo-600 font-bold' : 'hover:text-indigo-600'}
            >
              {p.title}
            </a>
          ))}
        </nav>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-10">
        {page ? (
          <div
            className="bg-white rounded-2xl border border-slate-200 p-8 md:p-10 text-sm text-slate-700 [&_h1]:text-2xl [&_h1]:font-extrabold [&_h1]:text-slate-900 [&_h1]:mb-2 [&_h2]:text-base [&_h2]:font-bold [&_h2]:text-slate-900 [&_h2]:mt-8 [&_h2]:mb-2 [&_p]:my-2 [&_p]:leading-relaxed [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:my-2 [&_li]:my-1.5 [&_li]:leading-relaxed [&_em]:text-slate-500 [&_code]:bg-slate-100 [&_code]:px-1 [&_code]:rounded [&_code]:text-xs [&_code]:font-mono [&_table]:w-full [&_table]:text-xs [&_table]:my-3 [&_table]:block [&_table]:overflow-x-auto [&_th]:border [&_th]:border-slate-300 [&_th]:bg-indigo-50 [&_th]:p-1.5 [&_th]:text-left [&_td]:border [&_td]:border-slate-200 [&_td]:p-1.5"
            // Safe by construction: content is a local constant and
            // markdownToHtml escapes before adding markup.
            dangerouslySetInnerHTML={{ __html: markdownToHtml(page.markdown) }}
          />
        ) : (
          <div className="text-center py-24">
            <h1 className="text-xl font-bold text-slate-900">Page not found</h1>
            <ul className="mt-4 space-y-1 text-sm">
              {Object.entries(LEGAL_PAGES).map(([key, p]) => (
                <li key={key}>
                  <a href={`/?page=${key}`} className="text-indigo-600 font-bold hover:underline">
                    {p.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </main>
    </div>
  );
}
