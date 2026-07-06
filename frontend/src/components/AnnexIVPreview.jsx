import React, { useState } from 'react';
import { Download, FileText, Link2, Check } from 'lucide-react';

import { buildAnnexIVMarkdown, downloadAnnexIV } from '../lib/annexIV.js';
import { exportAnnexIVPdf } from '../lib/annexIVPdf.js';

// Markdown preview pane shown beneath the dashboard. Two modes:
//   - historical: a row was clicked in the audit ledger; show the
//     stored markdown and label it as "Immutable Ledger".
//   - current:    the dev pressed "Generate Annex IV"; show a
//     locally-built markdown labelled "Ready to commit".
//
// `mode` is one of 'historical' | 'current' so the parent doesn't
// need to encode that in two separate booleans.
//
// `onShare` (optional, cloud-only) is an async () => url that mints a
// public share link for the historical proof on display. When absent
// the Share button doesn't render, so the local dashboard is unchanged.
export default function AnnexIVPreview({ scanData, historicalProof, mode, onShare }) {
  // 'idle' | 'busy' | 'copied' | 'failed' — resets to idle after feedback.
  const [shareState, setShareState] = useState('idle');
  const markdown = buildAnnexIVMarkdown(scanData, historicalProof);
  const label = historicalProof
    ? `Historical Record (${historicalProof.hash.substring(0, 8)})`
    : 'docs/compliance/annex-iv.md';
  const badgeClass = historicalProof
    ? 'text-blue-400 bg-blue-400/10'
    : 'text-emerald-400 bg-emerald-400/10';
  const badgeText = historicalProof ? 'Immutable Ledger' : 'Ready to commit';

  const handleShare = async () => {
    if (shareState === 'busy') return;
    setShareState('busy');
    try {
      const url = await onShare();
      await navigator.clipboard.writeText(url);
      setShareState('copied');
    } catch {
      setShareState('failed');
    }
    setTimeout(() => setShareState('idle'), 2500);
  };

  // The local-dev view sometimes only wants the historical mode (no
  // "current" preview because the dev hasn't generated it yet); the
  // parent decides whether to render this component at all.
  if (mode === 'current' && !scanData) return null;

  return (
    <div className="bg-slate-900 rounded-xl shadow-sm border border-slate-700 overflow-hidden text-slate-300 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-400">{label}</span>
          <span className={`text-xs px-2 py-1 rounded ${badgeClass}`}>{badgeText}</span>
        </div>
        <div className="flex items-center gap-2">
          {onShare && historicalProof && (
            <button
              onClick={handleShare}
              className="text-xs flex items-center gap-1 text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded transition"
            >
              {shareState === 'copied' ? (
                <><Check className="w-3 h-3 text-emerald-400" /> Link copied</>
              ) : shareState === 'failed' ? (
                <>Share failed — retry</>
              ) : (
                <><Link2 className="w-3 h-3" /> {shareState === 'busy' ? 'Sharing…' : 'Share'}</>
              )}
            </button>
          )}
          <button
            onClick={() => exportAnnexIVPdf(markdown, {
              hash: historicalProof?.hash,
              projectName: scanData?.projectName,
            })}
            className="text-xs flex items-center gap-1 text-white bg-indigo-600 hover:bg-indigo-500 px-3 py-1 rounded transition"
          >
            <FileText className="w-3 h-3" /> Export PDF
          </button>
          <button
            onClick={() => downloadAnnexIV(markdown, historicalProof?.hash)}
            className="text-xs flex items-center gap-1 text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded transition"
          >
            <Download className="w-3 h-3" /> Download
          </button>
        </div>
      </div>
      <div className="p-6 font-mono text-sm overflow-x-auto whitespace-pre">
        {markdown}
      </div>
    </div>
  );
}
