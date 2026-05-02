import React from 'react';
import { History } from 'lucide-react';

// Audit-ledger table. Click a row → parent fetches the historical
// proof drill markdown. Used in both the Pro dashboard and the
// local-dev view (with a slightly different empty-state hint).
export default function HistoryTable({ records, onRowClick, emptyHint }) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
      <div className="p-6 border-b border-slate-200">
        <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
          <History className="w-5 h-5 text-slate-400" />
          Immutable Proof Drills (Audit Ledger)
        </h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider border-b border-slate-200">
              <th className="p-4 font-semibold">Timestamp</th>
              <th className="p-4 font-semibold">Project</th>
              <th className="p-4 font-semibold">Commit SHA</th>
              <th className="p-4 font-semibold">Cryptographic Hash (SHA-256)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {records.length === 0 ? (
              <tr>
                <td colSpan="4" className="p-4 text-center text-slate-500 text-sm">
                  {emptyHint || 'No proof drills recorded yet.'}
                </td>
              </tr>
            ) : (
              records.map((record, idx) => (
                <tr
                  key={idx}
                  className="hover:bg-slate-100 transition cursor-pointer"
                  onClick={() => onRowClick(record.cryptoHash)}
                >
                  <td className="p-4 text-slate-600 text-sm whitespace-nowrap">
                    {new Date(record.timestamp).toLocaleString()}
                  </td>
                  <td className="p-4 font-medium text-slate-900">{record.projectName}</td>
                  <td className="p-4 text-slate-500 font-mono text-xs">{record.commitSha}</td>
                  <td className="p-4 text-slate-500 font-mono text-xs truncate max-w-xs" title={record.cryptoHash}>
                    {record.cryptoHash}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
