import React, { useState } from 'react';
import {
  AlertTriangle, FileText, CheckCircle, Database, Server,
  RefreshCw, DollarSign,
} from 'lucide-react';

import { API_BASE_URL } from '../lib/supabase.js';
import HistoryTable from './HistoryTable.jsx';
import AnnexIVPreview from './AnnexIVPreview.jsx';

// Local-developer view (no auth, no Stripe). Composes the four
// dev-only cards (DB config, posture, annex action) plus the BOM
// table, FinOps table, optional Annex IV preview, and audit ledger.
//
// dbConfig + setDbConfig flow up to the App so the saved-proof flow
// can read whether the local DB is connected.
export default function LocalDashboard({
  scanData,
  historyData,
  fetchHistoryData,
  isGenerating,
  setIsGenerating,
  markdownGenerated,
  setMarkdownGenerated,
  historicalProof,
  setHistoricalProof,
  onHistoryRowClick,
  dbConfig,
  setDbConfig,
}) {
  const [dbConnecting, setDbConnecting] = useState(false);
  const [dbError, setDbError] = useState('');

  const toggleDb = async () => {
    if (dbConfig.enabled) {
      await fetch(`${API_BASE_URL}/api/db-config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false }),
      });
      setDbConfig({ enabled: false, url: '', connected: false });
    } else {
      setDbConfig({ ...dbConfig, enabled: true });
    }
  };

  const connectDb = async () => {
    setDbConnecting(true);
    setDbError('');
    try {
      const res = await fetch(`${API_BASE_URL}/api/db-config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true, url: dbConfig.url }),
      });
      if (!res.ok) throw new Error(await res.text());
      setDbConfig({ ...dbConfig, connected: true });
      fetchHistoryData();
    } catch {
      setDbError('Invalid connection string');
    } finally {
      setDbConnecting(false);
    }
  };

  const handleGenerateAnnexIV = async () => {
    setIsGenerating(true);
    try {
      if (dbConfig.connected) {
        // Local-dev path only: server runs without auth middleware so
        // /api/save-proof accepts an unauthenticated POST. In cloud
        // mode this code path doesn't run because dbConfig.connected
        // is gated on the local-only /api/db-config toggle.
        const response = await fetch(`${API_BASE_URL}/api/save-proof`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(scanData),
        });
        if (response.ok) {
          setMarkdownGenerated(true);
          setHistoricalProof(null);
          fetchHistoryData();
        } else {
          console.error('Failed to save proof drill');
        }
      } else {
        setMarkdownGenerated(true);
        setHistoricalProof(null);
      }
    } catch (error) {
      console.error('Error generating documentation:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left Column: Posture & Actions */}
      <div className="space-y-6 lg:col-span-1">
        <DbConfigCard
          dbConfig={dbConfig}
          setDbConfig={setDbConfig}
          dbConnecting={dbConnecting}
          dbError={dbError}
          onToggle={toggleDb}
          onConnect={connectDb}
        />
        <PostureCard scanData={scanData} />
        <AnnexActionCard
          isGenerating={isGenerating}
          markdownGenerated={markdownGenerated}
          onGenerate={handleGenerateAnnexIV}
        />
      </div>

      {/* Right Column: AI-BOM, FinOps, Annex preview, audit ledger */}
      <div className="lg:col-span-2">
        <BomTable scanData={scanData} />
        <FinOpsTable finOps={scanData.finOps} costEstimate={scanData.finOpsCostEstimate} />

        {(markdownGenerated || historicalProof) && (
          <div className="mt-6">
            <AnnexIVPreview
              scanData={scanData}
              historicalProof={historicalProof}
              mode={historicalProof ? 'historical' : 'current'}
            />
          </div>
        )}

        {dbConfig.connected && (
          <div className="mt-6">
            <HistoryTable
              records={historyData}
              onRowClick={onHistoryRowClick}
              emptyHint="No proof drills recorded yet."
            />
          </div>
        )}
      </div>
    </div>
  );
}

function DbConfigCard({ dbConfig, setDbConfig, dbConnecting, dbError, onToggle, onConnect }) {
  return (
    <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-bold text-slate-500 uppercase tracking-wider">Cloud Database</h2>
        <button
          onClick={onToggle}
          className={`w-10 h-5 rounded-full relative transition-colors focus:outline-none ${dbConfig.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`}
        >
          <span className={`block w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 transition-all ${dbConfig.enabled ? 'left-6' : 'left-1'}`} />
        </button>
      </div>
      {dbConfig.enabled && !dbConfig.connected && (
        <div className="space-y-3 mt-4 animate-in fade-in duration-300">
          <input
            type="text"
            placeholder="postgresql://postgres..."
            className="w-full text-xs p-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none font-mono"
            value={dbConfig.url}
            onChange={e => setDbConfig({ ...dbConfig, url: e.target.value })}
          />
          {dbError && <p className="text-red-500 text-xs">{dbError}</p>}
          <button
            onClick={onConnect}
            disabled={dbConnecting || !dbConfig.url}
            className="w-full bg-slate-900 text-white text-sm font-medium py-2 rounded hover:bg-slate-800 disabled:opacity-50 transition"
          >
            {dbConnecting ? 'Connecting...' : 'Connect Database'}
          </button>
        </div>
      )}
      {dbConfig.connected && (
        <div className="mt-4 flex items-center gap-2 text-sm text-emerald-700 bg-emerald-50 border border-emerald-100 p-3 rounded animate-in fade-in duration-300">
          <Database className="w-4 h-4" />
          <span className="font-medium">Connected to Supabase</span>
        </div>
      )}
      {!dbConfig.enabled && (
        <p className="text-xs text-slate-500 mt-2">
          Enable cloud database to persist compliance scans and generate immutable proof drills.
        </p>
      )}
    </div>
  );
}

function PostureCard({ scanData }) {
  return (
    <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
      <h2 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">EU AI Act Posture</h2>
      <div className="flex items-center gap-4 mb-4">
        {scanData.complianceStatus === 'Passed' ? (
          <CheckCircle className="w-12 h-12 text-emerald-500" />
        ) : (
          <AlertTriangle className="w-12 h-12 text-amber-500" />
        )}
        <div>
          <p className="text-2xl font-bold">{scanData.complianceStatus}</p>
          <p className="text-sm text-slate-500">High-risk dependencies detected in production.</p>
        </div>
      </div>
      <div className="mt-6 border-t pt-6">
        <h3 className="text-sm font-bold text-slate-700 mb-3">Required Actions</h3>
        <ul className="space-y-3">
          <li className="flex items-start gap-2 text-sm text-slate-600">
            <div className="mt-0.5"><div className="w-2 h-2 rounded-full bg-red-500" /></div>
            Article 9: Complete continuous risk mitigation matrix.
          </li>
          <li className="flex items-start gap-2 text-sm text-slate-600">
            <div className="mt-0.5"><div className="w-2 h-2 rounded-full bg-red-500" /></div>
            Annex IV: Generate Technical Documentation.
          </li>
        </ul>
      </div>
    </div>
  );
}

function AnnexActionCard({ isGenerating, markdownGenerated, onGenerate }) {
  return (
    <div className="bg-indigo-600 p-6 rounded-xl shadow-sm text-white">
      <h2 className="text-lg font-bold mb-2">Automate Annex IV</h2>
      <p className="text-indigo-100 text-sm mb-6">
        Generate the required Markdown templates based on detected AST telemetry and commit them via GitOps.
      </p>
      <button
        onClick={onGenerate}
        disabled={isGenerating || markdownGenerated}
        className={`w-full py-3 rounded-lg font-bold flex justify-center items-center gap-2 transition ${
          markdownGenerated ? 'bg-indigo-800 text-indigo-300 cursor-not-allowed' : 'bg-white text-indigo-600 hover:bg-slate-50'
        }`}
      >
        {isGenerating ? <RefreshCw className="w-5 h-5 animate-spin" /> : <FileText className="w-5 h-5" />}
        {markdownGenerated ? 'Documentation Generated' : 'Generate Markdown via GitOps'}
      </button>
    </div>
  );
}

function BomTable({ scanData }) {
  const getRiskBadge = (level) => {
    switch (level) {
      case 'High':
        return <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded-full">HIGH RISK (EU AI Act)</span>;
      case 'Medium':
        return <span className="px-2 py-1 bg-yellow-100 text-yellow-700 text-xs font-bold rounded-full">MEDIUM</span>;
      default:
        return <span className="px-2 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-full">LOW</span>;
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
      <div className="p-6 border-b border-slate-200 flex justify-between items-center">
        <h2 className="text-lg font-bold text-slate-800 flex items-center gap-2">
          <Database className="w-5 h-5 text-slate-400" />
          Discovered AI Bill of Materials (AI-BOM)
        </h2>
        <span className="text-sm text-slate-500">Files scanned: {scanData.scannedFiles}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider border-b border-slate-200">
              <th className="p-4 font-semibold">Component</th>
              <th className="p-4 font-semibold">Version</th>
              <th className="p-4 font-semibold">Ecosystem</th>
              <th className="p-4 font-semibold">Context</th>
              <th className="p-4 font-semibold">Location</th>
              <th className="p-4 font-semibold">Risk Level</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {scanData.dependencies.map((dep, idx) => (
              <tr key={idx} className="hover:bg-slate-50 transition">
                <td className="p-4 font-medium text-slate-900">{dep.name}</td>
                <td className="p-4 text-slate-500 text-sm">{dep.version}</td>
                <td className="p-4 text-slate-500 text-sm flex items-center gap-1">
                  <Server className="w-3 h-3" /> {dep.ecosystem}
                </td>
                <td className="p-4 text-slate-600 text-sm">{dep.description}</td>
                <td className="p-4 text-slate-500 text-sm font-mono">{dep.location || 'N/A'}</td>
                <td className="p-4">{getRiskBadge(dep.riskLevel)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// formatCostRange turns a {monthlyUsdLow, monthlyUsdHigh} pair into the
// "$1,200–$3,400 /mo" string that fits the table cell. Pulled out so a
// future cell that wants the same format (e.g. a future hourly column)
// can reuse the same `Intl.NumberFormat` instance.
const usdFormatter = new Intl.NumberFormat('en-US', {
  style: 'currency', currency: 'USD', maximumFractionDigits: 0,
});
function formatCostRange(cost) {
  if (!cost) return null;
  const lo = usdFormatter.format(cost.monthlyUsdLow);
  const hi = usdFormatter.format(cost.monthlyUsdHigh);
  return lo === hi ? `${lo} /mo` : `${lo}–${hi} /mo`;
}
function formatSpotRange(cost) {
  if (!cost || !cost.spotMultiplier) return null;
  const lo = usdFormatter.format(cost.spotMonthlyUsdLow);
  const hi = usdFormatter.format(cost.spotMonthlyUsdHigh);
  return lo === hi ? `${lo} /mo` : `${lo}–${hi} /mo`;
}

function FinOpsTable({ finOps, costEstimate }) {
  if (!finOps || finOps.length === 0) return null;
  return (
    <div className="mt-6 bg-white rounded-xl shadow-sm border border-amber-200 overflow-hidden">
      <div className="p-6 border-b border-amber-100 bg-amber-50 flex justify-between items-center">
        <h2 className="text-lg font-bold text-amber-800 flex items-center gap-2">
          <DollarSign className="w-5 h-5 text-amber-600" />
          AI FinOps & Cloud Cost Warnings
        </h2>
        {/* Wave 7b: BOM-level cost summary on the right of the header.
           Hidden when the scan emitted no costed findings — the table
           still renders so users see the warnings, but we don't show a
           misleading $0 estimate. */}
        {costEstimate && costEstimate.costedFindings > 0 && (
          <div className="text-right">
            <div className="text-xs text-amber-600 uppercase tracking-wider font-semibold">
              Est. monthly cost
            </div>
            <div className="text-lg font-bold text-amber-800">
              {usdFormatter.format(costEstimate.totalMonthlyUsdLow)}
              {' – '}
              {usdFormatter.format(costEstimate.totalMonthlyUsdHigh)}
            </div>
            {(costEstimate.totalSpotMonthlyUsdLow > 0 || costEstimate.totalSpotMonthlyUsdHigh > 0) && (
              <div className="text-[11px] text-emerald-700 font-semibold">
                Spot: {usdFormatter.format(costEstimate.totalSpotMonthlyUsdLow)}
                {' – '}
                {usdFormatter.format(costEstimate.totalSpotMonthlyUsdHigh)}
                {' '}
                <span className="text-emerald-600">
                  (save {usdFormatter.format(costEstimate.spotSavingsMonthlyUsdLow)}
                  {' – '}
                  {usdFormatter.format(costEstimate.spotSavingsMonthlyUsdHigh)})
                </span>
              </div>
            )}
            <div className="text-[10px] text-amber-600 max-w-xs">
              {costEstimate.costedFindings} costed
              {costEstimate.uncostedFindings > 0 && ` · ${costEstimate.uncostedFindings} no catalog match`}
            </div>
          </div>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-amber-50/50 text-amber-700 text-xs uppercase tracking-wider border-b border-amber-100">
              <th className="p-4 font-semibold">Manifest / Resource</th>
              <th className="p-4 font-semibold">Finding</th>
              <th className="p-4 font-semibold">Est. $/mo</th>
              <th className="p-4 font-semibold">Spot $/mo</th>
              <th className="p-4 font-semibold">Location</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-amber-100">
            {finOps.map((f, idx) => (
              <tr key={idx} className="hover:bg-amber-50/30 transition">
                <td className="p-4 font-medium text-slate-900">{f.resource}</td>
                <td className="p-4 text-amber-700 text-sm flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  {f.description}
                </td>
                <td className="p-4 text-slate-700 text-sm font-mono whitespace-nowrap">
                  {formatCostRange(f.estimatedCost) || <span className="text-slate-400">—</span>}
                </td>
                <td className="p-4 text-emerald-700 text-sm font-mono whitespace-nowrap">
                  {formatSpotRange(f.estimatedCost) || <span className="text-slate-400">—</span>}
                </td>
                <td className="p-4 text-slate-500 text-sm font-mono">{f.location}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {costEstimate && (
        <div className="px-6 py-3 border-t border-amber-100 bg-amber-50/30 text-xs text-amber-700">
          <span className="font-semibold">Assumptions:</span> {costEstimate.assumedHoursPerMonth} hours/month, on-demand list pricing.
          Actual cost depends on instance size, region, and spot/savings-plan/reserved discounts.
        </div>
      )}
    </div>
  );
}
