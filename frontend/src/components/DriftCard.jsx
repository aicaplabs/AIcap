import React, { useEffect, useState } from 'react';
import { AlertTriangle, ArrowRight, Check, GitCompare, ShieldAlert } from 'lucide-react';

import { apiFetch } from '../lib/supabase.js';

// Drift card — what changed since the previous scan (Wave 18).
//
// The dashboard previously showed a list of scans and nothing about the
// relationship between them, which left the "continuous" in the product
// name unrepresented in the UI. This card answers the question a user
// actually opens the dashboard with: did anything change, and do I need
// to care?
//
// Ordering is deliberate. New advisories come first because they are the
// only category the user did not cause: a CVE published against a
// dependency nobody touched is the one thing a point-in-time audit
// cannot surface, and burying it under dependency churn would waste the
// feature.
export default function DriftCard() {
  const [state, setState] = useState({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await apiFetch('/api/drift');
        if (!resp.ok) throw new Error(`drift request failed: ${resp.status}`);
        const body = await resp.json();
        if (!cancelled) setState({ status: 'ready', body });
      } catch (err) {
        // A failed drift fetch must not take the dashboard down with it;
        // the card simply doesn't render.
        if (!cancelled) setState({ status: 'error', error: err.message });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.status !== 'ready' || !state.body) return null;

  // Fewer than two scans: say so rather than rendering an empty card
  // that looks like "nothing changed".
  if (!state.body.available) {
    return (
      <Shell>
        <p className="text-sm text-slate-500">
          {state.body.reason ||
            'Drift needs at least two scans to compare.'}
        </p>
      </Shell>
    );
  }

  const drift = state.body.drift;
  const s = drift.summary || {};
  const quiet =
    !s.dependenciesAdded &&
    !s.dependenciesRemoved &&
    !s.versionsChanged &&
    !s.newAdvisories &&
    !s.newFindings &&
    !drift.complianceChange;

  return (
    <Shell
      from={drift.from?.commitSha}
      to={drift.to?.commitSha}
      regressed={s.regressed}
    >
      {quiet ? (
        <p className="text-sm text-slate-600 flex items-center gap-2">
          <Check className="w-4 h-4 text-emerald-600" />
          No change to the AI surface since the previous scan.
        </p>
      ) : (
        <div className="space-y-4">
          {drift.risk?.newAdvisories?.length > 0 && (
            <section>
              <h4 className="text-xs font-bold uppercase tracking-wide text-rose-700 flex items-center gap-1.5 mb-2">
                <ShieldAlert className="w-3.5 h-3.5" />
                New advisories since last scan
              </h4>
              <ul className="space-y-1.5">
                {drift.risk.newAdvisories.map((a) => (
                  <li key={a.component} className="text-sm text-slate-700">
                    <code className="font-mono text-xs bg-rose-50 text-rose-800 px-1.5 py-0.5 rounded">
                      {a.component}
                      {a.version ? ` ${a.version}` : ''}
                    </code>{' '}
                    {a.vulns?.map((v) => (
                      <span key={v.id} className="ml-1">
                        {v.id}
                        {v.fixedVersion && (
                          <span className="text-emerald-700 font-medium">
                            {' '}→ fixed in {v.fixedVersion}
                          </span>
                        )}
                      </span>
                    ))}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {drift.complianceChange && (
            <section className="text-sm">
              <span className="text-slate-500">Compliance posture: </span>
              <span className="text-slate-700">{drift.complianceChange.from}</span>
              <ArrowRight className="w-3 h-3 inline mx-1 text-slate-400" />
              <span
                className={
                  drift.complianceChange.regressed
                    ? 'text-rose-700 font-semibold'
                    : 'text-emerald-700 font-semibold'
                }
              >
                {drift.complianceChange.to}
              </span>
            </section>
          )}

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Stat label="Added" value={s.dependenciesAdded} tone={s.highRiskAdded ? 'warn' : 'plain'} />
            <Stat label="Removed" value={s.dependenciesRemoved} />
            <Stat label="Version changes" value={s.versionsChanged} />
            <Stat label="Resolved findings" value={s.resolvedFindings} tone="good" />
          </div>

          {drift.dependencies?.added?.length > 0 && (
            <DetailList
              title="New components"
              items={drift.dependencies.added.map((d) => ({
                key: `${d.name}@${d.version}`,
                label: `${d.name} ${d.version || ''}`.trim(),
                high: d.riskLevel === 'High',
              }))}
            />
          )}

          {drift.dependencies?.versionChanged?.length > 0 && (
            <DetailList
              title="Version changes"
              items={drift.dependencies.versionChanged.map((v) => ({
                key: v.name,
                label: `${v.name}: ${v.fromVersion} → ${v.toVersion}`,
              }))}
            />
          )}
        </div>
      )}
    </Shell>
  );
}

function Shell({ children, from, to, regressed }) {
  return (
    <div
      className={`bg-white p-6 rounded-xl border ${
        regressed ? 'border-rose-300' : 'border-slate-200'
      }`}
    >
      <div className="flex items-center justify-between mb-4 gap-3">
        <h3 className="font-bold text-slate-900 flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-indigo-600" />
          Drift since last scan
        </h3>
        <div className="flex items-center gap-3">
          {from && to && (
            <span className="text-xs font-mono text-slate-400">
              {from.substring(0, 7)} → {to.substring(0, 7)}
            </span>
          )}
          {regressed && (
            <span className="text-xs font-bold text-rose-700 bg-rose-50 px-2 py-1 rounded flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Needs review
            </span>
          )}
        </div>
      </div>
      {children}
      <p className="text-xs text-slate-400 mt-4">
        Per-commit change records support EU AI Act Article 72 post-market monitoring.
      </p>
    </div>
  );
}

function Stat({ label, value, tone }) {
  const colour =
    tone === 'warn' && value > 0
      ? 'text-amber-700'
      : tone === 'good' && value > 0
        ? 'text-emerald-700'
        : 'text-slate-900';
  return (
    <div>
      <p className="text-xs text-slate-400 uppercase tracking-wide font-bold">{label}</p>
      <p className={`text-lg font-bold ${colour}`}>{value ?? 0}</p>
    </div>
  );
}

function DetailList({ title, items }) {
  return (
    <section>
      <h4 className="text-xs font-bold uppercase tracking-wide text-slate-400 mb-1.5">{title}</h4>
      <ul className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <li
            key={it.key}
            className={`text-xs font-mono px-2 py-0.5 rounded ${
              it.high ? 'bg-amber-50 text-amber-800' : 'bg-slate-100 text-slate-700'
            }`}
          >
            {it.label}
          </li>
        ))}
      </ul>
    </section>
  );
}
