import React from 'react';
import { Shield, RefreshCw, LogOut } from 'lucide-react';

import { IS_CLOUD_SAAS, supabase } from '../lib/supabase.js';

// Top branding bar. Shows different right-hand controls in cloud SaaS
// vs. local dev mode:
//   - Cloud: PRO CLOUD pill + "Sign Out" when authed
//   - Local: project name + "Rescan Repository" button
//
// `onSignOut` is supplied by the App (we don't call setSession here
// because the sign-out side effect is paired with React state cleanup
// the parent owns).
export default function Header({ session, scanData, isScanning, onRescan, onSignOut }) {
  return (
    <header className="flex items-center justify-between bg-white p-4 rounded-xl shadow-sm border border-slate-200 mb-6">
      <div className="flex items-center gap-3">
        <Shield className="w-8 h-8 text-indigo-600" />
        <h1 className="text-xl font-bold tracking-tight">AI-BOM Compliance Automator</h1>
        {IS_CLOUD_SAAS && (
          <div className="flex items-center gap-3">
            <span className="px-2 py-1 bg-indigo-100 text-indigo-700 text-xs font-bold rounded">PRO CLOUD</span>
            {session && (
              <button
                onClick={async () => {
                  await supabase.auth.signOut();
                  onSignOut();
                }}
                className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition"
              >
                <LogOut className="w-3 h-3" /> Sign Out
              </button>
            )}
          </div>
        )}
      </div>
      {!IS_CLOUD_SAAS && (
        <div className="flex items-center gap-4 text-sm font-medium">
          <span className="text-slate-500">
            Project: <span className="text-slate-900">{scanData.projectName}</span>
          </span>
          <button
            onClick={onRescan}
            disabled={isScanning}
            className="flex items-center gap-2 bg-indigo-50 text-indigo-700 px-4 py-2 rounded-lg hover:bg-indigo-100 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? 'Scanning...' : 'Rescan Repository'}
          </button>
        </div>
      )}
    </header>
  );
}
