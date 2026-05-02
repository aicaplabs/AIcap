// Pure helper that builds the Annex IV markdown for a scan.
//
// Two callers:
//   - When viewing a historical proof drill, we already have the rendered
//     markdown from the backend (`historicalProof.markdown`); just return it.
//   - When previewing the current scan, the dashboard composes the markdown
//     locally from `scanData` so the user can see it before committing.
//
// Kept as a pure function (no React, no state) so it can be unit-tested
// without rendering, and so the same template lives in one place instead
// of being duplicated across the two preview blocks in the old App.jsx.

// renderFinOpsBlock mirrors the backend's § 2(c) FinOps rendering:
// per-finding lines with optional cost detail, plus a BOM-level
// summary line + assumptions. Pulled out of the template literal so
// the formatting logic stays readable.
function renderFinOpsBlock(finOps, est) {
  const lines = finOps.map(f => {
    const base = `- **Resource:** ${f.resource}\n  - **Finding:** ${f.description}`;
    const c = f.estimatedCost;
    if (!c) return base;
    return base + `\n  - **Estimated cost:** $${c.hourlyUsdLow.toFixed(2)}–$${c.hourlyUsdHigh.toFixed(2)} /hr → **$${Math.round(c.monthlyUsdLow)}–$${Math.round(c.monthlyUsdHigh)} /month** (${c.cloud} family \`${c.instanceFamily}\`)`;
  });
  if (est && (est.costedFindings > 0 || est.uncostedFindings > 0)) {
    lines.push('');
    lines.push(`**Estimated total monthly cost:** $${Math.round(est.totalMonthlyUsdLow)}–$${Math.round(est.totalMonthlyUsdHigh)} ${est.currency} (across ${est.costedFindings} costed finding(s); ${est.uncostedFindings} additional finding(s) had no catalog match).`);
    lines.push(`_Assumptions: ${est.assumedHoursPerMonth} hours/month. ${est.disclaimer}_`);
  }
  return lines.join('\n');
}

// renderGovernance is the per-section helper that mirrors the backend's
// renderGovernanceSection (pkg/compliance/compliance.go). When the
// scanner emitted signals for a section we list them; otherwise we
// keep the original `[REQUIRES MANUAL INPUT]` placeholder so auditors
// see "we looked, found nothing — please document manually" rather
// than silent omission.
function renderGovernance(title, signals) {
  if (!signals || signals.length === 0) {
    return `- **${title}:** \`[REQUIRES MANUAL INPUT]\``;
  }
  const lines = signals.map(
    s => `  - ${s.description} _(source: ${s.source}, location: \`${s.location}\`)_`,
  );
  return `- **${title}:** ${signals.length} signal(s) detected — see evidence below.\n${lines.join('\n')}`;
}

export function buildAnnexIVMarkdown(scanData, historicalProof) {
  if (historicalProof) return historicalProof.markdown;
  const deps = scanData.dependencies || [];
  const finOps = scanData.finOps || [];
  // Wave 7a: governance signals come from the backend's PerformScan when
  // the scanData was sourced from /api/scan; the local-dev preview path
  // gracefully degrades to placeholders if the field is absent.
  const gov = scanData.governance || {};
  const promptDefenses = gov.promptInjectionDefenses || [];
  const promptDefenseLine = promptDefenses.length > 0
    ? `- [x] Prompt-injection defences detected: ${promptDefenses.map(s => `\`${s.evidence}\``).join(', ')}`
    : '- [ ] `[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]`';

  return `# EU AI Act - Annex IV Technical Documentation

## 1. General System Description (Annex IV, Section 1)
- **System Name:** ${scanData.projectName}
- **Version / Commit SHA:** \`Pending CI/CD Injection\`
- **Intended Purpose:** \`[REQUIRES MANUAL INPUT: Describe the exact purpose of this AI system]\`

## 2. System Architecture & Components (Annex IV, Section 2)
### 2(a) Pre-trained Systems & Dependencies (AI-BOM)
${deps.length > 0
  ? deps.map(d => `- **${d.name}** (v${d.version})${d.license ? ` [License: ${d.license}]` : ''}: ${d.description} (Risk: ${d.riskLevel})`).join('\n')
  : 'No AI dependencies detected.'}

### 2(c) Hardware Requirements & Estimated Monthly Cost (FinOps Telemetry)
${finOps.length > 0
  ? renderFinOpsBlock(finOps, scanData.finOpsCostEstimate)
  : 'No specific hardware constraints or GPU requests detected in infrastructure manifests.'}

## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)
**Current Automated Posture:** ${scanData.complianceStatus}

*Automated CI/CD Pipeline Controls:*
${scanData.complianceStatus === 'Passed'
  ? '- [x] High-risk dependency constraints validated.'
  : '- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.'}
${promptDefenseLine}

## 4. Human Oversight & Data Governance (Annex IV, Section 3)
${renderGovernance('Human-in-the-loop (HITL) Controls', gov.hitl)}
${renderGovernance('Training Data Provenance', gov.trainingData)}
${renderGovernance('Bias Monitoring', gov.biasMonitoring)}
`;
}

// Trigger a browser download of the given markdown content. Pure DOM
// I/O — kept out of React render code so callers that just need to
// pipe the markdown elsewhere don't have to drag in the side effect.
export function downloadAnnexIV(markdown, historicalHash) {
  const blob = new Blob([markdown], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = historicalHash
    ? `annex-iv-${historicalHash.substring(0, 8)}.md`
    : 'annex-iv.md';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
