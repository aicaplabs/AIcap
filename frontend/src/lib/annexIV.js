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

export function buildAnnexIVMarkdown(scanData, historicalProof) {
  if (historicalProof) return historicalProof.markdown;
  const deps = scanData.dependencies || [];
  const finOps = scanData.finOps || [];
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

### 2(c) Hardware Requirements & Deployment (FinOps Telemetry)
${finOps.length > 0
  ? finOps.map(f => `- **Resource:** ${f.resource}\n  - **Finding:** ${f.description}`).join('\n')
  : 'No specific hardware constraints or GPU requests detected in infrastructure manifests.'}

## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)
**Current Automated Posture:** ${scanData.complianceStatus}

*Automated CI/CD Pipeline Controls:*
${scanData.complianceStatus === 'Passed'
  ? '- [x] High-risk dependency constraints validated.'
  : '- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.'}
- [ ] \`[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]\`

## 4. Human Oversight & Data Governance (Annex IV, Section 3)
- **Human-in-the-loop (HITL) Controls:** \`[REQUIRES MANUAL INPUT]\`
- **Training Data Provenance:** \`[REQUIRES MANUAL INPUT]\`
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
