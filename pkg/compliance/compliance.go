package compliance
import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aicap/pkg/types"
)
// GenerateAnnexIVMarkdown is the convenience entry point used by
// callers (e.g. the CLI) that don't have a pre-computed risk
// register on hand. It just delegates to the with-register variant
// after computing the catalog-only register internally.
func GenerateAnnexIVMarkdown(bom types.AIBOM) string {
	return GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
}

// GenerateAnnexIVMarkdownWithRegister renders Annex IV using a
// caller-supplied register. /api/save-proof uses this so the
// rendered markdown reflects the OSV-enriched register (Wave 7f),
// not just the catalog-only one. Pure formatter — does no I/O.
func GenerateAnnexIVMarkdownWithRegister(bom types.AIBOM, register types.RiskRegister) string {
	var sb strings.Builder
	sb.WriteString("# EU AI Act - Annex IV Technical Documentation\n\n")
	sb.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Section 1: General Description
	sb.WriteString("## 1. General System Description (Annex IV, Section 1)\n")
	sb.WriteString(fmt.Sprintf("- **System Name:** %s\n", bom.ProjectName))
	sb.WriteString(fmt.Sprintf("- **Version / Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Total Files Scanned:** %d\n", bom.ScannedFiles))
	sb.WriteString(fmt.Sprintf("- **AI Components Detected:** %d\n", len(bom.Dependencies)))
	sb.WriteString("- **Intended Purpose:** `[REQUIRES MANUAL INPUT: Describe the exact purpose of this AI system]`\n\n")

	// Section 2: Architecture & Components
	sb.WriteString("## 2. System Architecture & Components (Annex IV, Section 2)\n\n")

	// 2(a): Dependencies grouped by ecosystem
	sb.WriteString("### 2(a) Pre-trained Systems & Dependencies (AI-BOM)\n")
	if len(bom.Dependencies) == 0 {
		sb.WriteString("No AI dependencies detected.\n\n")
	} else {
		// Group dependencies by ecosystem for clarity
		ecosystems := map[string][]types.AIDependency{}
		for _, dep := range bom.Dependencies {
			ecosystems[dep.Ecosystem] = append(ecosystems[dep.Ecosystem], dep)
		}
		for ecosystem, deps := range ecosystems {
			sb.WriteString(fmt.Sprintf("\n**%s:**\n", ecosystem))
			for _, dep := range deps {
				licenseText := ""
				if dep.License != "" {
					licenseText = fmt.Sprintf(" [License: %s]", dep.License)
				}
				sb.WriteString(fmt.Sprintf("- **%s** (v%s)%s: %s (Risk: %s)\n", dep.Name, dep.Version, licenseText, dep.Description, dep.RiskLevel))
			}
		}
		sb.WriteString("\n")
	}

	// 2(b): Licensing Summary (auto-generated)
	sb.WriteString("### 2(b) Licensing Compliance Summary\n")
	licensedCount := 0
	unlicensedHighRisk := 0
	licenseTypes := map[string]int{}
	for _, dep := range bom.Dependencies {
		if dep.License != "" {
			licensedCount++
			licenseTypes[dep.License]++
		} else if dep.RiskLevel == "High" {
			unlicensedHighRisk++
		}
	}
	sb.WriteString(fmt.Sprintf("- **Components with license data:** %d / %d\n", licensedCount, len(bom.Dependencies)))
	sb.WriteString(fmt.Sprintf("- **High-risk components missing license:** %d\n", unlicensedHighRisk))
	if len(licenseTypes) > 0 {
		sb.WriteString("- **License distribution:**\n")
		for lic, count := range licenseTypes {
			sb.WriteString(fmt.Sprintf("  - %s: %d component(s)\n", lic, count))
		}
	}
	sb.WriteString("\n")

	// 2(c): Hardware & Infrastructure
	sb.WriteString("### 2(c) Hardware Requirements & Estimated Monthly Cost (FinOps Telemetry)\n")
	if len(bom.FinOps) == 0 {
		sb.WriteString("No specific hardware constraints or GPU requests detected in infrastructure manifests.\n\n")
	} else {
		// Wave 7b: each finding now optionally carries an EstimatedCost
		// from the curated catalog (pkg/finops/gpu_costs.json). Render
		// it inline so auditors see the dollar figure per resource;
		// the summary block below aggregates the total range.
		for _, fin := range bom.FinOps {
			sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", fin.Resource))
			sb.WriteString(fmt.Sprintf("  - **Finding:** %s\n", fin.Description))
			sb.WriteString(fmt.Sprintf("  - **Severity:** %s\n", fin.Severity))
			if fin.EstimatedCost != nil {
				sb.WriteString(fmt.Sprintf(
					"  - **Estimated cost:** $%.2f–$%.2f /hr → **$%.0f–$%.0f /month** (%s family `%s`)\n",
					fin.EstimatedCost.HourlyUSDLow, fin.EstimatedCost.HourlyUSDHigh,
					fin.EstimatedCost.MonthlyUSDLow, fin.EstimatedCost.MonthlyUSDHigh,
					fin.EstimatedCost.Cloud, fin.EstimatedCost.InstanceFamily,
				))
			}
		}
		// BOM-level summary surfaces the aggregate, which is what the
		// FinOps user actually budgets against. Costed-vs-uncosted
		// counters tell auditors when the headline figure is missing
		// detections.
		if est := bom.FinOpsCostEstimate; est != nil && (est.CostedFindings > 0 || est.UncostedFindings > 0) {
			sb.WriteString(fmt.Sprintf("\n**Estimated total monthly cost:** $%.0f–$%.0f %s "+
				"(across %d costed finding(s); %d additional finding(s) had no catalog match).\n",
				est.TotalMonthlyUSDLow, est.TotalMonthlyUSDHigh, est.Currency,
				est.CostedFindings, est.UncostedFindings))
			sb.WriteString(fmt.Sprintf("_Assumptions: %d hours/month. %s_\n",
				est.AssumedHoursPerMonth, est.Disclaimer))
		}
		sb.WriteString("\n")
	}

	// Section 3: Risk Management
	sb.WriteString("## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)\n")
	sb.WriteString(fmt.Sprintf("**Current Automated Posture:** %s\n\n", bom.Compliance))

	// 3(a) Auto-generated risk register (Wave 6) — every detected dep
	// cross-referenced against the curated catalog of OWASP ML Top 10
	// categories, MITRE ATLAS techniques, and EU AI Act articles.
	// Same data lives in proof_drills.risk_register_state (JSONB) so
	// the dashboard / API can render the register without re-parsing
	// markdown. Wave 7f: caller passes in the register so live OSV
	// vuln IDs (when enrichment ran) show up in the rendered table.
	sb.WriteString("### 3(a) Cross-Referenced Risk Register (OWASP ML Top 10 / MITRE ATLAS)\n\n")
	sb.WriteString(fmt.Sprintf(
		"**Findings:** %d total — High: %d, Medium: %d, Low: %d\n\n",
		register.Summary.Total, register.Summary.High,
		register.Summary.Medium, register.Summary.Low,
	))
	if rendered := RenderRiskRegisterMarkdown(register); rendered != "" {
		sb.WriteString(rendered)
		sb.WriteString("\n")
		// Per-finding mitigation guidance — kept below the summary table
		// because the table is what auditors scan first.
		sb.WriteString("**Recommended mitigations:**\n\n")
		for _, f := range register.Findings {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", f.Component, f.Mitigation))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No catalogued AI risks detected. (Catalog scope is intentionally MVP — see pkg/compliance/vulns.json.)\n\n")
	}

	// Exposed-secret findings stay separate because they're an immediate
	// remediation requirement, not an Article 9 risk-management item.
	secretFindings := []types.AIDependency{}
	for _, dep := range bom.Dependencies {
		if dep.Name == "Exposed Secret" {
			secretFindings = append(secretFindings, dep)
		}
	}
	if len(secretFindings) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ **CRITICAL:** %d exposed secret(s) detected in source code. Immediate remediation required.\n\n", len(secretFindings)))
	}

	// 3(b): Policy compliance
	sb.WriteString("### 3(b) Policy-as-Code Compliance\n")
	if len(bom.PolicyViolations) == 0 {
		sb.WriteString("- [x] No policy violations detected")
		sb.WriteString(" (or no `.aicap.yml` policy file configured)\n\n")
	} else {
		blockers := 0
		warnings := 0
		for _, v := range bom.PolicyViolations {
			if v.Severity == "Blocker" {
				blockers++
			} else {
				warnings++
			}
		}
		sb.WriteString(fmt.Sprintf("- **Blockers:** %d\n", blockers))
		sb.WriteString(fmt.Sprintf("- **Warnings:** %d\n\n", warnings))
		for _, v := range bom.PolicyViolations {
			icon := "⚠️"
			if v.Severity == "Blocker" {
				icon = "🚫"
			}
			sb.WriteString(fmt.Sprintf("- %s [%s] %s (%s)\n", icon, v.Rule, v.Description, v.Location))
		}
		sb.WriteString("\n")
	}

	// CI/CD controls
	sb.WriteString("### 3(c) Automated CI/CD Pipeline Controls\n")
	if bom.Compliance == "Passed" {
		sb.WriteString("- [x] High-risk dependency constraints validated.\n")
	} else {
		sb.WriteString("- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.\n")
	}
	// 3(c) prompt-injection mitigation — Wave 7a auto-populates from
	// detected guardrail libraries (lakera, rebuff, nemoguardrails, …).
	// If none were found we keep the manual-input prompt; pretending we
	// have a defence we can't see is exactly the kind of false-positive
	// the original analysis warned against.
	if defs := bom.Governance.PromptInjectionDefenses; len(defs) > 0 {
		sb.WriteString(fmt.Sprintf("- [x] Prompt-injection defences detected: %s\n", joinEvidence(defs)))
		for _, s := range defs {
			sb.WriteString(fmt.Sprintf("  - %s _(source: %s, location: %s)_\n", s.Description, s.Source, s.Location))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("- [ ] `[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]`\n\n")
	}

	// Section 4: Human Oversight & Data Governance.
	// Wave 7a fills in HITL, Training Data, and Bias Monitoring from
	// scanner signals when available. Each subsection falls back to
	// the original `[REQUIRES MANUAL INPUT]` placeholder when no
	// signal was detected — auditors get evidence-or-prompt, never
	// silent omission.
	sb.WriteString("## 4. Human Oversight & Data Governance (Annex IV, Section 3)\n")
	renderGovernanceSection(&sb, "Human-in-the-loop (HITL) Controls", bom.Governance.HITL)
	renderGovernanceSection(&sb, "Training Data Provenance", bom.Governance.TrainingData)
	renderGovernanceSection(&sb, "Bias Monitoring", bom.Governance.BiasMonitoring)
	sb.WriteString("\n")

	// Section 5: Proof Drill
	sb.WriteString("## 5. Immutable Compliance Proof (AIcap Proof Drill)\n")
	sb.WriteString("This document was generated by **AIcap** — an automated AI compliance scanner.\n")
	sb.WriteString("The AI-BOM, this Annex IV template, and the commit SHA have been cryptographically\n")
	sb.WriteString("hashed together to create an immutable audit trail.\n\n")
	sb.WriteString(fmt.Sprintf("- **Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Scan Timestamp:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("- **Cryptographic proof hash available in the AIcap Cloud dashboard.**\n")

	return sb.String()
}

// renderGovernanceSection writes one Annex IV § 4 sub-bullet, either
// with detected evidence or the `[REQUIRES MANUAL INPUT]` placeholder.
// Pulled out of GenerateAnnexIVMarkdown so the three sub-sections (HITL,
// Training Data, Bias Monitoring) share identical formatting — auditors
// reading three different shapes is a needless cognitive load.
func renderGovernanceSection(sb *strings.Builder, title string, signals []types.GovernanceSignal) {
	if len(signals) == 0 {
		sb.WriteString(fmt.Sprintf("- **%s:** `[REQUIRES MANUAL INPUT]`\n", title))
		return
	}
	sb.WriteString(fmt.Sprintf("- **%s:** %d signal(s) detected — see evidence below.\n", title, len(signals)))
	for _, s := range signals {
		sb.WriteString(fmt.Sprintf("  - %s _(source: %s, location: `%s`)_\n", s.Description, s.Source, s.Location))
	}
}

// joinEvidence collapses a slice of GovernanceSignal evidence strings
// into a comma-separated list for the inline summary line at the top
// of a § 3(c) entry. Deliberately simple — no de-duping, since multiple
// detections of the same lib in different files are independently
// useful audit signals.
func joinEvidence(signals []types.GovernanceSignal) string {
	parts := make([]string, 0, len(signals))
	for _, s := range signals {
		parts = append(parts, "`"+s.Evidence+"`")
	}
	return strings.Join(parts, ", ")
}

// CycloneDX SBOM structures — minimal CycloneDX 1.5 compatible output
func LoadPolicyConfig(scanDir string) *types.PolicyConfig {
	policyPath := filepath.Join(scanDir, ".aicap.yml")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil // No policy file — that's okay
	}

	policy := &types.PolicyConfig{}

	// Simple YAML-like parser for our specific format (avoids yaml dependency)
	lines := strings.Split(string(data), "\n")
	var currentList *[]string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle list items
		if strings.HasPrefix(trimmed, "- ") && currentList != nil {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = strings.Trim(item, "\"'")
			*currentList = append(*currentList, item)
			continue
		}

		// Handle key-value pairs
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, "\"'")
			currentList = nil

			switch key {
			case "allowed_models":
				currentList = &policy.AllowedModels
			case "blocked_models":
				currentList = &policy.BlockedModels
			case "allowed_licenses":
				currentList = &policy.AllowedLicenses
			case "max_risk_level":
				policy.MaxRiskLevel = val
			case "block_on_high_risk":
				policy.BlockOnHighRisk = val == "true"
			case "require_licenses":
				policy.RequireLicenses = val == "true"
			}
		}
	}

	return policy
}

// evaluatePolicy checks detected dependencies against the policy configuration
func EvaluatePolicy(policy *types.PolicyConfig, bom types.AIBOM) []types.PolicyViolation {
	var violations []types.PolicyViolation

	for _, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		depVersionLower := strings.ToLower(dep.Version)

		// Check blocked models
		for _, blocked := range policy.BlockedModels {
			blockedLower := strings.ToLower(blocked)
			if strings.Contains(depNameLower, blockedLower) || strings.Contains(depVersionLower, blockedLower) {
				violations = append(violations, types.PolicyViolation{
					Rule:        "blocked_model",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is explicitly blocked by .aicap.yml policy", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check allowed models (if allowlist is specified, anything not in it is blocked)
		if len(policy.AllowedModels) > 0 && (dep.Name == "Hardcoded Model" || strings.HasPrefix(dep.Ecosystem, "Model Weight")) {
			isAllowed := false
			for _, allowed := range policy.AllowedModels {
				allowedLower := strings.ToLower(allowed)
				if strings.Contains(depVersionLower, allowedLower) || strings.Contains(depNameLower, allowedLower) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, types.PolicyViolation{
					Rule:        "allowed_model_violation",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is not in the approved model allowlist defined in .aicap.yml", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check risk level threshold
		if policy.BlockOnHighRisk && dep.RiskLevel == "High" {
			violations = append(violations, types.PolicyViolation{
				Rule:        "high_risk_blocked",
				Severity:    "Blocker",
				Description: fmt.Sprintf("High-risk dependency '%s' blocked by policy (block_on_high_risk: true)", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check license requirements
		if policy.RequireLicenses && dep.License == "" && dep.RiskLevel == "High" {
			violations = append(violations, types.PolicyViolation{
				Rule:        "missing_license",
				Severity:    "Warning",
				Description: fmt.Sprintf("High-risk dependency '%s' has no license information. Policy requires licenses for all high-risk components.", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check allowed licenses
		if len(policy.AllowedLicenses) > 0 && dep.License != "" {
			isAllowed := false
			for _, allowedLic := range policy.AllowedLicenses {
				if strings.EqualFold(dep.License, allowedLic) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, types.PolicyViolation{
					Rule:        "license_not_allowed",
					Severity:    "Warning",
					Description: fmt.Sprintf("License '%s' for '%s' is not in the approved license list", dep.License, dep.Name),
					Location:    dep.Location,
				})
			}
		}
	}

	return violations
}

// parseRequirementsTxt parses Python dependencies
func GenerateCycloneDXBOM(bom types.AIBOM) types.CycloneDXBOM {
	components := []types.CycloneDXComponent{}

	for _, dep := range bom.Dependencies {
		comp := types.CycloneDXComponent{
			Type:    ClassifyComponentType(dep),
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    GeneratePURL(dep),
			Properties: []types.CycloneDXProperty{
				{Name: "aicap:riskLevel", Value: dep.RiskLevel},
				{Name: "aicap:ecosystem", Value: dep.Ecosystem},
				{Name: "aicap:description", Value: dep.Description},
			},
		}

		if dep.Location != "" {
			comp.Properties = append(comp.Properties, types.CycloneDXProperty{
				Name: "aicap:location", Value: dep.Location,
			})
		}

		if dep.License != "" {
			lic := types.CycloneDXLicense{}
			lic.License.Name = dep.License
			comp.Licenses = []types.CycloneDXLicense{lic}
		}

		components = append(components, comp)
	}

	return types.CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + fmt.Sprintf("%x", sha256.Sum256([]byte(bom.ProjectName+bom.CommitSha)))[:36],
		Version:      1,
		Metadata: types.CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: types.CycloneDXComponent{
				Type:    "application",
				Name:    bom.ProjectName,
				Version: bom.CommitSha,
			},
		},
		Components: components,
	}
}

// ClassifyComponentType maps AIcap dependency types to CycloneDX component types
func ClassifyComponentType(dep types.AIDependency) string {
	if strings.HasPrefix(dep.Ecosystem, "Model Weight") || strings.HasPrefix(dep.Ecosystem, "Container Image") {
		return "machine-learning-model"
	}
	if dep.Name == "Exposed Secret" {
		return "data"
	}
	return "library"
}

// GeneratePURL creates a Package URL for the dependency
func GeneratePURL(dep types.AIDependency) string {
	switch {
	case strings.Contains(dep.Ecosystem, "pip") || strings.Contains(dep.Ecosystem, "Poetry"):
		return fmt.Sprintf("pkg:pypi/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "npm"):
		return fmt.Sprintf("pkg:npm/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Go"):
		return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Dockerfile"):
		return fmt.Sprintf("pkg:docker/%s", dep.Name)
	default:
		return ""
	}
}

// parseTerraformFile analyzes .tf files for GPU instance types and cost optimization opportunities
var owaspMLRisks = map[string][]string{
	"openai":       {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"anthropic":    {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"langchain":    {"ML01:2023 Input Manipulation - LLM orchestration framework susceptible to prompt injection", "ML06:2023 AI Supply Chain Attacks - Third-party orchestration framework creates supply chain risk"},
	"torch":        {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"tensorflow":   {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"transformers": {"ML06:2023 AI Supply Chain Attacks - Pre-trained model supply chain risk", "ML02:2023 Data Poisoning - Pre-trained models may contain poisoned weights"},
	"scikit-learn": {"ML08:2023 Model Skewing - Ensure training data distributions are monitored"},
	"ollama":       {"ML04:2023 Model Theft - Local model hosting increases model exfiltration surface"},
	"chromadb":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
	"pinecone":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
}

// enrichWithOWASPRisks adds OWASP ML Top 10 risk annotations to the types.AIBOM
func EnrichWithOWASPRisks(bom *types.AIBOM) {
	for i, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		if risks, ok := owaspMLRisks[depNameLower]; ok {
			// Append OWASP risks to the description
			owaspNote := " | OWASP ML: " + strings.Join(risks, "; ")
			// Only add if not already annotated
			if !strings.Contains(bom.Dependencies[i].Description, "OWASP") {
				bom.Dependencies[i].Description += owaspNote
			}
		}
	}
}

