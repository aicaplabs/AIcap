// Risk-register computation (Wave 6 Phase B).
//
// EU AI Act Article 9 requires every high-risk AI system to maintain a
// continuous risk register. AIcap previously left `proof_drills.risk_register_state`
// empty — the column was added in migration 00002 but no code wrote to it.
// This file closes that gap by cross-referencing every detected
// AIDependency against a curated catalog (vulns.json) and emitting a
// RiskRegister blob that gets persisted on every save-proof and
// rendered into Annex IV § 5.
//
// Catalog scope is intentionally MVP: a static JSON file shipped with
// the binary covering the most common AI libraries (tensorflow, torch,
// transformers, langchain, openai, anthropic, huggingface_hub,
// scikit-learn, diffusers). When a wave 7+ ingests live CVE / GHSA /
// MITRE ATLAS feeds, this same ComputeRiskRegister contract still
// holds — we just swap the source of `catalog`.

package compliance

import (
	_ "embed"
	"encoding/json"
	"strings"
	"time"

	"aicap/pkg/types"
)

//go:embed vulns.json
var vulnsJSON []byte

// catalogEntry mirrors the JSON shape in vulns.json. Kept private so
// callers always go through ComputeRiskRegister, which produces the
// public types.RiskFinding shape.
type catalogEntry struct {
	OwaspCategory   string   `json:"owasp_category"`
	MitreAtlas      []string `json:"mitre_atlas"`
	EUAIActArticles []string `json:"eu_ai_act_articles"`
	Severity        string   `json:"severity"`
	Mitigation      string   `json:"mitigation"`
	Rationale       string   `json:"rationale"`
}

// catalog is loaded once at process start. Keys are lower-cased so
// matching is case-insensitive (Hugging Face's "Transformers" matches
// the catalog's "transformers" entry, etc.). The "_meta" key is
// stripped during load — it documents the schema, not a vuln.
var catalog = func() map[string]catalogEntry {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(vulnsJSON, &raw); err != nil {
		// Fail-soft: an empty catalog means ComputeRiskRegister
		// returns "no findings" rather than panicking the server at
		// boot. The compliance build itself catches malformed JSON
		// (a Go test compile-checks the file).
		return map[string]catalogEntry{}
	}
	out := map[string]catalogEntry{}
	for k, v := range raw {
		if strings.HasPrefix(k, "_") {
			continue
		}
		var e catalogEntry
		if err := json.Unmarshal(v, &e); err != nil {
			continue
		}
		out[strings.ToLower(k)] = e
	}
	return out
}()

// ComputeRiskRegister walks the BOM and emits a RiskRegister covering
// every dependency that matches a curated entry. Pure function — no
// I/O, no DB. Callers (api.saveProof) JSON-encode the result and store
// it in proof_drills.risk_register_state.
//
// Matching strategy: lower-case dep.Name and look up the catalog. We
// don't currently match by purl, ecosystem, or version range — those
// belong in the live-feed wave. The Wave 6 contract is "the static
// catalog covers the obvious risks", which is enough to populate
// Annex IV § 5 with non-trivial content for any project that imports
// pytorch, tensorflow, transformers, langchain, etc.
func ComputeRiskRegister(bom types.AIBOM) types.RiskRegister {
	register := types.RiskRegister{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:    []types.RiskFinding{},
	}

	// One finding per (component, version). The same package is routinely
	// detected several times — a manifest and a lockfile, an import and a
	// pinned requirement — and emitting a row per detection produced a
	// register listing `openai v1.12.0` twice with identical content.
	//
	// Worse than the noise: OSV enrichment attaches advisories by
	// component, so of two duplicate rows only one received them. A
	// reader saw the same component and version listed twice, once with
	// ten CVEs and once with none, and had no way to tell which to
	// believe. Deduplicating here is what makes the enrichment
	// unambiguous.
	//
	// Distinct versions stay distinct: scikit-learn 0.24.2 and 1.4.0 in
	// different manifests are genuinely two things to assess.
	seen := map[string]bool{}

	// A placeholder version ("imported", "docker-install") means the
	// scanner saw the dependency but could not determine which version.
	// Such a row cannot be checked against OSV, so it renders with an
	// empty advisory column — and sitting beside a concrete-version row
	// for the same component that lists ten CVEs, it re-creates exactly
	// the ambiguity the deduplication above removes. When any concrete
	// version of a component is known, the placeholder adds nothing an
	// assessor can act on and is dropped.
	hasConcreteVersion := map[string]bool{}
	for _, dep := range bom.Dependencies {
		if isQueryableVersion(dep.Version) {
			hasConcreteVersion[strings.ToLower(dep.Name)] = true
		}
	}

	for _, dep := range bom.Dependencies {
		if !isQueryableVersion(dep.Version) && hasConcreteVersion[strings.ToLower(dep.Name)] {
			continue
		}
		entry, ok := catalog[strings.ToLower(dep.Name)]
		if !ok {
			continue
		}
		key := strings.ToLower(dep.Name) + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		// Catalog severity wins over the static dep.RiskLevel because
		// the catalog reflects the latest assessed compliance risk,
		// while dep.RiskLevel is a coarse heuristic from the scanner.
		// If the catalog entry has no severity (defensive), fall back
		// to the dep's RiskLevel.
		severity := entry.Severity
		if severity == "" {
			severity = dep.RiskLevel
		}
		register.Findings = append(register.Findings, types.RiskFinding{
			Component:       dep.Name,
			Version:         dep.Version,
			Ecosystem:       dep.Ecosystem,
			Severity:        severity,
			OwaspCategory:   entry.OwaspCategory,
			MitreAtlas:      entry.MitreAtlas,
			EUAIActArticles: entry.EUAIActArticles,
			Mitigation:      entry.Mitigation,
			Rationale:       entry.Rationale,
			Status:          "open",
			Source:          "catalog",
		})
		switch severity {
		case "High":
			register.Summary.High++
		case "Medium":
			register.Summary.Medium++
		case "Low":
			register.Summary.Low++
		}
		register.Summary.Total++
	}
	return register
}

// RenderRiskRegisterMarkdown emits a Markdown table for Annex IV § 5.
// Returned string is empty if there are no findings — the Annex IV
// builder writes a "no findings" line in that case so auditors can
// distinguish "scanner ran but caught nothing" from "scanner never ran".
//
// Wave 7f: each row's last column now lists live OSV-sourced
// CVE / GHSA IDs when present, so auditors see both the static
// catalog mapping and the live vulnerability surface in one table.
//
// Wave 16: a Source column distinguishes a curated catalog assessment
// from one raised by a live advisory alone — those are different kinds
// of claim and a reader is entitled to tell them apart.
func RenderRiskRegisterMarkdown(reg types.RiskRegister) string {
	if len(reg.Findings) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("| Component | Severity | OWASP ML Top 10 | MITRE ATLAS | AI Act | Status | Source | Live CVE/GHSA |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, f := range reg.Findings {
		atlas := strings.Join(f.MitreAtlas, ", ")
		if atlas == "" {
			atlas = "—"
		}
		articles := strings.Join(f.EUAIActArticles, ", ")
		liveIDs := "—"
		if len(f.LiveVulnIDs) > 0 {
			liveIDs = "`" + strings.Join(f.LiveVulnIDs, "`, `") + "`"
		}
		source := f.Source
		switch source {
		case "osv":
			source = "live advisory"
		case "", "catalog":
			source = "catalog"
		}
		sb.WriteString("| `")
		sb.WriteString(f.Component)
		sb.WriteString("`")
		if f.Version != "" {
			sb.WriteString(" ")
			sb.WriteString(DisplayVersion(f.Version))
		}
		sb.WriteString(" | ")
		sb.WriteString(f.Severity)
		sb.WriteString(" | ")
		sb.WriteString(f.OwaspCategory)
		sb.WriteString(" | ")
		sb.WriteString(atlas)
		sb.WriteString(" | ")
		sb.WriteString(articles)
		sb.WriteString(" | ")
		sb.WriteString(f.Status)
		sb.WriteString(" | ")
		sb.WriteString(source)
		sb.WriteString(" | ")
		sb.WriteString(liveIDs)
		sb.WriteString(" |\n")
	}
	return sb.String()
}

// RenderLiveAdvisoriesMarkdown emits the per-advisory detail block that
// sits under the register table: what each advisory is, how the
// publishing database rated it, and which version fixes it.
//
// This exists because the table answers "is there a problem?" and the
// person who has to act needs "what do I change?". The fixed version is
// the single most actionable field OSV returns, and until Wave 16 it was
// parsed and thrown away.
//
// Returns "" when no finding carries live advisory detail, so the caller
// can omit the section entirely rather than print an empty heading.
func RenderLiveAdvisoriesMarkdown(reg types.RiskRegister) string {
	var sb strings.Builder
	for _, f := range reg.Findings {
		if len(f.LiveVulns) == 0 {
			continue
		}
		sb.WriteString("- **`")
		sb.WriteString(f.Component)
		if f.Version != "" {
			sb.WriteString("` ")
			sb.WriteString(DisplayVersion(f.Version))
		} else {
			sb.WriteString("`")
		}
		sb.WriteString("**\n")
		for _, v := range f.LiveVulns {
			sb.WriteString("  - `")
			sb.WriteString(v.ID)
			sb.WriteString("`")
			if v.Severity != "" {
				sb.WriteString(" — ")
				sb.WriteString(v.Severity)
			}
			if v.Summary != "" {
				sb.WriteString(" — ")
				sb.WriteString(v.Summary)
			}
			if v.FixedVersion != "" {
				sb.WriteString(" — **fixed in ")
				sb.WriteString(v.FixedVersion)
				sb.WriteString("**")
			} else {
				// Stated explicitly: an advisory with no published fix
				// is a different remediation decision, not missing data.
				sb.WriteString(" — no fixed version published")
			}
			sb.WriteString("\n")
			if v.CVSSVector != "" {
				sb.WriteString("    - CVSS vector (as published): `")
				sb.WriteString(v.CVSSVector)
				sb.WriteString("`\n")
			}
		}
	}
	return sb.String()
}
