package compliance

import (
	"strings"
	"testing"

	"aicap/pkg/types"
)

// TestComputeRiskRegister_MatchesCatalog: a BOM that includes a known
// catalog entry produces a finding with the expected OWASP / MITRE /
// Article fields. Sanity-check the curated catalog plumbing.
func TestComputeRiskRegister_MatchesCatalog(t *testing.T) {
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	}
	reg := ComputeRiskRegister(bom)

	if got := reg.Summary.Total; got != 1 {
		t.Fatalf("Summary.Total = %d, want 1", got)
	}
	if got := reg.Summary.High; got != 1 {
		t.Errorf("Summary.High = %d, want 1", got)
	}
	if len(reg.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(reg.Findings))
	}
	f := reg.Findings[0]
	if f.Component != "tensorflow" {
		t.Errorf("Component = %q, want tensorflow", f.Component)
	}
	if !strings.Contains(f.OwaspCategory, "ML06") {
		t.Errorf("OwaspCategory = %q, want ML06 supply-chain", f.OwaspCategory)
	}
	if !sliceContains(f.EUAIActArticles, "Article 9") {
		t.Errorf("EUAIActArticles = %v, want to include Article 9", f.EUAIActArticles)
	}
	if f.Status != "open" {
		t.Errorf("Status = %q, want open (default)", f.Status)
	}
	if f.Mitigation == "" {
		t.Error("Mitigation is empty — catalog entry incomplete")
	}
}

// TestComputeRiskRegister_CaseInsensitive: the curated catalog uses
// lowercase keys ("tensorflow"). Detected deps may have any case
// ("TensorFlow", "TENSORFLOW"). Match should still fire.
func TestComputeRiskRegister_CaseInsensitive(t *testing.T) {
	cases := []string{"TensorFlow", "TENSORFLOW", "tensorflow"}
	for _, name := range cases {
		bom := types.AIBOM{Dependencies: []types.AIDependency{{Name: name, Version: "2.15.0"}}}
		if got := ComputeRiskRegister(bom).Summary.Total; got != 1 {
			t.Errorf("name=%q: Total = %d, want 1 (case-insensitive match)", name, got)
		}
	}
}

// TestComputeRiskRegister_NoMatchSkipped: deps not in the catalog are
// silently ignored. Wave 7+ feed integration may upgrade this to log
// "no entry for X", but the MVP stays quiet.
func TestComputeRiskRegister_NoMatchSkipped(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "obscure-toolkit-with-no-cve", Version: "0.1.0"},
	}}
	reg := ComputeRiskRegister(bom)
	if reg.Summary.Total != 0 || len(reg.Findings) != 0 {
		t.Errorf("expected 0 findings for unknown dep, got Total=%d, Findings=%d",
			reg.Summary.Total, len(reg.Findings))
	}
}

// TestComputeRiskRegister_MixedSeverities: realistic BOM with multiple
// catalogued libraries should produce per-severity counts.
func TestComputeRiskRegister_MixedSeverities(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow"}, // High in catalog
		{Name: "openai"},     // Medium
		{Name: "anthropic"},  // Medium
	}}
	reg := ComputeRiskRegister(bom)
	if reg.Summary.High != 1 || reg.Summary.Medium != 2 || reg.Summary.Total != 3 {
		t.Errorf("got High=%d Medium=%d Total=%d; want 1/2/3",
			reg.Summary.High, reg.Summary.Medium, reg.Summary.Total)
	}
}

// TestRenderRiskRegisterMarkdown_EmptyRegister: zero-finding registers
// must return an empty string so the Annex IV builder can decide what
// placeholder to write.
func TestRenderRiskRegisterMarkdown_EmptyRegister(t *testing.T) {
	if got := RenderRiskRegisterMarkdown(types.RiskRegister{}); got != "" {
		t.Errorf("empty register rendered = %q, want empty string", got)
	}
}

// TestRenderRiskRegisterMarkdown_TableShape: with findings we get the
// expected table headers + one row per finding.
func TestRenderRiskRegisterMarkdown_TableShape(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "langchain", Version: "0.1.0"},
	}}
	md := RenderRiskRegisterMarkdown(ComputeRiskRegister(bom))
	for _, want := range []string{
		"| Component |", "| Severity |", "OWASP", "MITRE", "AI Act",
		"`langchain`", "v0.1.0", "open",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("RenderRiskRegisterMarkdown missing %q\nfull output:\n%s", want, md)
		}
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
