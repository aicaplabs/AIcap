package compliance

import (
	"strings"
	"testing"

	"aicap/pkg/types"
)

func a50bom(names ...string) types.AIBOM {
	deps := make([]types.AIDependency, 0, len(names))
	for _, n := range names {
		deps = append(deps, types.AIDependency{Name: n, Version: "1.0.0", Ecosystem: "Python (pip)"})
	}
	return types.AIBOM{Dependencies: deps}
}

func obligationByArticle(obs []types.TransparencyObligation, article string) *types.TransparencyObligation {
	for i := range obs {
		if strings.Contains(obs[i].Article, article) {
			return &obs[i]
		}
	}
	return nil
}

func TestDetectTransparency_ChatbotDisclosure(t *testing.T) {
	obs := DetectTransparencyObligations(a50bom("openai"))

	o := obligationByArticle(obs, "50(1)")
	if o == nil {
		t.Fatalf("no Article 50(1) duty for an LLM integration: %+v", obs)
	}
	if len(o.TriggeredBy) != 1 || !strings.Contains(o.TriggeredBy[0], "openai") {
		t.Errorf("triggeredBy = %v", o.TriggeredBy)
	}
	// 50(1) is discharged by interface copy, which no scan can see. The
	// flag must say so, or an empty EvidenceFound would read as a gap.
	if o.EvidenceIsDetectable {
		t.Error("50(1) marked as having detectable evidence — it is discharged by UI copy")
	}
}

func TestDetectTransparency_GroupsRatherThanRepeats(t *testing.T) {
	// Eight LLM libraries are one duty, not eight. Repeating it would
	// bury the sentence the reader has to act on.
	obs := DetectTransparencyObligations(a50bom(
		"openai", "anthropic", "cohere", "litellm", "langchain", "langgraph", "llama-index", "crewai",
	))

	count := 0
	for _, o := range obs {
		if strings.Contains(o.Article, "50(1)") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Article 50(1) reported %d times, want once", count)
	}
	o := obligationByArticle(obs, "50(1)")
	if len(o.TriggeredBy) < 5 {
		t.Errorf("the grouped duty should still name what triggered it, got %v", o.TriggeredBy)
	}
}

func TestDetectTransparency_SyntheticMarkingGapAndEvidence(t *testing.T) {
	// Without a marking library the status reports the gap...
	gap := obligationByArticle(DetectTransparencyObligations(a50bom("diffusers")), "50(2)")
	if gap == nil {
		t.Fatal("no Article 50(2) duty for an image-generation library")
	}
	if !gap.EvidenceIsDetectable {
		t.Error("50(2) evidence should be detectable — watermarking leaves a dependency trace")
	}
	if len(gap.EvidenceFound) != 0 {
		t.Errorf("evidence reported with no marking library present: %v", gap.EvidenceFound)
	}
	if !strings.Contains(gap.Status, "no technical marking") {
		t.Errorf("status = %q, want the gap stated plainly", gap.Status)
	}

	// ...and with one, it reports what it found.
	found := obligationByArticle(DetectTransparencyObligations(a50bom("diffusers", "invisible-watermark")), "50(2)")
	if len(found.EvidenceFound) != 1 || found.EvidenceFound[0] != "invisible-watermark" {
		t.Fatalf("evidenceFound = %v, want the watermarking library", found.EvidenceFound)
	}
	// Even with evidence, the status must not read as compliant — the
	// scan cannot tell whether marking covers every output path.
	if !strings.Contains(found.Status, "verify") {
		t.Errorf("status = %q, want it to still require verification", found.Status)
	}
	if strings.Contains(strings.ToLower(found.Status), "compliant") {
		t.Errorf("status asserts compliance: %q", found.Status)
	}
}

func TestDetectTransparency_EmotionSystemsKeepA50_3DutyEvenWhenNotProhibited(t *testing.T) {
	// The relationship between the two articles worth getting right: an
	// emotion recognition system outside a workplace or school is NOT
	// prohibited by Article 5, but the people exposed to it must still
	// be informed under 50(3). That duty is the floor that remains.
	bom := a50bom("fer")
	obs := DetectTransparencyObligations(bom)

	o := obligationByArticle(obs, "50(3)")
	if o == nil {
		t.Fatalf("no Article 50(3) duty for an emotion-recognition library: %+v", obs)
	}
	if !strings.Contains(o.AppliesWhen, "Article 5 does NOT prohibit") {
		t.Error("50(3) text should explain that it survives a clean Article 5 analysis")
	}
	// And Article 5 should also have something to say about it.
	if len(DetectProhibitedPractices(bom)) == 0 {
		t.Error("fer should raise an Article 5 indicator as well as the 50(3) duty")
	}
}

func TestDetectTransparency_DeepfakeDuty(t *testing.T) {
	o := obligationByArticle(DetectTransparencyObligations(a50bom("wav2lip")), "50(4)")
	if o == nil {
		t.Fatal("no Article 50(4) duty for a lip-sync generation library")
	}
	if !strings.Contains(o.Requirement, "deep fake") {
		t.Errorf("requirement text does not describe the deep-fake duty: %q", o.Requirement)
	}
	// The artistic/satirical carve-out must survive into the text, or the
	// duty reads as stricter than it is.
	if !strings.Contains(o.Requirement, "artistic") {
		t.Error("requirement omits the artistic/creative/satirical limitation")
	}
}

func TestDetectTransparency_QuietOnNonAIProject(t *testing.T) {
	if obs := DetectTransparencyObligations(a50bom("scikit-learn", "xgboost", "pandas")); len(obs) != 0 {
		t.Errorf("classical-ML stack attracted transparency duties: %+v", obs)
	}
}

func TestDetectTransparency_IsDeterministic(t *testing.T) {
	bom := a50bom("openai", "diffusers", "fer", "wav2lip", "invisible-watermark")
	first := DetectTransparencyObligations(bom)
	for i := 0; i < 10; i++ {
		got := DetectTransparencyObligations(bom)
		if len(got) != len(first) {
			t.Fatal("obligation count varied between runs")
		}
		for j := range got {
			if got[j].ID != first[j].ID || strings.Join(got[j].TriggeredBy, ",") != strings.Join(first[j].TriggeredBy, ",") {
				t.Fatal("obligation ordering or triggers varied between runs")
			}
		}
	}
}

func TestDetectTransparency_PlaceholderVersionsNotShown(t *testing.T) {
	// "openai imported" in a duty label is noise; the name alone is right.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "openai", Version: "imported", Ecosystem: "Source Code (.py import)"},
	}}
	o := obligationByArticle(DetectTransparencyObligations(bom), "50(1)")
	if o == nil {
		t.Fatal("no duty raised for an imported LLM library")
	}
	if strings.Contains(o.TriggeredBy[0], "imported") {
		t.Errorf("placeholder version leaked into the label: %q", o.TriggeredBy[0])
	}
}

func TestRenderArticle50Markdown_StatesTheDateAndTheLimits(t *testing.T) {
	md := RenderArticle50Markdown(DetectTransparencyObligations(a50bom("openai", "diffusers")))

	if !strings.Contains(md, "2 August 2026") {
		t.Error("the applicability date must appear — it is the same deadline as the high-risk regime")
	}
	if !strings.Contains(md, "not a clearance") {
		t.Error("the section must say that absence of a duty is not a clearance")
	}
	// Article 50 forbids nothing; the framing must not imply otherwise.
	for _, forbidden := range []string{"prohibited", "you are in breach", "violation"} {
		if strings.Contains(strings.ToLower(md), forbidden) {
			t.Errorf("section uses prohibition language (%q) for a disclosure duty", forbidden)
		}
	}
	if !strings.Contains(md, "machine-readable") {
		t.Error("50(2) is a machine-readable marking duty; a visible label alone does not satisfy it")
	}
}

func TestRenderArticle50Markdown_EmptyWhenNoDuties(t *testing.T) {
	if got := RenderArticle50Markdown(nil); got != "" {
		t.Errorf("got %q, want empty so the caller omits the section", got)
	}
}

func TestArticle50Catalog_AllTriggersAreDetectable(t *testing.T) {
	// A trigger the scanner cannot detect can never fire. This catches a
	// catalog entry added without the matching libraries.json entry.
	var dead []string
	for _, ob := range article50Catalog {
		for _, trig := range append(append([]string{}, ob.Triggers...), ob.DischargeEvidence...) {
			if len(DetectTransparencyObligations(a50bom(trig))) == 0 &&
				len(ob.DischargeEvidence) == 0 {
				dead = append(dead, trig)
			}
		}
	}
	if len(dead) > 0 {
		t.Errorf("triggers that produce no duty: %v", dead)
	}
}

func TestAnnexIV_IncludesArticle50Section(t *testing.T) {
	bom := types.AIBOM{ProjectName: "chatbot", Dependencies: []types.AIDependency{
		{Name: "openai", Version: "1.40.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
	}}
	bom.TransparencyObligations = DetectTransparencyObligations(bom)

	md := GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
	if !strings.Contains(md, "Article 50 — Transparency Obligations") {
		t.Error("Annex IV omits the Article 50 section despite an applicable duty")
	}
}
