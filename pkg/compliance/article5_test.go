package compliance

import (
	"strings"
	"testing"

	"aicap/pkg/types"
)

// Article 5 is the one area where being wrong in the *accusatory*
// direction is worse than silence: telling a customer they are
// committing a prohibited practice when they are not costs them time
// with counsel and costs the tool its credibility. These tests pin the
// wording as much as the detection.

func a5bom(deps ...types.AIDependency) types.AIBOM {
	return types.AIBOM{Dependencies: deps}
}

func TestDetectProhibitedPractices_EmotionRecognition(t *testing.T) {
	signals := DetectProhibitedPractices(a5bom(
		types.AIDependency{Name: "fer", Version: "22.5.1", Ecosystem: "Python (pip)"},
	))

	if len(signals) != 1 {
		t.Fatalf("signals = %d, want 1: %+v", len(signals), signals)
	}
	s := signals[0]
	if !strings.Contains(s.Article, "5(1)(f)") {
		t.Errorf("article = %q, want the emotion-inference paragraph", s.Article)
	}
	if s.Status != "requires human assessment" {
		t.Errorf("status = %q — a scan must not return a verdict", s.Status)
	}
	// The prohibition text must carry the carve-out, or a reader will
	// conclude the practice is banned outright.
	if !strings.Contains(s.Prohibition, "workplace") || !strings.Contains(s.Prohibition, "medical or safety") {
		t.Errorf("prohibition text omits scope or exception: %q", s.Prohibition)
	}
	if s.Question == "" {
		t.Error("no question attached — the signal is unusable without the thing only a human can answer")
	}
}

func TestDetectProhibitedPractices_MultipleArticlesPerComponent(t *testing.T) {
	// deepface does emotion inference AND face recognition. Reporting
	// only one would silently drop a legal question.
	signals := DetectProhibitedPractices(a5bom(
		types.AIDependency{Name: "deepface", Version: "0.0.93", Ecosystem: "Python (pip)"},
	))

	if len(signals) < 2 {
		t.Fatalf("signals = %d, want at least 2 (emotion + biometric ID): %+v", len(signals), signals)
	}
	articles := map[string]bool{}
	for _, s := range signals {
		articles[s.Article] = true
	}
	var sawEmotion, sawBiometric bool
	for a := range articles {
		if strings.Contains(a, "5(1)(f)") {
			sawEmotion = true
		}
		if strings.Contains(a, "5(1)(e)") || strings.Contains(a, "5(1)(h)") {
			sawBiometric = true
		}
	}
	if !sawEmotion || !sawBiometric {
		t.Errorf("deepface must raise both capabilities, got articles %v", articles)
	}
}

func TestDetectProhibitedPractices_DeduplicatesAcrossManifests(t *testing.T) {
	// The same library found in a manifest and a lockfile is one legal
	// question, not two.
	signals := DetectProhibitedPractices(a5bom(
		types.AIDependency{Name: "fer", Version: "22.5.1", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "fer", Version: "22.5.1", Ecosystem: "Python (Poetry lock)"},
	))
	if len(signals) != 1 {
		t.Errorf("signals = %d, want 1 per distinct question", len(signals))
	}
}

func TestDetectProhibitedPractices_QuietOnOrdinaryAIStack(t *testing.T) {
	// A normal LLM application must produce no Article 5 noise at all.
	// A false accusation here is expensive.
	signals := DetectProhibitedPractices(a5bom(
		types.AIDependency{Name: "openai", Version: "1.40.0", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "langchain", Version: "0.2.0", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "transformers", Version: "4.44.0", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "chromadb", Version: "0.5.0", Ecosystem: "Python (pip)"},
	))
	if len(signals) != 0 {
		t.Errorf("ordinary LLM stack raised Article 5 signals: %+v", signals)
	}
}

func TestDetectProhibitedPractices_IsDeterministic(t *testing.T) {
	bom := a5bom(
		types.AIDependency{Name: "insightface", Version: "0.7", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "deepface", Version: "0.0.93", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "fer", Version: "22.5.1", Ecosystem: "Python (pip)"},
	)
	first := DetectProhibitedPractices(bom)
	for i := 0; i < 10; i++ {
		got := DetectProhibitedPractices(bom)
		for j := range got {
			if got[j].Component != first[j].Component || got[j].Article != first[j].Article {
				t.Fatal("signal order varied between runs")
			}
		}
	}
}

func TestRenderArticle5Markdown_NeverAssertsBreach(t *testing.T) {
	md := RenderArticle5Markdown(DetectProhibitedPractices(a5bom(
		types.AIDependency{Name: "fer", Version: "22.5.1", Ecosystem: "Python (pip)"},
	)))

	if !strings.Contains(md, "not a finding that you are committing a prohibited practice") {
		t.Error("the section must disclaim that it is a determination of breach")
	}
	if !strings.Contains(md, "2 February 2025") {
		t.Error("the applicability date is the reason this matters now; it must appear")
	}
	if !strings.Contains(md, "35 000 000") || !strings.Contains(md, "7%") {
		t.Error("the penalty exposure is why a reader should act; it must appear")
	}
	// Absence of signals for the undetectable prohibitions must be
	// stated, or the section reads as a full Article 5 clearance.
	if !strings.Contains(md, "not a clearance") {
		t.Error("the section must say that absence of signals is not a clearance")
	}
	for _, forbidden := range []string{"you are in breach", "violation detected", "illegal"} {
		if strings.Contains(strings.ToLower(md), forbidden) {
			t.Errorf("section asserts breach with the phrase %q", forbidden)
		}
	}
}

func TestRenderArticle5Markdown_EmptyWhenNothingDetected(t *testing.T) {
	// Printing "no prohibited practices detected" would read as a
	// clearance the scan cannot give — several Article 5 prohibitions
	// (social scoring, predictive policing, manipulative design) leave
	// no trace in a dependency manifest at all.
	if got := RenderArticle5Markdown(nil); got != "" {
		t.Errorf("got %q, want empty so the caller omits the section", got)
	}
}

func TestPerformScan_Article5Catalog_AllComponentsResolve(t *testing.T) {
	// Every component named in article5.json should be detectable by the
	// scanner, or the indicator can never fire. This catches a catalog
	// entry added without a matching libraries.json entry.
	var missing []string
	for name := range article5ByComponent {
		signals := DetectProhibitedPractices(a5bom(
			types.AIDependency{Name: name, Version: "1.0", Ecosystem: "Python (pip)"},
		))
		if len(signals) == 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("indicator components that produce no signal: %v", missing)
	}
}

func TestAnnexIV_IncludesArticle5SectionWhenDetected(t *testing.T) {
	bom := types.AIBOM{
		ProjectName: "hiring-screen",
		Dependencies: []types.AIDependency{
			{Name: "fer", Version: "22.5.1", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	}
	bom.ProhibitedPractices = DetectProhibitedPractices(bom)

	md := GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
	if !strings.Contains(md, "Article 5 — Prohibited Practices Review Required") {
		t.Error("Annex IV omits the Article 5 section despite a detected signal")
	}
}

func TestAnnexIV_NoArticle5SectionWhenNothingDetected(t *testing.T) {
	bom := types.AIBOM{ProjectName: "plain", Dependencies: []types.AIDependency{
		{Name: "openai", Version: "1.40.0", Ecosystem: "Python (pip)"},
	}}
	bom.ProhibitedPractices = DetectProhibitedPractices(bom)

	md := GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
	if strings.Contains(md, "Article 5") {
		t.Error("Annex IV mentions Article 5 with nothing detected — reads as a clearance")
	}
}
