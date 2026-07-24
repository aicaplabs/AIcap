// EU AI Act Article 5 — prohibited-practice indicators (Wave 20).
//
// Everything else in this package serves Article 11 / Annex IV: the
// technical documentation a provider of a *high-risk* system must hold.
// Article 5 is a different obligation and a heavier one. It has applied
// since 2 February 2025 — a year and a half before the high-risk rules
// this product is otherwise built around — and it carries the Act's
// largest penalties (Article 99(3): up to EUR 35 000 000 or 7% of
// worldwide annual turnover). A scanner that inventories AI components
// while saying nothing about the chapter already in force, and most
// expensive to breach, has a conspicuous hole in it.
//
// The central design constraint: **a static scan cannot determine that a
// practice is prohibited.** Article 5 turns almost entirely on purpose,
// context, and deployment setting. Emotion inference is prohibited in
// workplaces and education institutions and unremarkable in a consented
// research study. Facial recognition is prohibited when the database was
// built by untargeted scraping, or when matching runs live in a public
// space for law enforcement — and perfectly lawful when you unlock your
// own phone. The code looks identical in every one of those cases.
//
// So this file emits *indicators with the question attached*, never
// verdicts. A finding says: this codebase links a capability that falls
// within the scope of Article 5(1)(f); here is what that paragraph
// actually prohibits; here is the question only you can answer. Getting
// this wrong in the other direction — telling a customer they are
// committing a prohibited practice when they are not — would be a worse
// failure than silence, because it would train them to dismiss the tool.

package compliance

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"aicap/pkg/types"
)

//go:embed article5.json
var article5JSON []byte

// article5Indicator mirrors one entry in article5.json.
type article5Indicator struct {
	Components  []string `json:"components"`
	Practice    string   `json:"practice"`
	Article     string   `json:"article"`
	Prohibition string   `json:"prohibition"`
	AppliesWhen string   `json:"applies_when"`
	Question    string   `json:"question"`
}

// article5ByComponent maps a lower-cased component name to every
// indicator that names it.
//
// A slice, not a single value: some components genuinely implement more
// than one in-scope capability. deepface performs both emotion inference
// (5(1)(f)) and face recognition (5(1)(e)/(h)), and collapsing those to
// whichever entry the catalog happened to define last would silently
// drop a legal question the reader needs to answer.
//
// Built once at process start. A malformed catalog yields an empty map
// and therefore no findings — the same fail-soft posture the risk
// catalog uses, since a parse error must not take the server down.
var article5ByComponent = func() map[string][]article5Indicator {
	var doc struct {
		Indicators []article5Indicator `json:"indicators"`
	}
	if err := json.Unmarshal(article5JSON, &doc); err != nil {
		return map[string][]article5Indicator{}
	}
	out := map[string][]article5Indicator{}
	for _, ind := range doc.Indicators {
		for _, c := range ind.Components {
			key := strings.ToLower(c)
			out[key] = append(out[key], ind)
		}
	}
	return out
}()

// DetectProhibitedPractices cross-references the BOM against the Article 5
// indicator catalog.
//
// Pure function — no I/O. Returns nil when nothing matches, so callers
// can omit the whole section rather than printing a reassuring "none
// found" that a reader might mistake for a compliance assessment.
//
// Matching is by component name only. Deliberately narrow: these
// indicators lead to a conversation with counsel, and a false positive
// costs a customer real time and credibility with their own legal team.
// Broader heuristics (scanning for face-mesh call sites, or inferring
// intent from variable names) were considered and rejected — they would
// raise the false-positive rate on exactly the findings where being
// wrong is most expensive.
func DetectProhibitedPractices(bom types.AIBOM) []types.ProhibitedPracticeSignal {
	seen := map[string]bool{}
	var out []types.ProhibitedPracticeSignal

	for _, dep := range bom.Dependencies {
		indicators, ok := article5ByComponent[strings.ToLower(dep.Name)]
		if !ok {
			continue
		}
		for _, ind := range indicators {
			// One signal per (component, article), even when a component
			// appears in several manifests — the legal question is asked
			// once per distinct question, not once per detection site.
			key := strings.ToLower(dep.Name) + "|" + ind.Article
			if seen[key] {
				continue
			}
			seen[key] = true

			out = append(out, types.ProhibitedPracticeSignal{
				Component:   dep.Name,
				Version:     dep.Version,
				Location:    dep.Location,
				Practice:    ind.Practice,
				Article:     ind.Article,
				Prohibition: ind.Prohibition,
				AppliesWhen: ind.AppliesWhen,
				Question:    ind.Question,
				Status:      "requires human assessment",
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		return out[i].Article < out[j].Article
	})
	return out
}

// RenderArticle5Markdown emits the Article 5 review section.
//
// Returns "" when there are no signals, so the Annex IV builder omits
// the section entirely. That is deliberate: printing "no prohibited
// practices detected" would read as a clearance this scan cannot give.
// Several Article 5 prohibitions — social scoring, predictive policing,
// manipulative techniques — leave no reliable trace in a dependency
// manifest at all, so absence of a signal is genuinely not evidence of
// absence, and the section says so where it does appear.
func RenderArticle5Markdown(signals []types.ProhibitedPracticeSignal) string {
	if len(signals) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Article 5 — Prohibited Practices Review Required\n\n")
	sb.WriteString("This scan detected **")
	sb.WriteString(itoa(len(signals)))
	sb.WriteString(" component(s)** whose capabilities fall within the scope of\n")
	sb.WriteString("EU AI Act Article 5. Article 5 has applied since **2 February 2025** and\n")
	sb.WriteString("carries the Act's heaviest penalties — up to **EUR 35 000 000 or 7% of\n")
	sb.WriteString("worldwide annual turnover** (Article 99(3)).\n\n")

	sb.WriteString("> **This is not a finding that you are committing a prohibited practice.**\n")
	sb.WriteString("> Article 5 turns on purpose, context, and deployment setting — who the\n")
	sb.WriteString("> system is applied to, where, and to what end. A static scan can see that\n")
	sb.WriteString("> a capability is present in the codebase; it cannot see the deployment\n")
	sb.WriteString("> context that determines whether a prohibition applies. Each entry below\n")
	sb.WriteString("> states what the cited paragraph actually prohibits and the question that\n")
	sb.WriteString("> resolves it. Those questions are for your legal counsel, not for a tool.\n\n")

	for _, s := range signals {
		sb.WriteString("### `")
		sb.WriteString(s.Component)
		if s.Version != "" {
			sb.WriteString("` v")
			sb.WriteString(s.Version)
		} else {
			sb.WriteString("`")
		}
		sb.WriteString(" — ")
		sb.WriteString(s.Practice)
		sb.WriteString("\n\n")
		sb.WriteString("- **Article:** ")
		sb.WriteString(s.Article)
		sb.WriteString("\n")
		sb.WriteString("- **What that paragraph prohibits:** ")
		sb.WriteString(s.Prohibition)
		sb.WriteString("\n")
		sb.WriteString("- **When it applies:** ")
		sb.WriteString(s.AppliesWhen)
		sb.WriteString("\n")
		sb.WriteString("- **Question to answer:** ")
		sb.WriteString(s.Question)
		sb.WriteString("\n")
		if s.Location != "" {
			sb.WriteString("- **Detected at:** `")
			sb.WriteString(s.Location)
			sb.WriteString("`\n")
		}
		sb.WriteString("- **Status:** ")
		sb.WriteString(s.Status)
		sb.WriteString("\n\n")
	}

	sb.WriteString("**Absence of further signals is not a clearance.** Several Article 5\n")
	sb.WriteString("prohibitions — social scoring, individual crime-risk prediction from\n")
	sb.WriteString("profiling, subliminal or manipulative techniques, exploitation of\n")
	sb.WriteString("vulnerabilities — are properties of what a system *does* with ordinary\n")
	sb.WriteString("code and data. They leave no reliable trace in a dependency manifest and\n")
	sb.WriteString("cannot be detected by any scanner. They still require assessment.\n\n")

	return sb.String()
}

// itoa avoids pulling strconv in for a single small conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
