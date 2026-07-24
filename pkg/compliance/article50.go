// EU AI Act Article 50 — transparency obligations (Wave 21).
//
// Article 50 is the companion to Article 5 and behaves differently from
// both it and Annex IV. Article 5 asks "is this practice forbidden?"
// Annex IV asks "have you documented a high-risk system?" Article 50
// asks something narrower and more actionable: "does the person on the
// other side know?"
//
// Four duties, all applying from 2 August 2026 — the same date as the
// high-risk obligations, which makes them the same deadline conversation:
//
//	50(1) tell people they are talking to an AI
//	50(2) mark synthetic output machine-readably
//	50(3) tell people they are subject to emotion or biometric analysis
//	50(4) disclose deep fakes and AI-generated public-interest text
//
// Two design choices distinguish this from the Article 5 detector.
//
// First, **obligations are grouped, not listed per component.** A
// project with eight LLM libraries has one Article 50(1) duty, not
// eight. Reporting it eight times would bury the single sentence the
// reader has to act on.
//
// Second, **duties carry evidence where evidence is possible.** Some of
// these can be discharged by a technical control that leaves a trace —
// a watermarking library, a C2PA provenance manifest — so the report
// shows what it found rather than only what is missing. But most
// Article 50 disclosure is UI copy, a consent flow, or an editorial
// process, none of which appears in a dependency graph. So a missing
// marker is never reported as a failure: the catalog records how each
// duty is actually discharged, and the report says plainly when that
// mechanism is one a scanner cannot see.

package compliance

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"aicap/pkg/types"
)

//go:embed article50.json
var article50JSON []byte

type article50Obligation struct {
	ID                string   `json:"id"`
	Article           string   `json:"article"`
	Obligation        string   `json:"obligation"`
	Requirement       string   `json:"requirement"`
	AppliesWhen       string   `json:"applies_when"`
	Question          string   `json:"question"`
	DischargedBy      string   `json:"discharged_by"`
	Triggers          []string `json:"triggers"`
	DischargeEvidence []string `json:"discharge_evidence"`
}

var article50Catalog = func() []article50Obligation {
	var doc struct {
		Obligations []article50Obligation `json:"obligations"`
	}
	if err := json.Unmarshal(article50JSON, &doc); err != nil {
		// Fail soft, like every other catalog here: an unparseable file
		// costs the section, not the process.
		return nil
	}
	return doc.Obligations
}()

// DetectTransparencyObligations reports which Article 50 duties the
// scanned system appears to attract, and what evidence of discharge was
// found for each.
//
// Pure function. Returns nil when nothing matches.
func DetectTransparencyObligations(bom types.AIBOM) []types.TransparencyObligation {
	present := map[string]types.AIDependency{}
	for _, dep := range bom.Dependencies {
		name := strings.ToLower(dep.Name)
		// Prefer an entry with a concrete version for display.
		if existing, seen := present[name]; !seen || existing.Version == "" {
			present[name] = dep
		}
	}

	var out []types.TransparencyObligation
	for _, ob := range article50Catalog {
		var triggered []string
		for _, t := range ob.Triggers {
			if dep, ok := present[strings.ToLower(t)]; ok {
				label := dep.Name
				if dep.Version != "" && isConcreteVersion(dep.Version) {
					label += " " + dep.Version
				}
				triggered = append(triggered, label)
			}
		}
		if len(triggered) == 0 {
			continue
		}
		sort.Strings(triggered)

		var evidence []string
		for _, e := range ob.DischargeEvidence {
			if dep, ok := present[strings.ToLower(e)]; ok {
				evidence = append(evidence, dep.Name)
			}
		}
		sort.Strings(evidence)

		// Status is about what the scan can see, never about compliance.
		// "no technical marking detected" is a true statement about the
		// dependency graph; "non-compliant" would be a claim about a
		// deployment this code has never observed.
		status := "requires human assessment"
		switch {
		case len(evidence) > 0:
			status = "technical evidence detected — verify it covers all generated output"
		case len(ob.DischargeEvidence) > 0:
			status = "no technical marking detected in dependencies"
		}

		out = append(out, types.TransparencyObligation{
			ID:                   ob.ID,
			Article:              ob.Article,
			Obligation:           ob.Obligation,
			Requirement:          ob.Requirement,
			AppliesWhen:          ob.AppliesWhen,
			Question:             ob.Question,
			DischargedBy:         ob.DischargedBy,
			TriggeredBy:          triggered,
			EvidenceFound:        evidence,
			EvidenceIsDetectable: len(ob.DischargeEvidence) > 0,
			Status:               status,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// isConcreteVersion keeps scanner placeholders out of user-facing labels.
func isConcreteVersion(v string) bool {
	switch strings.ToLower(v) {
	case "", "unknown", "imported", "local", "docker-image", "docker-install", "docker-layer", "hidden":
		return false
	}
	return true
}

// RenderArticle50Markdown emits the transparency-obligations section.
//
// Empty when nothing applies, so the caller omits the heading rather
// than printing a clearance.
func RenderArticle50Markdown(obligations []types.TransparencyObligation) string {
	if len(obligations) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Article 50 — Transparency Obligations\n\n")
	sb.WriteString("This system attracts **")
	sb.WriteString(itoa(len(obligations)))
	sb.WriteString(" transparency obligation(s)** under EU AI Act Article 50,\n")
	sb.WriteString("which applies from **2 August 2026** — the same date as the high-risk\n")
	sb.WriteString("obligations documented above.\n\n")

	sb.WriteString("> Article 50 is about whether the person on the other side knows. Unlike\n")
	sb.WriteString("> the high-risk regime it does not depend on classification, and unlike\n")
	sb.WriteString("> Article 5 it does not forbid anything — it requires disclosure. Most of\n")
	sb.WriteString("> these duties are discharged by interface copy, a consent flow, or an\n")
	sb.WriteString("> editorial process, none of which is visible to a dependency scan. Where\n")
	sb.WriteString("> a duty *can* be discharged by a technical control, the evidence found is\n")
	sb.WriteString("> reported below.\n\n")

	for _, o := range obligations {
		sb.WriteString("### ")
		sb.WriteString(o.Article)
		sb.WriteString(" — ")
		sb.WriteString(o.Obligation)
		sb.WriteString("\n\n")
		sb.WriteString("- **What it requires:** ")
		sb.WriteString(o.Requirement)
		sb.WriteString("\n")
		sb.WriteString("- **When it applies:** ")
		sb.WriteString(o.AppliesWhen)
		sb.WriteString("\n")
		sb.WriteString("- **Triggered by:** ")
		sb.WriteString(joinCode(o.TriggeredBy))
		sb.WriteString("\n")
		sb.WriteString("- **How it is discharged:** ")
		sb.WriteString(o.DischargedBy)
		sb.WriteString("\n")

		if o.EvidenceIsDetectable {
			if len(o.EvidenceFound) > 0 {
				sb.WriteString("- **Evidence detected:** ")
				sb.WriteString(joinCode(o.EvidenceFound))
				sb.WriteString(" — confirm the marking is applied to *all* generated output, ")
				sb.WriteString("not only some paths.\n")
			} else {
				sb.WriteString("- **Evidence detected:** none. No content-watermarking or ")
				sb.WriteString("provenance library (C2PA, invisible-watermark, AudioSeal) was found ")
				sb.WriteString("in the dependency graph. Article 50(2) requires marking that is ")
				sb.WriteString("**machine-readable** — a visible \"made with AI\" label does not ")
				sb.WriteString("satisfy it on its own.\n")
			}
		}

		sb.WriteString("- **Question to answer:** ")
		sb.WriteString(o.Question)
		sb.WriteString("\n")
		sb.WriteString("- **Status:** ")
		sb.WriteString(o.Status)
		sb.WriteString("\n\n")
	}

	sb.WriteString("**Absence of an obligation above is not a clearance.** These duties are\n")
	sb.WriteString("inferred from detected components; a system that generates synthetic content\n")
	sb.WriteString("through a bespoke model, or interacts with users through code this scan\n")
	sb.WriteString("cannot attribute, attracts the same duties without appearing here.\n\n")

	return sb.String()
}

func joinCode(items []string) string {
	if len(items) == 0 {
		return "—"
	}
	return "`" + strings.Join(items, "`, `") + "`"
}
