package compliance

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"aicap/pkg/types"
)

// spdxIDPattern is the identifier grammar from the SPDX 2.3 spec. A
// document violating it fails validation in any conforming consumer,
// which would defeat the entire point of emitting SPDX.
var spdxIDPattern = regexp.MustCompile(`^SPDXRef-[a-zA-Z0-9.\-]+$`)

func spdxBOM(deps ...types.AIDependency) types.AIBOM {
	return types.AIBOM{ProjectName: "demo/project", CommitSha: "abc1234", Dependencies: deps}
}

func TestSPDX_DocumentShapeIsValid(t *testing.T) {
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "openai", Version: "1.40.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
	), types.RiskRegister{})

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want CC0-1.0 (required by the spec)", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("document SPDXID = %q", doc.SPDXID)
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://") {
		t.Errorf("documentNamespace = %q, want an absolute URI", doc.DocumentNamespace)
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("creationInfo.creators is required")
	}
	// Every package needs downloadLocation and copyrightText; the spec
	// has no "omit it" option, only NOASSERTION.
	for _, p := range doc.Packages {
		if p.DownloadLocation == "" || p.CopyrightText == "" {
			t.Errorf("package %s missing a required field: %+v", p.SPDXID, p)
		}
	}
}

func TestSPDX_IdentifiersAreLegalAndUnique(t *testing.T) {
	// The names this scanner produces are hostile to the SPDXID grammar:
	// npm scopes, spaces, and file paths. Two "Hardcoded Model" findings
	// must not collapse into one package either — that would silently
	// merge two distinct components in the consumer's view.
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "@anthropic-ai/sdk", Version: "0.32.0", Ecosystem: "Node.js (npm)"},
		types.AIDependency{Name: "Hardcoded Model", Version: "gpt-5", Ecosystem: "Source Code (.py)"},
		types.AIDependency{Name: "Hardcoded Model", Version: "claude-opus-4-5", Ecosystem: "Source Code (.py)"},
		types.AIDependency{Name: "models/llama-3-8b.gguf", Version: "local", Ecosystem: "Model Weight (.gguf)"},
	), types.RiskRegister{})

	seen := map[string]bool{}
	for _, p := range doc.Packages {
		if !spdxIDPattern.MatchString(p.SPDXID) {
			t.Errorf("illegal SPDXID %q (from name %q)", p.SPDXID, p.Name)
		}
		if seen[p.SPDXID] {
			t.Errorf("duplicate SPDXID %q — two components would merge", p.SPDXID)
		}
		seen[p.SPDXID] = true
	}
	// The original names must survive even though the ids are mangled.
	var names []string
	for _, p := range doc.Packages {
		names = append(names, p.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "@anthropic-ai/sdk") {
		t.Error("the original package name was lost in sanitisation")
	}
}

func TestSPDX_UnrecognisedLicenceBecomesLicenseRef(t *testing.T) {
	// "Proprietary (OpenAI)" is not an SPDX expression. Emitting it in
	// licenseDeclared would produce an invalid document.
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{
			Name: "Hardcoded Model", Version: "gpt-5",
			Ecosystem: "Source Code (.py)", License: "Proprietary (OpenAI)",
		},
	), types.RiskRegister{})

	var pkg *types.SPDXPackage
	for i := range doc.Packages {
		if doc.Packages[i].Name == "Hardcoded Model" {
			pkg = &doc.Packages[i]
		}
	}
	if pkg == nil {
		t.Fatal("model package missing")
	}
	if !strings.HasPrefix(pkg.LicenseDeclared, "LicenseRef-") {
		t.Errorf("licenseDeclared = %q, want a LicenseRef for vendor prose", pkg.LicenseDeclared)
	}
	if spdxIDUnsafe.MatchString(strings.TrimPrefix(pkg.LicenseDeclared, "LicenseRef-")) {
		t.Errorf("LicenseRef contains characters the grammar forbids: %q", pkg.LicenseDeclared)
	}
	// And the original text must be preserved, not discarded.
	found := false
	for _, e := range doc.ExtractedLicenses {
		if e.LicenseID == pkg.LicenseDeclared && e.ExtractedText == "Proprietary (OpenAI)" {
			found = true
		}
	}
	if !found {
		t.Errorf("no hasExtractedLicensingInfos entry preserving the original text: %+v", doc.ExtractedLicenses)
	}
}

func TestSPDX_RecognisedLicencePassesThrough(t *testing.T) {
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "some-model", Version: "1.0", Ecosystem: "Model Weight (.bin)", License: "apache-2.0"},
	), types.RiskRegister{})

	for _, p := range doc.Packages {
		if p.Name == "some-model" {
			if p.LicenseDeclared != "Apache-2.0" {
				t.Errorf("licenseDeclared = %q, want the canonical SPDX id Apache-2.0", p.LicenseDeclared)
			}
		}
	}
	if len(doc.ExtractedLicenses) != 0 {
		t.Errorf("a recognised licence should need no LicenseRef: %+v", doc.ExtractedLicenses)
	}
}

func TestSPDX_LicenseConcludedIsAlwaysNoAssertion(t *testing.T) {
	// "Concluded" asserts a legal determination. AIcap reads what a
	// registry reports; it does not perform review, so claiming a
	// conclusion would misrepresent what happened.
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "m", Version: "1", Ecosystem: "Model Weight (.bin)", License: "mit"},
	), types.RiskRegister{})
	for _, p := range doc.Packages {
		if p.LicenseConcluded != "NOASSERTION" {
			t.Errorf("package %s licenseConcluded = %q, want NOASSERTION", p.SPDXID, p.LicenseConcluded)
		}
	}
}

func TestSPDX_AdvisoriesBecomeSecurityExternalRefs(t *testing.T) {
	// SPDX 2.3 has no vulnerability model; SECURITY external refs are
	// the established convention.
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "transformers",
		LiveVulns: []types.LiveVuln{{ID: "GHSA-abcd"}, {ID: "CVE-2025-1"}},
	}}}
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "transformers", Version: "4.30.0", Ecosystem: "Python (pip)"},
	), reg)

	var refs []string
	for _, p := range doc.Packages {
		for _, r := range p.ExternalRefs {
			if r.Category == "SECURITY" {
				refs = append(refs, r.Locator)
			}
		}
	}
	if len(refs) != 2 {
		t.Fatalf("security refs = %v, want two advisory URLs", refs)
	}
	for _, r := range refs {
		if !strings.HasPrefix(r, "https://osv.dev/vulnerability/") {
			t.Errorf("advisory ref is not a resolvable URL: %q", r)
		}
	}
}

func TestSPDX_RelationshipsDescribeAndDepend(t *testing.T) {
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "openai", Version: "1.40.0", Ecosystem: "Python (pip)"},
		types.AIDependency{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
	), types.RiskRegister{})

	var describes, depends int
	for _, r := range doc.Relationships {
		switch r.RelationshipType {
		case "DESCRIBES":
			describes++
			if r.SPDXElementID != "SPDXRef-DOCUMENT" {
				t.Errorf("DESCRIBES must originate at the document, got %q", r.SPDXElementID)
			}
		case "DEPENDS_ON":
			depends++
		}
	}
	if describes != 1 {
		t.Errorf("DESCRIBES relationships = %d, want exactly 1", describes)
	}
	if depends != 2 {
		t.Errorf("DEPENDS_ON relationships = %d, want one per component", depends)
	}

	// Every relationship must point at a package that exists.
	ids := map[string]bool{"SPDXRef-DOCUMENT": true}
	for _, p := range doc.Packages {
		ids[p.SPDXID] = true
	}
	for _, r := range doc.Relationships {
		if !ids[r.SPDXElementID] || !ids[r.RelatedSPDXElement] {
			t.Errorf("dangling relationship: %+v", r)
		}
	}
}

func TestSPDX_PlaceholderVersionsOmitted(t *testing.T) {
	// versionInfo should hold a version. "imported" is a scanner marker
	// that means nothing to a consumer.
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "torch", Version: "imported", Ecosystem: "Source Code (.py import)"},
	), types.RiskRegister{})
	for _, p := range doc.Packages {
		if p.Name == "torch" && p.VersionInfo != "" {
			t.Errorf("versionInfo = %q, want it omitted for a placeholder", p.VersionInfo)
		}
	}
}

func TestSPDX_ScopeIsStatedInTheDocument(t *testing.T) {
	// An SBOM that silently enumerates only AI components would mislead
	// a consumer expecting a full dependency tree.
	doc := GenerateSPDXDocument(spdxBOM(), types.RiskRegister{})
	if !strings.Contains(doc.CreationInfo.Comment, "AI") ||
		!strings.Contains(strings.ToLower(doc.CreationInfo.Comment), "not the") {
		t.Errorf("creationInfo.comment does not state the AI-only scope: %q", doc.CreationInfo.Comment)
	}
}

func TestSPDX_NamespaceIsStableForTheSameScan(t *testing.T) {
	bom := spdxBOM(types.AIDependency{Name: "openai", Version: "1.0", Ecosystem: "Python (pip)"})
	a := GenerateSPDXDocument(bom, types.RiskRegister{}).DocumentNamespace
	b := GenerateSPDXDocument(bom, types.RiskRegister{}).DocumentNamespace
	if a != b {
		t.Errorf("namespace varies between identical runs: %q vs %q", a, b)
	}
	other := GenerateSPDXDocument(types.AIBOM{ProjectName: "other", CommitSha: "zzz"}, types.RiskRegister{}).DocumentNamespace
	if other == a {
		t.Error("different projects produced the same namespace — namespaces must be unique per document")
	}
}

func TestSPDX_SerialisesToJSON(t *testing.T) {
	doc := GenerateSPDXDocument(spdxBOM(
		types.AIDependency{Name: "@anthropic-ai/sdk", Version: "0.32.0", Ecosystem: "Node.js (npm)", License: "MIT"},
	), types.RiskRegister{})

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"spdxVersion", "dataLicense", "SPDXID", "documentNamespace", "creationInfo", "packages", "relationships"} {
		if _, ok := round[key]; !ok {
			t.Errorf("serialised document missing required key %q", key)
		}
	}
}
