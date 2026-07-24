package compliance

import (
	"context"
	"strings"
	"sync"
	"testing"

	"aicap/pkg/types"
)

// Wave 16 tests: advisory depth, query scope, and determinism.
//
// The two behaviours under test are the ones that decide whether the
// risk register is useful to the person reading it: whether a
// vulnerability can be reported at all when the static catalog has never
// heard of the component, and whether the report says what to upgrade to.

// --- Advisory depth ------------------------------------------------------

func TestOSVVuln_ToLiveVuln_CarriesFixAndSeverity(t *testing.T) {
	v := osvVuln{
		ID:               "GHSA-abcd",
		Aliases:          []string{"CVE-2025-1111"},
		Summary:          "Arbitrary code execution during model load",
		DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
		Severity:         []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []osvAffected{{
			Package: osvPackage{Name: "transformers", Ecosystem: "PyPI"},
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{
				{Introduced: "0"}, {Fixed: "4.48.1"},
			}}},
		}},
	}

	got := v.toLiveVuln("transformers")

	if got.FixedVersion != "4.48.1" {
		t.Errorf("FixedVersion = %q, want 4.48.1 — the most actionable field OSV returns", got.FixedVersion)
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", got.Severity)
	}
	if !strings.HasPrefix(got.CVSSVector, "CVSS:3.1/") {
		t.Errorf("CVSSVector = %q, want the vector quoted verbatim, not recomputed", got.CVSSVector)
	}
	if got.Summary == "" || len(got.Aliases) != 1 {
		t.Errorf("summary/aliases dropped: %+v", got)
	}
}

func TestOSVVuln_EarliestFixFor_IgnoresSiblingPackages(t *testing.T) {
	// An advisory can list several affected packages. Reporting a
	// sibling's fix version as this component's remediation would be
	// actively wrong advice.
	v := osvVuln{
		ID: "GHSA-multi",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "other-package", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Fixed: "9.9.9"}}}},
			},
			{
				Package: osvPackage{Name: "torch", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Fixed: "2.6.0"}}}},
			},
		},
	}
	if got := v.earliestFixFor("torch"); got != "2.6.0" {
		t.Errorf("earliestFixFor(torch) = %q, want 2.6.0", got)
	}
}

func TestOSVVuln_NoPublishedFix_ReportsEmpty(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-nofix",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "torch", Ecosystem: "PyPI"},
			Ranges:  []osvRange{{Events: []osvEvent{{Introduced: "0"}}}},
		}},
	}
	if got := v.toLiveVuln("torch").FixedVersion; got != "" {
		t.Errorf("FixedVersion = %q, want empty when no fix is published", got)
	}
}

// --- Query scope ---------------------------------------------------------

func TestIsQueryableVersion(t *testing.T) {
	// Placeholders must never reach OSV: /v1/query without a parseable
	// version returns every advisory ever filed against the package,
	// including ones fixed long before the version in use. Attributing
	// those to the project would be a fabricated compliance finding.
	for _, v := range []string{"", "unknown", "imported", "local", "docker-install",
		"docker-image", "docker-layer", "HIDDEN", "latest", "*"} {
		if isQueryableVersion(v) {
			t.Errorf("isQueryableVersion(%q) = true, want false", v)
		}
	}
	for _, v := range []string{"1.0", "2.4.0", "4.44.0", "1.40.0rc1", "0.32.0"} {
		if !isQueryableVersion(v) {
			t.Errorf("isQueryableVersion(%q) = false, want true", v)
		}
	}
}

func TestEnrichWithOSV_SkipsPlaceholderVersions(t *testing.T) {
	queried := make(chan string, 8)
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		queried <- q.Version
		return []osvVuln{{ID: "CVE-SHOULD-NOT-APPEAR"}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		// Detected via `import torch` — the version is unknown.
		{Name: "torch", Version: "imported", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	close(queried)
	if v, ok := <-queried; ok {
		t.Errorf("OSV was queried with version %q; placeholder versions must be skipped", v)
	}
	if len(register.Findings) != 1 {
		t.Fatalf("findings = %d, want the catalog finding preserved", len(register.Findings))
	}
	if len(register.Findings[0].LiveVulns) != 0 {
		t.Error("advisories attached to a dependency whose version is unknown")
	}
}

func TestEnrichWithOSV_QueriesDepsOutsideTheCatalog(t *testing.T) {
	// The scope fix. Before Wave 16 only catalog-matched names were sent
	// to OSV, so a vulnerable dependency the 10-entry catalog had never
	// heard of was never even looked up.
	var mu sync.Mutex
	seen := map[string]bool{}
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		mu.Lock()
		seen[q.Package.Name] = true
		mu.Unlock()
		return nil
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
		{Name: "pillow", Version: "10.0.0", Ecosystem: "Python (pip)"},
		{Name: "express", Version: "4.19.0", Ecosystem: "Node.js (npm)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"torch", "pillow", "express"} {
		if !seen[want] {
			t.Errorf("%q was never queried against OSV", want)
		}
	}
}

func TestEnrichWithOSV_DeduplicatesRepeatedDeps(t *testing.T) {
	// The same dependency is routinely detected in both a manifest and a
	// lockfile. That must be one OSV call, not two.
	var mu sync.Mutex
	calls := 0
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (Poetry lock)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("OSV called %d times for one distinct dep+version, want 1", calls)
	}
}

func TestEnrichWithOSV_OrderingIsDeterministic(t *testing.T) {
	// Workers finish in arbitrary order. An auditable document that
	// reshuffles its rows between identical runs invites exactly the
	// questions this product exists to prevent.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		return []osvVuln{{ID: "CVE-" + q.Package.Name}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "zeta-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
		{Name: "alpha-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
		{Name: "mid-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
	}}

	var first []string
	for run := 0; run < 5; run++ {
		register := ComputeRiskRegister(bom)
		EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())
		order := []string{}
		for _, f := range register.Findings {
			order = append(order, f.Component)
		}
		if run == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("finding order varied between runs: %v vs %v", first, order)
		}
	}
	if len(first) != 3 || first[0] != "alpha-pkg" {
		t.Errorf("order = %v, want alphabetical by component", first)
	}
}

// --- Severity and remediation --------------------------------------------

func TestSeverityFromVulns(t *testing.T) {
	cases := []struct {
		labels []string
		want   string
	}{
		{[]string{"HIGH"}, "High"},
		{[]string{"CRITICAL"}, "High"},
		{[]string{"MODERATE"}, "Medium"},
		{[]string{"LOW"}, "Low"},
		{[]string{"LOW", "HIGH"}, "High"},
		// Unrated advisories land on Medium: "Low" would understate an
		// unknown, "High" would inflate the summary counts an auditor
		// reads before anything else.
		{[]string{""}, "Medium"},
		{nil, "Medium"},
	}
	for _, c := range cases {
		vulns := make([]types.LiveVuln, 0, len(c.labels))
		for _, l := range c.labels {
			vulns = append(vulns, types.LiveVuln{Severity: l})
		}
		if got := severityFromVulns(vulns); got != c.want {
			t.Errorf("severityFromVulns(%v) = %q, want %q", c.labels, got, c.want)
		}
	}
}

func TestRemediationAdvice_NamesFixOrSaysThereIsNone(t *testing.T) {
	withFix := remediationAdvice([]types.LiveVuln{{FixedVersion: "4.48.1"}, {FixedVersion: "4.48.1"}})
	if !strings.Contains(withFix, "4.48.1") {
		t.Errorf("advice = %q, want the fixed version named", withFix)
	}
	if strings.Count(withFix, "4.48.1") != 1 {
		t.Errorf("advice = %q, want the duplicate fix version deduplicated", withFix)
	}

	noFix := remediationAdvice([]types.LiveVuln{{ID: "GHSA-x"}})
	if !strings.Contains(strings.ToLower(noFix), "no fixed version") {
		t.Errorf("advice = %q, want it to state plainly that no fix is published", noFix)
	}
}

// --- Rendering -----------------------------------------------------------

func TestRenderLiveAdvisoriesMarkdown_ShowsFixAndDetail(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "transformers",
		Version:   "4.44.0",
		Source:    "catalog",
		LiveVulns: []types.LiveVuln{{
			ID:           "GHSA-abcd",
			Severity:     "HIGH",
			Summary:      "Arbitrary code execution",
			FixedVersion: "4.48.1",
			CVSSVector:   "CVSS:3.1/AV:N",
		}},
	}}}

	md := RenderLiveAdvisoriesMarkdown(reg)
	for _, want := range []string{"GHSA-abcd", "HIGH", "Arbitrary code execution", "fixed in 4.48.1", "CVSS:3.1/AV:N"} {
		if !strings.Contains(md, want) {
			t.Errorf("advisory block missing %q:\n%s", want, md)
		}
	}
}

func TestRenderLiveAdvisoriesMarkdown_StatesWhenNoFixExists(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "torch",
		LiveVulns: []types.LiveVuln{{ID: "GHSA-nofix", Severity: "MODERATE"}},
	}}}
	md := RenderLiveAdvisoriesMarkdown(reg)
	if !strings.Contains(md, "no fixed version published") {
		t.Errorf("an unfixed advisory must say so — it is a different remediation decision:\n%s", md)
	}
}

func TestRenderLiveAdvisoriesMarkdown_EmptyWhenNoLiveData(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{Component: "torch"}}}
	if got := RenderLiveAdvisoriesMarkdown(reg); got != "" {
		t.Errorf("got %q, want empty so the caller can omit the heading entirely", got)
	}
}

func TestRenderRiskRegisterMarkdown_ShowsFindingSource(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{
		{Component: "torch", Severity: "High", Status: "open", Source: "catalog"},
		{Component: "pillow", Severity: "High", Status: "open", Source: "osv"},
	}}
	md := RenderRiskRegisterMarkdown(reg)
	if !strings.Contains(md, "| Source |") {
		t.Errorf("table missing Source column:\n%s", md)
	}
	if !strings.Contains(md, "live advisory") || !strings.Contains(md, "catalog") {
		t.Errorf("table must distinguish curated from live-advisory findings:\n%s", md)
	}
}

func TestAnnexIV_IncludesLiveAdvisoryBlock(t *testing.T) {
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "transformers", Version: "4.44.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	}
	register := ComputeRiskRegister(bom)
	register.Findings[0].LiveVulns = []types.LiveVuln{{
		ID: "GHSA-abcd", Severity: "HIGH", FixedVersion: "4.48.1",
	}}
	register.Findings[0].LiveVulnIDs = []string{"GHSA-abcd"}

	md := GenerateAnnexIVMarkdownWithRegister(bom, register)

	if !strings.Contains(md, "Live advisories") {
		t.Error("Annex IV omits the live advisory section")
	}
	if !strings.Contains(md, "fixed in 4.48.1") {
		t.Error("Annex IV omits the fixed version — the one field the reader can act on")
	}
	if !strings.Contains(md, "does not recompute") {
		t.Error("Annex IV should state that severities are quoted as published, not recomputed")
	}
}

func TestEnrichWithOSV_CatalogFindingKeepsCuratedMitigationAndGainsFix(t *testing.T) {
	// The curated mitigation is a considered assessment of the
	// component's risk class; the live fix is the immediate action.
	// A reader scanning the mitigation list should get both.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		return []osvVuln{{
			ID:               "GHSA-tf",
			DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
			Affected: []osvAffected{{
				Package: osvPackage{Name: "tensorflow", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Introduced: "0"}, {Fixed: "2.18.1"}}}},
			}},
		}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	curated := register.Findings[0].Mitigation
	if curated == "" {
		t.Fatal("setup: catalog entry has no mitigation")
	}

	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	got := register.Findings[0].Mitigation
	if !strings.Contains(got, strings.TrimRight(curated, " .")) {
		t.Errorf("curated mitigation was discarded:\n got: %s\nwant it to retain: %s", got, curated)
	}
	if !strings.Contains(got, "2.18.1") {
		t.Errorf("mitigation = %q, want the available fix version appended", got)
	}
	if register.Findings[0].Source != "catalog" {
		t.Errorf("source = %q, want catalog (the finding originated there)", register.Findings[0].Source)
	}
	// Enriching a catalog finding must not create a second row for it.
	if len(register.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(register.Findings))
	}
}

// --- Attestation ---------------------------------------------------------

func TestAnnexIV_LocalRender_DoesNotClaimAnImmutableAuditTrail(t *testing.T) {
	// The reason it is safe to emit Annex IV from the free CLI at all.
	// If this regresses, the tool ships a document asserting an audit
	// trail that does not exist — the exact overstatement the product
	// exists to prevent.
	bom := types.AIBOM{ProjectName: "demo", CommitSha: "abc123"}
	md := GenerateAnnexIVMarkdownWithAttestation(bom, ComputeRiskRegister(bom),
		types.Attestation{Anchored: false})

	if strings.Contains(md, "immutable audit trail") {
		t.Error("a locally generated document must not claim an immutable audit trail")
	}
	for _, want := range []string{
		"Unattested",
		"not anchored to an audit ledger",
		"It cannot be independently verified",
		"AICAP_API_KEY",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("unattested provenance section missing %q", want)
		}
	}
}

func TestAnnexIV_AnchoredRender_KeepsLedgerLanguage(t *testing.T) {
	bom := types.AIBOM{ProjectName: "demo", CommitSha: "abc123"}
	md := GenerateAnnexIVMarkdownWithAttestation(bom, ComputeRiskRegister(bom),
		types.Attestation{Anchored: true, LedgerHash: "deadbeef"})

	if !strings.Contains(md, "immutable audit trail") {
		t.Error("anchored render lost its ledger language")
	}
	if !strings.Contains(md, "deadbeef") {
		t.Error("anchored render omits the ledger hash it was given")
	}
	if strings.Contains(md, "Unattested") {
		t.Error("anchored render must not carry the unattested warning")
	}
}

func TestGenerateAnnexIVMarkdownWithRegister_DefaultsToAnchored(t *testing.T) {
	// /api/save-proof relies on this: its renders are persisted into the
	// ledger, so the anchored wording is correct there and must not
	// change as a side effect of the CLI work.
	bom := types.AIBOM{ProjectName: "demo"}
	md := GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
	if !strings.Contains(md, "Immutable Compliance Proof") {
		t.Error("save-proof render lost its anchored § 5")
	}
}
