package drift

import (
	"testing"

	"aicap/pkg/types"
)

func dep(name, version, ecosystem, risk string) types.AIDependency {
	return types.AIDependency{Name: name, Version: version, Ecosystem: ecosystem, RiskLevel: risk}
}

func bom(compliance string, deps ...types.AIDependency) types.AIBOM {
	return types.AIBOM{Dependencies: deps, Compliance: compliance}
}

func register(findings ...types.RiskFinding) types.RiskRegister {
	return types.RiskRegister{Findings: findings}
}

// --- The signal the feature exists for -----------------------------------

func TestCompute_NewAdvisoryOnUnchangedDependency(t *testing.T) {
	// Nobody touched the dependency. A CVE was published against it
	// anyway. This is the case a point-in-time audit structurally cannot
	// catch, and the reason a *continuous* scanner is worth paying for —
	// if this test breaks, the product's central claim breaks with it.
	deps := []types.AIDependency{dep("transformers", "4.44.0", "Python (pip)", "High")}

	before := register(types.RiskFinding{Component: "transformers", Version: "4.44.0"})
	after := register(types.RiskFinding{
		Component: "transformers",
		Version:   "4.44.0",
		LiveVulns: []types.LiveVuln{{ID: "GHSA-new", Severity: "HIGH", FixedVersion: "4.48.1"}},
	})

	d := Compute(bom("Passed", deps...), bom("Passed", deps...), before, after)

	if len(d.Risk.NewAdvisories) != 1 {
		t.Fatalf("NewAdvisories = %d, want 1: %+v", len(d.Risk.NewAdvisories), d.Risk)
	}
	got := d.Risk.NewAdvisories[0]
	if got.Component != "transformers" || len(got.Vulns) != 1 || got.Vulns[0].ID != "GHSA-new" {
		t.Errorf("advisory delta = %+v", got)
	}
	if got.Vulns[0].FixedVersion != "4.48.1" {
		t.Error("the fixed version must survive into the drift record — it is the actionable part")
	}
	if !d.Summary.Regressed {
		t.Error("a new advisory against an unchanged component must count as a regression")
	}
	// Nothing about the BOM changed, so nothing should be reported there.
	if d.Summary.DependenciesAdded != 0 || d.Summary.VersionsChanged != 0 {
		t.Errorf("dependency churn reported where none exists: %+v", d.Summary)
	}
}

func TestCompute_AdvisoryAlreadyPresentIsNotNew(t *testing.T) {
	// Re-reporting a known advisory on every scan would make the feature
	// unusable as an alert.
	vuln := types.LiveVuln{ID: "GHSA-known"}
	before := register(types.RiskFinding{Component: "torch", LiveVulns: []types.LiveVuln{vuln}})
	after := register(types.RiskFinding{Component: "torch", LiveVulns: []types.LiveVuln{vuln}})

	d := Compute(bom("Passed"), bom("Passed"), before, after)
	if len(d.Risk.NewAdvisories) != 0 {
		t.Errorf("a previously-reported advisory was reported as new: %+v", d.Risk.NewAdvisories)
	}
	if d.Summary.Regressed {
		t.Error("an unchanged scan must not read as a regression")
	}
}

// --- Dependency deltas ----------------------------------------------------

func TestCompute_AddedAndRemovedDependencies(t *testing.T) {
	from := bom("Passed", dep("torch", "2.4.0", "Python (pip)", "High"))
	to := bom("Passed",
		dep("torch", "2.4.0", "Python (pip)", "High"),
		dep("langchain", "0.2.0", "Python (pip)", "Medium"),
	)

	d := Compute(from, to, register(), register())

	if len(d.Dependencies.Added) != 1 || d.Dependencies.Added[0].Name != "langchain" {
		t.Fatalf("Added = %+v, want [langchain]", d.Dependencies.Added)
	}
	if len(d.Dependencies.Removed) != 0 {
		t.Errorf("Removed = %+v, want none", d.Dependencies.Removed)
	}

	// And the reverse direction.
	rev := Compute(to, from, register(), register())
	if len(rev.Dependencies.Removed) != 1 || rev.Dependencies.Removed[0].Name != "langchain" {
		t.Errorf("Removed = %+v, want [langchain]", rev.Dependencies.Removed)
	}
}

func TestCompute_VersionChange(t *testing.T) {
	from := bom("Passed", dep("torch", "2.4.0", "Python (pip)", "High"))
	to := bom("Passed", dep("torch", "2.6.0", "Python (pip)", "High"))

	d := Compute(from, to, register(), register())

	if len(d.Dependencies.VersionChanged) != 1 {
		t.Fatalf("VersionChanged = %+v, want one entry", d.Dependencies.VersionChanged)
	}
	vc := d.Dependencies.VersionChanged[0]
	if vc.FromVersion != "2.4.0" || vc.ToVersion != "2.6.0" {
		t.Errorf("version change = %+v", vc)
	}
	// A moved version is not an addition or a removal.
	if len(d.Dependencies.Added) != 0 || len(d.Dependencies.Removed) != 0 {
		t.Errorf("version bump reported as add/remove: %+v", d.Dependencies)
	}
}

func TestCompute_EcosystemLabelChangeIsNotChurn(t *testing.T) {
	// Adding a lockfile, or migrating requirements.txt to poetry.lock,
	// changes every ecosystem label without changing a single dependency.
	// If that reported the whole BOM as removed and re-added, users would
	// learn to ignore the feature — which is worse than not having it.
	from := bom("Passed", dep("torch", "2.4.0", "Python (pip)", "High"))
	to := bom("Passed", dep("torch", "2.4.0", "Python (Poetry lock)", "High"))

	d := Compute(from, to, register(), register())

	if len(d.Dependencies.Added) != 0 || len(d.Dependencies.Removed) != 0 {
		t.Errorf("ecosystem relabel produced churn: %+v", d.Dependencies)
	}
	if len(d.Dependencies.VersionChanged) != 0 {
		t.Errorf("ecosystem relabel produced a version change: %+v", d.Dependencies.VersionChanged)
	}
}

func TestCompute_PlaceholderVersionTransitionsAreNotReported(t *testing.T) {
	// "imported" -> "2.4.0" means the scanner learned the version, not
	// that the project upgraded. Reporting it as a version bump would be
	// a false alarm.
	from := bom("Passed", dep("torch", "imported", "Source Code (.py import)", "High"))
	to := bom("Passed", dep("torch", "2.4.0", "Python (pip)", "High"))

	d := Compute(from, to, register(), register())
	if len(d.Dependencies.VersionChanged) != 0 {
		t.Errorf("placeholder-to-version transition reported as a bump: %+v", d.Dependencies.VersionChanged)
	}
}

func TestCompute_DuplicateDetectionsCollapseToOneComponent(t *testing.T) {
	// The same package is routinely found in a manifest and a lockfile
	// and an import. That is one component, and the entry carrying a
	// concrete version is the one worth keeping.
	from := bom("Passed")
	to := bom("Passed",
		dep("torch", "imported", "Source Code (.py import)", "High"),
		dep("torch", "2.4.0", "Python (pip)", "High"),
	)

	d := Compute(from, to, register(), register())
	if len(d.Dependencies.Added) != 1 {
		t.Fatalf("Added = %+v, want a single torch entry", d.Dependencies.Added)
	}
	if d.Dependencies.Added[0].Version != "2.4.0" {
		t.Errorf("kept version %q, want the concrete 2.4.0", d.Dependencies.Added[0].Version)
	}
}

func TestCompute_HardcodedModelSwapIsAChange(t *testing.T) {
	// Every hardcoded model shares the name "Hardcoded Model"; the model
	// identifier lives in Version. Keying on name alone would report a
	// gpt-4o -> gpt-5 swap as no change at all — a governance-relevant
	// event going silent.
	from := bom("Passed", dep("Hardcoded Model", "gpt-4o", "Source Code (.py)", "High"))
	to := bom("Passed", dep("Hardcoded Model", "gpt-5", "Source Code (.py)", "High"))

	d := Compute(from, to, register(), register())

	if len(d.Dependencies.Added) != 1 || d.Dependencies.Added[0].Version != "gpt-5" {
		t.Errorf("Added = %+v, want the new model", d.Dependencies.Added)
	}
	if len(d.Dependencies.Removed) != 1 || d.Dependencies.Removed[0].Version != "gpt-4o" {
		t.Errorf("Removed = %+v, want the old model", d.Dependencies.Removed)
	}
}

func TestCompute_ExposedSecretsTrackedPerLocation(t *testing.T) {
	from := bom("Passed", types.AIDependency{
		Name: "Exposed Secret", Version: "HIDDEN", Location: "app.py:12", RiskLevel: "High",
	})
	to := bom("Passed", types.AIDependency{
		Name: "Exposed Secret", Version: "HIDDEN", Location: "worker.py:44", RiskLevel: "High",
	})

	d := Compute(from, to, register(), register())
	if len(d.Dependencies.Added) != 1 || len(d.Dependencies.Removed) != 1 {
		t.Errorf("secrets at different locations must be distinct findings: %+v", d.Dependencies)
	}
}

// --- Posture --------------------------------------------------------------

func TestCompute_ComplianceRegression(t *testing.T) {
	d := Compute(
		bom("Passed"),
		bom("Action Required (Annex IV Documentation Missing)"),
		register(), register(),
	)
	if d.ComplianceChange == nil {
		t.Fatal("no compliance change recorded")
	}
	if !d.ComplianceChange.Regressed {
		t.Error("Passed -> Action Required is a regression")
	}
	if !d.Summary.Regressed {
		t.Error("summary must flag the regression for alerting")
	}
}

func TestCompute_ComplianceImprovement(t *testing.T) {
	d := Compute(
		bom("Action Required (Annex IV Documentation Missing)"),
		bom("Passed"),
		register(), register(),
	)
	if d.ComplianceChange == nil || d.ComplianceChange.Regressed {
		t.Errorf("Action Required -> Passed must not read as a regression: %+v", d.ComplianceChange)
	}
	if d.Summary.Regressed {
		t.Error("an improving scan must not alert")
	}
}

func TestCompute_PolicyBlockRanksWorstAndUnknownIsNotClean(t *testing.T) {
	blocked := Compute(bom("Action Required (x)"), bom("Blocked by Policy"), register(), register())
	if blocked.ComplianceChange == nil || !blocked.ComplianceChange.Regressed {
		t.Error("Action Required -> Blocked by Policy is a regression")
	}
	// An unrecognised status must not be silently treated as clean.
	unknown := Compute(bom("Passed"), bom("Something New"), register(), register())
	if unknown.ComplianceChange == nil || !unknown.ComplianceChange.Regressed {
		t.Error("Passed -> unrecognised status should be treated as a regression, not ignored")
	}
}

func TestCompute_HighRiskAdditionRegresses(t *testing.T) {
	// Posture can stay "Action Required" across both scans while a new
	// high-risk component appears. That still deserves an alert.
	from := bom("Action Required (x)", dep("torch", "2.4.0", "Python (pip)", "High"))
	to := bom("Action Required (x)",
		dep("torch", "2.4.0", "Python (pip)", "High"),
		dep("vllm", "0.6.0", "Python (pip)", "High"),
	)

	d := Compute(from, to, register(), register())
	if d.Summary.HighRiskAdded != 1 {
		t.Errorf("HighRiskAdded = %d, want 1", d.Summary.HighRiskAdded)
	}
	if !d.Summary.Regressed {
		t.Error("a new high-risk component must flag as a regression even with unchanged posture")
	}
}

// --- Register deltas ------------------------------------------------------

func TestCompute_NewAndResolvedFindings(t *testing.T) {
	before := register(types.RiskFinding{Component: "torch"})
	after := register(types.RiskFinding{Component: "langchain"})

	d := Compute(bom("Passed"), bom("Passed"), before, after)

	if len(d.Risk.NewFindings) != 1 || d.Risk.NewFindings[0].Component != "langchain" {
		t.Errorf("NewFindings = %+v", d.Risk.NewFindings)
	}
	if len(d.Risk.ResolvedFindings) != 1 || d.Risk.ResolvedFindings[0].Component != "torch" {
		t.Errorf("ResolvedFindings = %+v", d.Risk.ResolvedFindings)
	}
}

func TestCompute_IdenticalScansProduceEmptyDrift(t *testing.T) {
	// The common case by far: most commits change nothing about the AI
	// surface. That must produce a quiet, unambiguous "nothing changed".
	b := bom("Passed", dep("torch", "2.4.0", "Python (pip)", "High"))
	reg := register(types.RiskFinding{Component: "torch"})

	d := Compute(b, b, reg, reg)

	if d.Summary != (types.DriftSummary{}) {
		t.Errorf("identical scans produced drift: %+v", d.Summary)
	}
	if d.ComplianceChange != nil {
		t.Errorf("identical scans produced a compliance change: %+v", d.ComplianceChange)
	}
}

func TestCompute_IsDeterministic(t *testing.T) {
	// Map iteration order must not leak into the output: this record is
	// persisted and shown in an audit context.
	from := bom("Passed", dep("zeta", "1.0", "Python (pip)", "Low"))
	to := bom("Passed",
		dep("alpha", "1.0", "Python (pip)", "High"),
		dep("mid", "1.0", "Python (pip)", "Low"),
		dep("zulu", "1.0", "Python (pip)", "Low"),
	)

	first := Compute(from, to, register(), register())
	for i := 0; i < 20; i++ {
		got := Compute(from, to, register(), register())
		for j := range got.Dependencies.Added {
			if got.Dependencies.Added[j].Name != first.Dependencies.Added[j].Name {
				t.Fatalf("ordering varied between runs: %v vs %v",
					first.Dependencies.Added, got.Dependencies.Added)
			}
		}
	}
	if first.Dependencies.Added[0].Name != "alpha" {
		t.Errorf("Added not sorted by name: %+v", first.Dependencies.Added)
	}
}
