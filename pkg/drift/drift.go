// Scan-to-scan drift (Wave 18).
//
// The product is called a *continuous* AI-BOM scanner and the ledger has
// stored consecutive proof drills since Wave 4, but nothing ever compared
// two of them. Every scan was an isolated snapshot: a user could see what
// their system looked like on Tuesday and what it looked like on Friday,
// and had to spot the difference by eye.
//
// That comparison is the product's reason to exist. A one-off scan is a
// point-in-time audit, which a consultant can also produce; what a
// consultant cannot produce is "a CVE was published this morning against
// a dependency you have not touched in four months". Article 72 of the
// AI Act requires providers of high-risk systems to actively collect and
// review experience with the system across its lifetime — a per-commit
// record of what changed, and what changed *underneath* you, is exactly
// the evidence that obligation asks for.
//
// Everything here is a pure function over two BOMs and two risk
// registers. No I/O, no database: the API layer loads two proof-drill
// rows and calls Compute, and the same code can later diff a local scan
// against a stored baseline in the CLI.

package drift

import (
	"sort"
	"strings"

	"aicap/pkg/types"
)

// Compute diffs two scans and reports what changed between them.
//
// `from` is the earlier scan, `to` the later one. Callers that pass them
// the wrong way round get a coherent but inverted answer — the function
// has no way to tell which is older, since a BOM carries no timestamp.
func Compute(from, to types.AIBOM, fromReg, toReg types.RiskRegister) types.Drift {
	d := types.Drift{
		From: types.DriftEndpoint{CommitSha: from.CommitSha},
		To:   types.DriftEndpoint{CommitSha: to.CommitSha},
	}

	d.Dependencies = diffDependencies(from.Dependencies, to.Dependencies)
	d.Risk = diffRisk(fromReg, toReg)

	if from.Compliance != to.Compliance {
		d.ComplianceChange = &types.ComplianceChange{
			From:      from.Compliance,
			To:        to.Compliance,
			Regressed: postureRank(to.Compliance) > postureRank(from.Compliance),
		}
	}

	d.Summary = types.DriftSummary{
		DependenciesAdded:   len(d.Dependencies.Added),
		DependenciesRemoved: len(d.Dependencies.Removed),
		VersionsChanged:     len(d.Dependencies.VersionChanged),
		NewAdvisories:       countAdvisories(d.Risk.NewAdvisories),
		NewFindings:         len(d.Risk.NewFindings),
		ResolvedFindings:    len(d.Risk.ResolvedFindings),
	}
	for _, dep := range d.Dependencies.Added {
		if dep.RiskLevel == "High" {
			d.Summary.HighRiskAdded++
		}
	}
	// "Regressed" is what a monitoring dashboard alerts on, so it is
	// deliberately broad: a worse compliance posture, a newly high-risk
	// component, or a new advisory against something already present.
	d.Summary.Regressed = (d.ComplianceChange != nil && d.ComplianceChange.Regressed) ||
		d.Summary.HighRiskAdded > 0 ||
		d.Summary.NewAdvisories > 0

	return d
}

// depKey is the identity used to decide whether a component in one scan
// is "the same component" in the other.
//
// Package name alone — deliberately not name+ecosystem. A project that
// migrates requirements.txt to poetry.lock, or adds a lockfile alongside
// its manifest, changes every ecosystem label without changing a single
// dependency; keying on the label would report the entire BOM as removed
// and re-added. The resulting noise would train users to ignore the
// feature, which is worse than the small chance of conflating a PyPI
// package with an identically named npm one.
//
// Two finding types are not packages and need their own identity:
//
//   - "Hardcoded Model" — the model identifier lives in Version, and
//     that identifier *is* the thing being tracked. Swapping gpt-4o for
//     gpt-5 must read as a change, not as an unchanged "Hardcoded Model".
//   - "Exposed Secret" — every site is its own finding. Value is
//     redacted, so location is the only identity available.
func depKey(dep types.AIDependency) string {
	switch dep.Name {
	case "Hardcoded Model":
		return "model:" + strings.ToLower(dep.Version)
	case "Exposed Secret":
		return "secret:" + dep.Location
	}
	return "pkg:" + strings.ToLower(dep.Name)
}

func diffDependencies(from, to []types.AIDependency) types.DependencyDrift {
	fromByKey := indexDeps(from)
	toByKey := indexDeps(to)

	out := types.DependencyDrift{}

	for key, dep := range toByKey {
		prev, existed := fromByKey[key]
		if !existed {
			out.Added = append(out.Added, dep)
			continue
		}
		// Present in both — report a version move when we can see one.
		// Placeholder versions ("imported", "local") are not versions and
		// a transition between them says nothing an engineer can act on,
		// so those are ignored rather than reported as churn.
		if prev.Version != dep.Version && isRealVersion(prev.Version) && isRealVersion(dep.Version) {
			out.VersionChanged = append(out.VersionChanged, types.VersionChange{
				Name:        dep.Name,
				Ecosystem:   dep.Ecosystem,
				FromVersion: prev.Version,
				ToVersion:   dep.Version,
			})
		}
	}

	for key, dep := range fromByKey {
		if _, stillThere := toByKey[key]; !stillThere {
			out.Removed = append(out.Removed, dep)
		}
	}

	sortDeps(out.Added)
	sortDeps(out.Removed)
	sort.Slice(out.VersionChanged, func(i, j int) bool {
		return out.VersionChanged[i].Name < out.VersionChanged[j].Name
	})
	return out
}

// indexDeps collapses a BOM's dependency list to one entry per identity.
// The same package legitimately appears several times (a manifest and a
// lockfile, an import and a requirements pin); for drift purposes those
// are one component. The entry carrying a concrete version wins, since
// that is the one a version comparison can use.
func indexDeps(deps []types.AIDependency) map[string]types.AIDependency {
	out := make(map[string]types.AIDependency, len(deps))
	for _, dep := range deps {
		key := depKey(dep)
		existing, seen := out[key]
		if !seen || (!isRealVersion(existing.Version) && isRealVersion(dep.Version)) {
			out[key] = dep
		}
	}
	return out
}

// isRealVersion reports whether a version string is a concrete version
// rather than one of the scanner's placeholders ("imported", "local",
// "docker-install", "HIDDEN", "unknown").
func isRealVersion(v string) bool {
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "unknown", "imported", "local", "docker-image", "docker-install",
		"docker-layer", "hidden", "latest":
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

func diffRisk(from, to types.RiskRegister) types.RiskDrift {
	fromByComponent := map[string]types.RiskFinding{}
	for _, f := range from.Findings {
		fromByComponent[strings.ToLower(f.Component)] = f
	}
	toByComponent := map[string]types.RiskFinding{}
	for _, f := range to.Findings {
		toByComponent[strings.ToLower(f.Component)] = f
	}

	out := types.RiskDrift{}

	for name, f := range toByComponent {
		prev, existed := fromByComponent[name]
		if !existed {
			out.NewFindings = append(out.NewFindings, f)
			continue
		}
		// The signal this whole package exists for: advisories that
		// appeared against a component the project did not touch. Nobody
		// changed anything; the world changed underneath them. This is
		// the case a point-in-time audit structurally cannot catch.
		if fresh := newAdvisories(prev.LiveVulns, f.LiveVulns); len(fresh) > 0 {
			out.NewAdvisories = append(out.NewAdvisories, types.AdvisoryDelta{
				Component: f.Component,
				Version:   f.Version,
				Vulns:     fresh,
			})
		}
	}

	for name, f := range fromByComponent {
		if _, stillThere := toByComponent[name]; !stillThere {
			out.ResolvedFindings = append(out.ResolvedFindings, f)
		}
	}

	sort.Slice(out.NewFindings, func(i, j int) bool {
		return out.NewFindings[i].Component < out.NewFindings[j].Component
	})
	sort.Slice(out.ResolvedFindings, func(i, j int) bool {
		return out.ResolvedFindings[i].Component < out.ResolvedFindings[j].Component
	})
	sort.Slice(out.NewAdvisories, func(i, j int) bool {
		return out.NewAdvisories[i].Component < out.NewAdvisories[j].Component
	})
	return out
}

// newAdvisories returns advisories present in `to` but not in `from`,
// compared by advisory ID.
func newAdvisories(from, to []types.LiveVuln) []types.LiveVuln {
	seen := make(map[string]bool, len(from))
	for _, v := range from {
		seen[v.ID] = true
	}
	var fresh []types.LiveVuln
	for _, v := range to {
		if !seen[v.ID] {
			fresh = append(fresh, v)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].ID < fresh[j].ID })
	return fresh
}

func countAdvisories(deltas []types.AdvisoryDelta) int {
	n := 0
	for _, d := range deltas {
		n += len(d.Vulns)
	}
	return n
}

// postureRank orders compliance statuses from best to worst so a change
// between them can be classified as an improvement or a regression.
// Unknown statuses rank between "Passed" and "Action Required": a status
// this code does not recognise should not be silently treated as clean.
func postureRank(status string) int {
	switch {
	case status == "Passed":
		return 0
	case strings.HasPrefix(status, "Blocked by Policy"):
		return 3
	case strings.HasPrefix(status, "Action Required"):
		return 2
	default:
		return 1
	}
}

func sortDeps(deps []types.AIDependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
}
