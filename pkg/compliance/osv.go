// OSV.dev live vulnerability lookup (Wave 7f).
//
// The 2026-Q2 reassessment kept Phase 3 at ~88% because the risk
// register fed exclusively from a curated static catalog
// (pkg/compliance/vulns.json). That catalog covers the main AI
// libraries with up-to-date OWASP / MITRE / Article mappings, but
// lags real-world CVE / GHSA disclosures: a fresh CVE filed against
// `transformers` last week wouldn't show up in our findings until we
// hand-edit the catalog.
//
// This file adds a live cross-reference against OSV.dev — the open
// vulnerability database that aggregates CVE, GHSA, PYSEC, RUSTSEC,
// and ecosystem-specific advisories. For each dependency we POST
// {package, version} to the OSV /v1/query endpoint and fold the
// returned advisories into the risk register.
//
// Wave 16 changed two things about that:
//
//   - Scope. Lookups used to run only for dependencies whose name
//     already matched the ~10-entry static catalog, so the register
//     could never report a vulnerability the catalog had not
//     anticipated — the project's actually-vulnerable dependency was
//     never queried. Now every dependency with a mappable ecosystem and
//     a concrete version is checked, and one with no catalog entry but a
//     live advisory gets a finding of its own (Source: "osv").
//   - Depth. Only the vuln ID was kept and the rest of the payload
//     discarded, which told an auditor a problem existed and an engineer
//     nothing about what to do. The summary, the severity label, and
//     above all the fixed version were already in the response we
//     parsed; they are now carried through to the report.
//
// Failure mode: if OSV is unreachable / slow / rate-limited, we fall
// back to the curated catalog alone. The risk register STILL emits
// the finding — we just don't get the live advisory data. That keeps
// scans usable in CI and avoids tying compliance reporting to a
// third-party API's uptime.
//
// Configuration (env vars):
//   AICAP_OSV_DISABLED   "true" to skip OSV entirely. Default: enabled.
//   AICAP_OSV_URL        Override the OSV base URL. Default:
//                        https://api.osv.dev. Tests use this to point
//                        the client at httptest.NewServer.
//   AICAP_OSV_TIMEOUT_MS Per-call timeout in ms. Default: 1500.

package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aicap/pkg/types"
)

// OSVClient is the small wrapper around api.osv.dev's /v1/query endpoint
// that the risk-register enrichment uses. Methods on *OSVClient are
// safe for concurrent use; the embedded http.Client owns the connection
// pool.
type OSVClient struct {
	baseURL string
	client  *http.Client
}

// NewOSVClient reads AICAP_OSV_URL / AICAP_OSV_TIMEOUT_MS / AICAP_OSV_DISABLED
// and returns either a configured client or nil (when OSV is disabled).
// A nil client is the signal to skip enrichment — callers must check.
func NewOSVClient() *OSVClient {
	if strings.EqualFold(os.Getenv("AICAP_OSV_DISABLED"), "true") {
		return nil
	}
	base := os.Getenv("AICAP_OSV_URL")
	if base == "" {
		base = "https://api.osv.dev"
	}
	timeout := 1500 * time.Millisecond
	if v := os.Getenv("AICAP_OSV_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	return &OSVClient{
		baseURL: strings.TrimRight(base, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

// osvQuery is the request body for /v1/query. The OSV schema accepts
// either {package, version} or a commit hash; we always go through the
// package path since we don't carry SHA pins for our deps.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// osvVuln mirrors the subset of the OSV schema we surface. Until Wave 16
// only ID was read and everything else discarded, which made the report
// say "this component has GHSA-xxxx" and stop — the auditor learns a
// problem exists, the engineer learns nothing about what to do. Summary,
// severity, and above all the fixed version were already in the payload
// we were parsing.
type osvVuln struct {
	ID               string        `json:"id"`
	Aliases          []string      `json:"aliases"`
	Summary          string        `json:"summary"`
	Severity         []osvSeverity `json:"severity"`
	Affected         []osvAffected `json:"affected"`
	DatabaseSpecific osvDBSpecific `json:"database_specific"`
}

// osvSeverity carries a CVSS vector string in Score (not a number —
// the OSV schema puts the full vector there).
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvDBSpecific holds the per-database extras. GHSA entries publish a
// plain-word severity here ("HIGH", "MODERATE"), which is more useful to
// quote than a CVSS vector is.
type osvDBSpecific struct {
	Severity string `json:"severity"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is one point on an affected-version range. A range is an
// ordered sequence of introduced/fixed events; we care about `fixed`,
// which is the remediation target.
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// toLiveVuln flattens an OSV advisory into the record we persist.
//
// `pkgName` scopes the fixed-version search: an advisory can list
// several affected packages (a monorepo publishing multiple
// distributions), and the fix version for a sibling package would be
// actively misleading remediation advice.
func (v osvVuln) toLiveVuln(pkgName string) types.LiveVuln {
	out := types.LiveVuln{
		ID:       v.ID,
		Aliases:  v.Aliases,
		Summary:  v.Summary,
		Severity: v.DatabaseSpecific.Severity,
	}
	for _, s := range v.Severity {
		if s.Score != "" {
			out.CVSSVector = s.Score
			break
		}
	}
	out.FixedVersion = v.earliestFixFor(pkgName)
	return out
}

// earliestFixFor returns the first `fixed` version recorded for the
// named package, or "" when the advisory publishes no fix.
//
// "" is a meaningful answer, not a missing one: an unfixed advisory
// changes the remediation decision from "upgrade" to "mitigate or
// replace", so the renderer says so explicitly rather than leaving the
// cell blank.
func (v osvVuln) earliestFixFor(pkgName string) string {
	pkgName = strings.ToLower(pkgName)
	for _, aff := range v.Affected {
		if pkgName != "" && strings.ToLower(aff.Package.Name) != pkgName {
			continue
		}
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// Lookup posts to /v1/query and returns the vulnerability IDs OSV
// reported. On any error (network, decode, non-2xx) we return the
// error AND an empty slice — callers fall back to the catalog-only
// finding. We deliberately don't propagate the body of OSV errors
// to the caller's logs because they can include the dep name we
// queried, which adds noise without adding signal.
func (c *OSVClient) Lookup(ctx context.Context, name, ecosystem, version string) ([]types.LiveVuln, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("osv client not configured")
	}
	body, err := json.Marshal(osvQuery{
		Package: osvPackage{Name: name, Ecosystem: ecosystem},
		Version: version,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("osv non-200 status")
	}
	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	vulns := make([]types.LiveVuln, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		vulns = append(vulns, v.toLiveVuln(name))
	}
	return vulns, nil
}

// mapEcosystem translates AIcap's per-parser ecosystem labels (e.g.
// "Python (pip)", "Node.js (pnpm lock)", "Go (go.mod)") into the OSV
// ecosystem identifiers that api.osv.dev expects. Returns "" when we
// don't know how to map — those deps are skipped rather than queried
// with a guess.
func mapEcosystem(label string) string {
	lower := strings.ToLower(label)
	switch {
	case strings.HasPrefix(lower, "python"):
		return "PyPI"
	case strings.HasPrefix(lower, "node.js"):
		return "npm"
	case strings.HasPrefix(lower, "go ("):
		return "Go"
	}
	return ""
}

// isQueryableVersion reports whether a BOM version string is a concrete
// version we can meaningfully ask OSV about.
//
// The scanner records several non-version placeholders — "imported" for
// a bare `import torch`, "local" for a weight file on disk,
// "docker-install" for a pip line inside a Dockerfile, "unknown" for an
// unpinned requirement. Sending those to OSV is worse than skipping
// them: /v1/query with an unparseable or absent version returns every
// advisory ever filed against the package, including ones fixed long
// before the version in use. Attributing those to the project would be
// a fabricated finding in a compliance document.
//
// Skipping is the honest outcome. The static catalog finding still
// applies, and "we could not determine the version" is a visible gap
// rather than a silent guess — the same principle the Annex IV
// [REQUIRES MANUAL INPUT] placeholders follow.
func isQueryableVersion(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "unknown", "imported", "local", "docker-image", "docker-install",
		"docker-layer", "hidden", "latest", "*":
		return false
	}
	// A usable version starts with a digit ("2.4.0", "1.40.0rc1").
	return v[0] >= '0' && v[0] <= '9'
}

// EnrichWithOSV cross-references the BOM against OSV.dev and folds the
// results into the risk register.
//
// Wave 16 decoupled the query set from the static catalog. Previously a
// dependency was only looked up if its name already matched one of the
// ~10 entries in vulns.json, which meant the register could never report
// a vulnerability in anything the catalog had not anticipated — the
// project's actually-vulnerable dependency was never even queried. Now
// every dependency with a mappable ecosystem and a concrete version is
// checked, and a dependency with no catalog entry but a live advisory
// gets a finding of its own.
//
// Findings raised this way are marked Source: "osv" so an auditor can
// tell a curated risk assessment from a machine-generated one. Their
// OWASP mapping is the supply-chain category, which is what a known
// vulnerability in a third-party component actually is, and they cite
// Article 15 (accuracy, robustness and cybersecurity) rather than
// inventing a bespoke article mapping per advisory.
//
// Concurrency: lookups fan out over a small worker pool (5) to keep scan
// latency reasonable while staying well inside OSV's tolerance for burst
// querying.
//
// `ctx` controls the overall budget. When it expires, whatever came back
// is kept and the rest is skipped: partial live data plus the full
// static register beats failing the scan on a third party's latency.
func EnrichWithOSV(ctx context.Context, register *types.RiskRegister, bom types.AIBOM, client *OSVClient) {
	if register == nil || client == nil {
		return
	}

	// Existing catalog findings, indexed so a live result lands on the
	// finding it belongs to rather than creating a duplicate row.
	//
	// Keyed by (component, version), not component alone. A project can
	// legitimately carry two versions of the same package in different
	// manifests, and a name-only index sent both versions' advisories to
	// whichever row happened to be indexed — attributing a vulnerability
	// to a version that does not have it, in a compliance document.
	indexByKey := map[string]int{}
	for i, f := range register.Findings {
		indexByKey[strings.ToLower(f.Component)+"@"+f.Version] = i
	}

	type job struct {
		name      string
		ecosystem string
		version   string
		depIdx    int
	}

	// One job per distinct (name, version) pair. A dependency detected
	// in both a manifest and a lockfile must not be queried twice.
	jobs := make([]job, 0, len(bom.Dependencies))
	queued := map[string]bool{}
	for i, dep := range bom.Dependencies {
		eco := mapEcosystem(dep.Ecosystem)
		if eco == "" || !isQueryableVersion(dep.Version) {
			continue
		}
		name := strings.ToLower(dep.Name)
		key := name + "@" + dep.Version
		if queued[key] {
			continue
		}
		queued[key] = true
		jobs = append(jobs, job{name: name, ecosystem: eco, version: dep.Version, depIdx: i})
	}
	if len(jobs) == 0 {
		return
	}

	type result struct {
		job   job
		vulns []types.LiveVuln
	}

	const workers = 5
	jobCh := make(chan job, len(jobs))
	var mu sync.Mutex
	var results []result
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				vulns, err := client.Lookup(ctx, j.name, j.ecosystem, j.version)
				if err != nil || len(vulns) == 0 {
					continue
				}
				mu.Lock()
				results = append(results, result{job: j, vulns: vulns})
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)
	wg.Wait()

	// Results arrive in worker-completion order, which varies run to
	// run. Sort before applying so the persisted register and the
	// rendered Annex IV are byte-stable for identical inputs — an
	// auditable document that reshuffles itself between runs invites
	// exactly the questions this product exists to avoid.
	sort.Slice(results, func(a, b int) bool {
		if results[a].job.name != results[b].job.name {
			return results[a].job.name < results[b].job.name
		}
		return results[a].job.version < results[b].job.version
	})

	for _, res := range results {
		if idx, ok := indexByKey[res.job.name+"@"+res.job.version]; ok {
			f := &register.Findings[idx]
			f.LiveVulns = mergeVulns(f.LiveVulns, res.vulns)
			f.LiveVulnIDs = vulnIDs(f.LiveVulns)
			if f.Source == "" {
				f.Source = "catalog"
			}
			// Append the upgrade target to the curated mitigation rather
			// than replacing it. The catalog advice is a considered
			// assessment of the component's risk class and shouldn't be
			// discarded; the fix version is the immediate action, and a
			// reader scanning the mitigation list should not have to
			// cross-reference the advisory block to find it.
			if fix := remediationAdvice(f.LiveVulns); strings.HasPrefix(fix, "Upgrade") &&
				!strings.Contains(f.Mitigation, "Upgrade to a fixed version") {
				f.Mitigation = strings.TrimRight(f.Mitigation, " .") + ". " + fix
			}
			continue
		}

		// No catalog entry — raise the finding from the advisory alone.
		dep := bom.Dependencies[res.job.depIdx]
		finding := types.RiskFinding{
			Component:     dep.Name,
			Version:       dep.Version,
			Ecosystem:     dep.Ecosystem,
			Severity:      severityFromVulns(res.vulns),
			OwaspCategory: "ML06:2023 AI Supply Chain Attacks",
			EUAIActArticles: []string{
				"Article 15 (Accuracy, Robustness and Cybersecurity)",
			},
			Mitigation: remediationAdvice(res.vulns),
			Rationale: "Raised from a live OSV.dev advisory for this exact version, " +
				"not from the curated catalog. Assess exploitability in context.",
			Status:      "open",
			Source:      "osv",
			LiveVulns:   res.vulns,
			LiveVulnIDs: vulnIDs(res.vulns),
		}
		register.Findings = append(register.Findings, finding)
		indexByKey[res.job.name+"@"+res.job.version] = len(register.Findings) - 1
		register.Summary.Total++
		switch finding.Severity {
		case "High":
			register.Summary.High++
		case "Medium":
			register.Summary.Medium++
		default:
			register.Summary.Low++
		}
	}
}

// severityFromVulns maps the advisories' own severity labels onto the
// register's High/Medium/Low scale. Unlabelled advisories land on
// Medium: calling an unrated vulnerability "Low" understates it, and
// calling it "High" would inflate the summary counts an auditor reads
// first.
func severityFromVulns(vulns []types.LiveVuln) string {
	best := ""
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL", "HIGH":
			return "High"
		case "MODERATE", "MEDIUM":
			best = "Medium"
		case "LOW":
			if best == "" {
				best = "Low"
			}
		}
	}
	if best == "" {
		return "Medium"
	}
	return best
}

// remediationAdvice turns the advisories' fixed versions into the one
// sentence an engineer needs. Falls back to explicit language when no
// fix is published, because "no fix available" is a different decision
// (mitigate, pin, or replace) rather than an absence of information.
func remediationAdvice(vulns []types.LiveVuln) string {
	fixes := []string{}
	seen := map[string]bool{}
	for _, v := range vulns {
		// Skip anything that isn't version-shaped. OSV records a `fixed`
		// event per affected range, and for projects that publish
		// source-range advisories that value is a git commit SHA. Telling
		// an engineer to "upgrade to
		// 432117cd1f59c76d97da2eaff55a7d758301dbc7" is not remediation
		// advice, and a heavily-advised package produced a wall of them.
		if !looksLikeVersion(v.FixedVersion) || seen[v.FixedVersion] {
			continue
		}
		seen[v.FixedVersion] = true
		fixes = append(fixes, v.FixedVersion)
	}
	if len(fixes) == 0 {
		return "No fixed version is published for the advisories affecting this component. " +
			"Assess exploitability, apply a compensating control, or plan a replacement."
	}
	// One target, not a list. Advisories against a long-lived package fix
	// on several release branches, and enumerating every one of them
	// buries the actionable answer. The highest fixed version clears all
	// of them, which is the single thing the reader needs to do.
	return "Upgrade to " + highestVersion(fixes) + " or later, then re-run the scan."
}

// looksLikeVersion filters OSV `fixed` values down to release versions.
// A version starts with a digit and is short; a git SHA is 40 hex
// characters and is not something anyone can act on.
func looksLikeVersion(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	if v[0] < '0' || v[0] > '9' {
		return false
	}
	// All-hex and long enough to be a truncated SHA rather than a version.
	if len(v) >= 12 && !strings.ContainsAny(v, ".") {
		return false
	}
	return true
}

// highestVersion returns the greatest version in the list, comparing
// numeric components left to right.
//
// Deliberately not a full semver implementation: these strings come from
// an external feed in whatever shape upstream publishes, and pre-release
// ordering rules would add failure modes without changing the answer for
// the case that matters — picking the newest of several patch releases.
// Ties on the numeric prefix fall back to string order so the result is
// always deterministic.
func highestVersion(versions []string) string {
	best := versions[0]
	for _, v := range versions[1:] {
		if compareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

func compareVersions(a, b string) int {
	aParts, bParts := versionNumbers(a), versionNumbers(b)
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		var x, y int
		if i < len(aParts) {
			x = aParts[i]
		}
		if i < len(bParts) {
			y = bParts[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return strings.Compare(a, b)
}

// versionNumbers extracts the numeric components of a version string,
// ignoring separators and any trailing qualifier ("1.2.0rc1" -> 1,2,0,1).
func versionNumbers(v string) []int {
	var out []int
	cur := -1
	for _, r := range v {
		if r >= '0' && r <= '9' {
			if cur < 0 {
				cur = 0
			}
			cur = cur*10 + int(r-'0')
			continue
		}
		if cur >= 0 {
			out = append(out, cur)
			cur = -1
		}
	}
	if cur >= 0 {
		out = append(out, cur)
	}
	return out
}

// vulnIDs projects the advisory list onto the legacy LiveVulnIDs field,
// kept populated so historical consumers of the JSONB keep working.
func vulnIDs(vulns []types.LiveVuln) []string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	return ids
}

// mergeVulns appends advisories not already present by ID. Stable in
// input order so test assertions can pin specific positions.
func mergeVulns(existing, add []types.LiveVuln) []types.LiveVuln {
	seen := make(map[string]bool, len(existing)+len(add))
	for _, v := range existing {
		seen[v.ID] = true
	}
	out := append([]types.LiveVuln(nil), existing...)
	for _, v := range add {
		if !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	return out
}
