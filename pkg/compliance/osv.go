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
// and ecosystem-specific advisories. For each catalog-matched
// dependency we POST {package, version} to the OSV /v1/query endpoint
// and attach the returned vuln IDs to the existing RiskFinding.
//
// Failure mode: if OSV is unreachable / slow / rate-limited, we fall
// back to the curated catalog alone. The risk register STILL emits
// the finding — we just don't get the live CVE list. That keeps
// scans deterministic in CI and avoids tying compliance reporting to
// a third-party API's uptime.
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

type osvVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

// Lookup posts to /v1/query and returns the vulnerability IDs OSV
// reported. On any error (network, decode, non-2xx) we return the
// error AND an empty slice — callers fall back to the catalog-only
// finding. We deliberately don't propagate the body of OSV errors
// to the caller's logs because they can include the dep name we
// queried, which adds noise without adding signal.
func (c *OSVClient) Lookup(ctx context.Context, name, ecosystem, version string) ([]string, error) {
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
	ids := make([]string, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		ids = append(ids, v.ID)
	}
	return ids, nil
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

// EnrichWithOSV walks the BOM dependencies, looks up each one in OSV,
// and attaches live CVE/GHSA IDs to the matching RiskFinding. Pure
// post-hoc decoration: if OSV is disabled, unreachable, or returns no
// vulns, the register comes back with the same Findings slice the
// catalog computed.
//
// Concurrency: we fan out lookups via a small worker pool (5) to
// keep total scan latency reasonable. OSV's docs allow burst querying
// for individual users, but we cap concurrency to avoid getting
// throttled on a project with hundreds of deps.
//
// `ctx` controls the overall budget — a caller wanting to bound the
// whole enrichment can pass a context.WithTimeout(ctx, 5*time.Second).
func EnrichWithOSV(ctx context.Context, register *types.RiskRegister, bom types.AIBOM, client *OSVClient) {
	if register == nil || client == nil {
		return
	}
	if len(register.Findings) == 0 {
		return
	}

	// Build a quick name->finding-index lookup so workers can write
	// back into the right slot without per-finding mutex contention.
	indexByName := map[string]int{}
	for i, f := range register.Findings {
		indexByName[strings.ToLower(f.Component)] = i
	}

	// Query plan: every BOM dependency whose lower-case name appears
	// in the register. We want the OSV result for the resolved version
	// the BOM carries (lockfile or manifest), so we drive from
	// bom.Dependencies rather than from the findings (which may not
	// carry an authoritative version when the catalog entry was
	// pinned by name only).
	type job struct {
		name      string
		ecosystem string
		version   string
		findIdx   int
	}
	jobs := make([]job, 0, len(bom.Dependencies))
	for _, dep := range bom.Dependencies {
		eco := mapEcosystem(dep.Ecosystem)
		if eco == "" {
			continue
		}
		idx, ok := indexByName[strings.ToLower(dep.Name)]
		if !ok {
			continue
		}
		jobs = append(jobs, job{
			name: strings.ToLower(dep.Name), ecosystem: eco,
			version: dep.Version, findIdx: idx,
		})
	}
	if len(jobs) == 0 {
		return
	}

	const workers = 5
	jobCh := make(chan job, len(jobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				ids, err := client.Lookup(ctx, j.name, j.ecosystem, j.version)
				if err != nil || len(ids) == 0 {
					continue
				}
				mu.Lock()
				register.Findings[j.findIdx].LiveVulnIDs = mergeUnique(
					register.Findings[j.findIdx].LiveVulnIDs, ids,
				)
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)
	wg.Wait()
}

// mergeUnique appends `add` to `existing` skipping duplicates. Stable
// in the input order so test assertions can pin specific positions.
func mergeUnique(existing, add []string) []string {
	seen := make(map[string]bool, len(existing)+len(add))
	for _, s := range existing {
		seen[s] = true
	}
	out := append([]string(nil), existing...)
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
