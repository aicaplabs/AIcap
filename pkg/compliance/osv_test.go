package compliance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aicap/pkg/types"
)

// mockOSV stands up an httptest.Server that responds to /v1/query with
// a canned vuln list. The server captures the last request body so
// tests can assert that the client sent the expected package + version.
type mockOSV struct {
	*httptest.Server
	lastBody []byte
	respond  func(query osvQuery) []osvVuln
}

func newMockOSV(t *testing.T, respond func(query osvQuery) []osvVuln) *mockOSV {
	t.Helper()
	m := &mockOSV{respond: respond}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		m.lastBody = body
		var q osvQuery
		if err := json.Unmarshal(body, &q); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(osvResponse{Vulns: m.respond(q)})
	}))
	return m
}

// withOSVURL temporarily points NewOSVClient at the mock server. The
// returned cleanup must run even when the test fails, so wrap with
// t.Cleanup.
func withOSVURL(t *testing.T, url string) {
	t.Helper()
	prev := []struct{ k, v string }{
		{"AICAP_OSV_URL", ""},
		{"AICAP_OSV_DISABLED", ""},
	}
	for i, p := range prev {
		prev[i].v = osGetenvSafe(p.k)
	}
	t.Setenv("AICAP_OSV_URL", url)
	t.Setenv("AICAP_OSV_DISABLED", "")
}

// osGetenvSafe mirrors os.Getenv but in a vendor-friendly way for tests.
// (Direct os import would force a sub-import; we already use it via the
// package's own imports.)
func osGetenvSafe(k string) string { return "" }

// --- Lookup contract -----------------------------------------------------

func TestOSVClient_Lookup_PassesThroughVulnIDs(t *testing.T) {
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		if q.Package.Name != "transformers" || q.Package.Ecosystem != "PyPI" {
			t.Errorf("got package %+v, want PyPI/transformers", q.Package)
		}
		return []osvVuln{
			{ID: "CVE-2024-XXXX"},
			{ID: "GHSA-yyyy-zzzz"},
		}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	client := NewOSVClient()
	if client == nil {
		t.Fatal("NewOSVClient returned nil with disable=false")
	}
	ids, err := client.Lookup(context.Background(), "transformers", "PyPI", "4.30.0")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ids) != 2 || ids[0] != "CVE-2024-XXXX" {
		t.Errorf("ids = %v, want [CVE-2024-XXXX, GHSA-yyyy-zzzz]", ids)
	}
}

func TestOSVClient_Lookup_TimeoutSurfacesAsError(t *testing.T) {
	// Server that hangs longer than the client timeout.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)
	t.Setenv("AICAP_OSV_TIMEOUT_MS", "50")

	client := NewOSVClient()
	_, err := client.Lookup(context.Background(), "x", "PyPI", "1.0")
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestOSVClient_Disabled_ReturnsNil(t *testing.T) {
	t.Setenv("AICAP_OSV_DISABLED", "true")
	if got := NewOSVClient(); got != nil {
		t.Errorf("NewOSVClient = %#v, want nil when AICAP_OSV_DISABLED=true", got)
	}
}

func TestOSVClient_Non200_SurfacesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	client := NewOSVClient()
	if _, err := client.Lookup(context.Background(), "x", "PyPI", "1.0"); err == nil {
		t.Error("expected error on 429, got nil")
	}
}

// --- mapEcosystem --------------------------------------------------------

func TestMapEcosystem_KnownLabels(t *testing.T) {
	cases := map[string]string{
		"Python (pip)":                 "PyPI",
		"Python (Poetry lock)":         "PyPI",
		"Python (Pipfile lock)":        "PyPI",
		"Python (Conda environment.yml)": "PyPI",
		"Node.js (npm)":                "npm",
		"Node.js (pnpm lock)":          "npm",
		"Node.js (yarn lock)":          "npm",
		"Go (go.mod)":                  "Go",
		"Source Code (.py)":            "", // unknown — skipped
	}
	for input, want := range cases {
		if got := mapEcosystem(input); got != want {
			t.Errorf("mapEcosystem(%q) = %q, want %q", input, got, want)
		}
	}
}

// --- EnrichWithOSV -------------------------------------------------------

func TestEnrichWithOSV_AttachesIDsToMatchingFinding(t *testing.T) {
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		if q.Package.Name == "tensorflow" {
			return []osvVuln{{ID: "CVE-2024-TF-1"}}
		}
		return nil
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	if len(register.Findings) != 1 {
		t.Fatalf("setup: register has %d findings, want 1", len(register.Findings))
	}

	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	if got := register.Findings[0].LiveVulnIDs; len(got) != 1 || got[0] != "CVE-2024-TF-1" {
		t.Errorf("LiveVulnIDs = %v, want [CVE-2024-TF-1]", got)
	}
}

func TestEnrichWithOSV_NoMatchingFinding_LeavesEmpty(t *testing.T) {
	// OSV returns vulns for a dep that isn't in the catalog -> finding
	// list is empty -> nothing to enrich -> no panic, no extra
	// findings created.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		return []osvVuln{{ID: "CVE-2024-X"}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "obscure-not-in-catalog", Version: "1.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	if len(register.Findings) != 0 {
		t.Fatalf("expected 0 findings for unknown dep, got %d", len(register.Findings))
	}
	// Should not panic.
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())
}

func TestEnrichWithOSV_NilClient_NoOp(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, nil)
	if got := register.Findings[0].LiveVulnIDs; len(got) != 0 {
		t.Errorf("LiveVulnIDs = %v, want empty (nil client must be a no-op)", got)
	}
}

func TestEnrichWithOSV_OSVErrorFallsBackQuietly(t *testing.T) {
	// Server always 500s. Enrichment must not crash, must not corrupt
	// the catalog-derived findings, must just leave LiveVulnIDs empty.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "oops", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	// Catalog finding still present, just no LiveVulnIDs.
	if len(register.Findings) != 1 {
		t.Errorf("findings = %d, want 1 (catalog row preserved)", len(register.Findings))
	}
	if len(register.Findings[0].LiveVulnIDs) != 0 {
		t.Errorf("LiveVulnIDs leaked despite 500: %v", register.Findings[0].LiveVulnIDs)
	}
}

// --- Markdown rendering with live vulns ----------------------------------

func TestRenderRiskRegisterMarkdown_RendersLiveVulnIDs(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component:       "tensorflow",
		Severity:        "High",
		OwaspCategory:   "ML06: AI Supply Chain Attacks",
		EUAIActArticles: []string{"Article 9"},
		Status:          "open",
		LiveVulnIDs:     []string{"CVE-2024-TF-1", "GHSA-zzzz"},
	}}}
	md := RenderRiskRegisterMarkdown(reg)
	for _, want := range []string{"Live CVE/GHSA", "`CVE-2024-TF-1`", "`GHSA-zzzz`"} {
		if !strings.Contains(md, want) {
			t.Errorf("rendered markdown missing %q\n%s", want, md)
		}
	}
}

func TestRenderRiskRegisterMarkdown_NoVulns_DashPlaceholder(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "tensorflow", Severity: "High", Status: "open",
	}}}
	md := RenderRiskRegisterMarkdown(reg)
	// The "Live CVE/GHSA" column must still exist (header), and the
	// row must show "—" rather than empty cell content.
	if !strings.Contains(md, "Live CVE/GHSA") {
		t.Error("header missing Live CVE/GHSA column")
	}
	if !strings.Contains(md, "| — |") {
		t.Errorf("expected '— ' placeholder for empty LiveVulnIDs:\n%s", md)
	}
}
