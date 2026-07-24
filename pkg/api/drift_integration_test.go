//go:build integration

// Integration tests for /api/drift (Wave 18).
//
// The unit tests in pkg/drift cover the comparison logic. These cover
// what only a database can exercise: picking the right *pair* of scans,
// tenant scoping, and the "not enough history yet" state that every new
// account starts in.
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"aicap/pkg/types"
)

// getDriftAt fetches /api/drift with an optional ?to= parameter.
func getDriftAt(t *testing.T, srvURL, jwt, toHash string) map[string]any {
	t.Helper()
	url := srvURL + "/api/drift"
	if toHash != "" {
		url += "?to=" + toHash
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("drift status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode drift: %v", err)
	}
	return out
}

// driftBody digs the drift object out of the envelope.
func driftBody(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	if avail, _ := resp["available"].(bool); !avail {
		t.Fatalf("drift not available: %v", resp)
	}
	d, ok := resp["drift"].(map[string]any)
	if !ok {
		t.Fatalf("no drift object in response: %v", resp)
	}
	return d
}

func TestDrift_NeedsTwoScans(t *testing.T) {
	// The state every new account is in. It must be a plain answer, not
	// an error the dashboard has to special-case.
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000800"
	token := seedAPIKey(t, db, userID, "pro")
	jwt := mintJWT(t, userID, "o@example.com")

	resp := getDriftAt(t, srv.URL, jwt, "")
	if avail, _ := resp["available"].(bool); avail {
		t.Errorf("drift reported available with no scans: %v", resp)
	}

	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "only-one"})

	resp = getDriftAt(t, srv.URL, jwt, "")
	if avail, _ := resp["available"].(bool); avail {
		t.Errorf("drift reported available with a single scan: %v", resp)
	}
	if reason, _ := resp["reason"].(string); reason == "" {
		t.Error("no reason given for unavailable drift")
	}
}

func TestDrift_ComparesTwoMostRecentScans(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000801"
	token := seedAPIKey(t, db, userID, "pro")
	jwt := mintJWT(t, userID, "o@example.com")

	saveProof(t, srv, token, types.AIBOM{
		ProjectName: "p", CommitSha: "c1", Compliance: "Passed",
		Dependencies: []types.AIDependency{
			{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	})
	saveProof(t, srv, token, types.AIBOM{
		ProjectName: "p", CommitSha: "c2", Compliance: "Passed",
		Dependencies: []types.AIDependency{
			{Name: "torch", Version: "2.6.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
			{Name: "vllm", Version: "0.6.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	})

	d := driftBody(t, getDriftAt(t, srv.URL, jwt, ""))

	from, _ := d["from"].(map[string]any)
	to, _ := d["to"].(map[string]any)
	if from["commitSha"] != "c1" || to["commitSha"] != "c2" {
		t.Errorf("compared the wrong pair: from=%v to=%v", from["commitSha"], to["commitSha"])
	}

	summary, _ := d["summary"].(map[string]any)
	if added, _ := summary["dependenciesAdded"].(float64); added != 1 {
		t.Errorf("dependenciesAdded = %v, want 1", summary["dependenciesAdded"])
	}
	if changed, _ := summary["versionsChanged"].(float64); changed != 1 {
		t.Errorf("versionsChanged = %v, want 1 (torch 2.4.0 -> 2.6.0)", summary["versionsChanged"])
	}
	if hi, _ := summary["highRiskAdded"].(float64); hi != 1 {
		t.Errorf("highRiskAdded = %v, want 1", summary["highRiskAdded"])
	}
	if regressed, _ := summary["regressed"].(bool); !regressed {
		t.Error("adding a high-risk component must flag as a regression")
	}
}

func TestDrift_ToParameterComparesAgainstPredecessor(t *testing.T) {
	// Drift for a historical point, not just the head — an auditor asking
	// "what changed at this commit?" months later.
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000802"
	token := seedAPIKey(t, db, userID, "pro")
	jwt := mintJWT(t, userID, "o@example.com")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "h1"})
	saveProof(t, srv, token, types.AIBOM{
		ProjectName: "p", CommitSha: "h2",
		Dependencies: []types.AIDependency{
			{Name: "langchain", Version: "0.2.0", Ecosystem: "Python (pip)", RiskLevel: "Medium"},
		},
	})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "h3"})

	// Find h2's hash.
	var h2Hash string
	if err := db.QueryRow(
		`SELECT crypto_hash FROM proof_drills WHERE user_id = $1 AND commit_sha = 'h2'`, userID,
	).Scan(&h2Hash); err != nil {
		t.Fatalf("read h2 hash: %v", err)
	}

	d := driftBody(t, getDriftAt(t, srv.URL, jwt, h2Hash))

	from, _ := d["from"].(map[string]any)
	to, _ := d["to"].(map[string]any)
	if from["commitSha"] != "h1" || to["commitSha"] != "h2" {
		t.Errorf("?to=h2 compared from=%v to=%v, want h1 -> h2", from["commitSha"], to["commitSha"])
	}
	summary, _ := d["summary"].(map[string]any)
	if added, _ := summary["dependenciesAdded"].(float64); added != 1 {
		t.Errorf("dependenciesAdded = %v, want 1 (langchain arrived at h2)", summary["dependenciesAdded"])
	}
}

func TestDrift_IsTenantScoped(t *testing.T) {
	// Another tenant's scans must be invisible, both as comparison
	// material and via a guessed hash.
	srv, db := setup(t)
	alice := "00000000-0000-0000-0000-000000000803"
	bob := "00000000-0000-0000-0000-000000000804"
	aliceToken := seedAPIKey(t, db, alice, "pro")
	bobToken := seedAPIKey(t, db, bob, "pro")

	saveProof(t, srv, aliceToken, types.AIBOM{ProjectName: "a", CommitSha: "a1"})
	saveProof(t, srv, aliceToken, types.AIBOM{ProjectName: "a", CommitSha: "a2"})
	saveProof(t, srv, bobToken, types.AIBOM{ProjectName: "b", CommitSha: "b1"})

	// Bob has one scan of his own; Alice's two must not fill the gap.
	resp := getDriftAt(t, srv.URL, mintJWT(t, bob, "bob@example.com"), "")
	if avail, _ := resp["available"].(bool); avail {
		t.Errorf("bob saw drift built from another tenant's scans: %v", resp)
	}

	// And Alice's hash must not resolve for Bob.
	var aliceHash string
	if err := db.QueryRow(
		`SELECT crypto_hash FROM proof_drills WHERE user_id = $1 AND commit_sha = 'a2'`, alice,
	).Scan(&aliceHash); err != nil {
		t.Fatalf("read alice hash: %v", err)
	}
	resp = getDriftAt(t, srv.URL, mintJWT(t, bob, "bob@example.com"), aliceHash)
	if avail, _ := resp["available"].(bool); avail {
		t.Errorf("bob resolved another tenant's hash: %v", resp)
	}
}

func TestDrift_RequiresAuth(t *testing.T) {
	srv, _ := setup(t)
	resp, err := http.Get(srv.URL + "/api/drift")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDrift_QuietWhenNothingChanged(t *testing.T) {
	// The common case: most commits change nothing about the AI surface.
	// A monitoring feature that cries wolf on every scan gets muted.
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000805"
	token := seedAPIKey(t, db, userID, "pro")
	jwt := mintJWT(t, userID, "o@example.com")

	deps := []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
	}
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "q1", Dependencies: deps, Compliance: "Passed"})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "p", CommitSha: "q2", Dependencies: deps, Compliance: "Passed"})

	d := driftBody(t, getDriftAt(t, srv.URL, jwt, ""))
	summary, _ := d["summary"].(map[string]any)

	for _, key := range []string{"dependenciesAdded", "dependenciesRemoved", "versionsChanged"} {
		if v, _ := summary[key].(float64); v != 0 {
			t.Errorf("%s = %v, want 0 for an unchanged scan", key, v)
		}
	}
	if regressed, _ := summary["regressed"].(bool); regressed {
		t.Error("an unchanged scan must not flag as a regression")
	}
}
