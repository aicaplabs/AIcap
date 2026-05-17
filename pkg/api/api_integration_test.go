//go:build integration

// Integration tests for pkg/api. Kept behind the `integration` build tag
// because they require a reachable Postgres. Run with:
//
//   TEST_DATABASE_URL=postgres://aicap:aicap@localhost:5432/aicap?sslmode=disable \
//     go test -tags=integration ./pkg/api/...
//
// `docker compose up -d db` from the repo root starts a matching database.
// The default `go test ./...` path ignores these so laptops without Docker
// still get a clean unit-test run.
package api_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"aicap/pkg/api"
	"aicap/pkg/migrate"
	"aicap/pkg/types"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/stripe/stripe-go/v79/webhook"
)

const jwtSecret = "integration-test-secret-do-not-use-in-prod"

// setup brings up a full backend against TEST_DATABASE_URL: applies
// migrations, clears any prior test data, returns the configured
// httptest.Server and db handle. Each test calls this to get an isolated
// environment — tests share the same schema but truncate their tables so
// they don't see each other's rows.
func setup(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	if err := migrate.Apply(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Wipe every table this test suite touches. TRUNCATE … CASCADE handles
	// the FK between proof_drills and projects, and RESTART IDENTITY zeroes
	// any sequence so test assertions that depend on row counts are stable.
	if _, err := db.Exec(`TRUNCATE proof_drills, projects, api_keys, stripe_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	t.Setenv("SUPABASE_JWT_SECRET", jwtSecret)
	t.Setenv("VITE_FRONTEND_URL", "https://app.example.com")
	// Pass isCloudSaaS=true so auth middleware is wired in, matching prod.
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, db, true)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})
	return srv, db
}

func mintJWT(t *testing.T, sub, email string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":   sub,
		"email": email,
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// seedAPIKey inserts a Pro API key for `userID` and returns the raw token the
// CLI would present. After Wave 3b the database only stores the SHA-256 hash
// (column: token_hash) — we hash at seed time, then hand the plaintext back
// so the test can put it in an Authorization header. A deterministic token
// string per user_id keeps assertions stable across runs.
func seedAPIKey(t *testing.T, db *sql.DB, userID, tier string) string {
	t.Helper()
	token := fmt.Sprintf("aicap_pro_sk_test_%s", userID)
	sum := sha256.Sum256([]byte(token))
	hashed := hex.EncodeToString(sum[:])
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, token_hash, subscription_tier) VALUES ($1, $2, $3)`,
		userID, hashed, tier,
	); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	return token
}

// TestHealthz_OK is the smoke test — if this fails, everything below is
// suspect (wiring, DB connectivity, migration runner, route registration).
func TestHealthz_OK(t *testing.T) {
	srv, _ := setup(t)
	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s status = %d, want 200", path, resp.StatusCode)
		}
	}
}

// TestReadyz_FailsWhenDBDown verifies the orchestrator contract: if the DB
// is unreachable we return 503 on /readyz (pull out of LB) but /livez still
// returns 200 (don't restart the pod for a transient DB blip).
func TestReadyz_FailsWhenDBDown(t *testing.T) {
	srv, db := setup(t)
	// Close the underlying DB so Ping fails. The httptest server keeps
	// serving; only the readiness dependency goes away.
	db.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/livez")
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/livez status = %d, want 200 (liveness must not depend on DB)", resp.StatusCode)
	}
}

// TestCORSPreflight_NoAuthRejection is the regression test for the Wave 1
// CORS bug: the browser sends OPTIONS without Authorization, and earlier
// versions of the middleware returned 401, breaking every cross-origin call.
func TestCORSPreflight_NoAuthRejection(t *testing.T) {
	srv, _ := setup(t)
	for _, path := range []string{"/api/create-checkout-session", "/api/history", "/api/save-proof"} {
		req, _ := http.NewRequest(http.MethodOptions, srv.URL+path, nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("preflight %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("%s: preflight returned 401 — CORS will break", path)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
			t.Errorf("%s: missing Access-Control-Allow-Origin on preflight", path)
		}
	}
}

// TestSaveProof_RequiresAPIKey proves the route is guarded — an unauthed
// POST gets 401, not a "thanks, saved!" for a phantom user.
func TestSaveProof_RequiresAPIKey(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof",
		bytes.NewBufferString(`{"ProjectName":"demo","CommitSha":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestSaveProof_HappyPath covers the dominant Pro-CLI flow: valid API key
// in, row persisted with the authenticated user's ID attached.
func TestSaveProof_HappyPath(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000001"
	token := seedAPIKey(t, db, userID, "pro")

	body := types.AIBOM{ProjectName: "demo/repo", CommitSha: "deadbeef"}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}

	// Verify the row landed with the right user_id — this is the
	// Wave 1 tenant-scoping contract.
	var gotUser string
	if err := db.QueryRow(
		`SELECT user_id::text FROM proof_drills WHERE commit_sha = $1`, "deadbeef",
	).Scan(&gotUser); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if gotUser != userID {
		t.Errorf("proof_drills.user_id = %q, want %q", gotUser, userID)
	}
}

// TestSaveProof_FreeTierQuota exercises the rolling-window rate limit:
// the 10th scan in the last 30 days succeeds, the 11th returns 402.
//
// Each iteration uses a unique commit_sha so Wave 6's (user_id, commit_sha)
// idempotency doesn't collapse them into a single logical save. Sending
// the same commit 11 times is one entry in the ledger, not eleven.
func TestSaveProof_FreeTierQuota(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000002"
	token := seedAPIKey(t, db, userID, "free")

	post := func(commit string) int {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: commit})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if got := post(fmt.Sprintf("sha-%d", i)); got != 201 {
			t.Fatalf("scan %d: status = %d, want 201", i+1, got)
		}
	}
	if got := post("sha-overflow"); got != http.StatusPaymentRequired {
		t.Errorf("scan 11: status = %d, want 402", got)
	}
}

// TestOpenAPI_Served (Wave 11): /api/openapi.json returns a valid
// OpenAPI 3.0 JSON document that lists the public endpoints. We don't
// validate every path here — that would couple the test to every
// future edit — but we assert the doc parses as JSON, advertises an
// `openapi` version, and includes the load-bearing routes.
func TestOpenAPI_Served(t *testing.T) {
	srv, _ := setup(t)
	resp, err := http.Get(srv.URL + "/api/openapi.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var doc struct {
		OpenAPI string                 `json:"openapi"`
		Paths   map[string]interface{} `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		t.Errorf("openapi version = %q, want 3.x", doc.OpenAPI)
	}
	for _, want := range []string{"/api/save-proof", "/api/me", "/api/generate-key", "/livez"} {
		if _, ok := doc.Paths[want]; !ok {
			t.Errorf("openapi.json missing path %q", want)
		}
	}
}

// TestSaveProof_RateLimitHeaders_FreeTier (Wave 11): every save-proof
// response on the free post-trial path carries X-RateLimit-Limit,
// X-RateLimit-Remaining, and X-RateLimit-Reset so CI tooling can warn
// before the quota is exhausted. Headers must ship on both the success
// and the 402-overflow responses.
func TestSaveProof_RateLimitHeaders_FreeTier(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000077"
	token := seedAPIKey(t, db, userID, "free")

	post := func(commit string) (*http.Response, error) {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: commit})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return http.DefaultClient.Do(req)
	}

	// First scan: limit=10, remaining should be 9, reset > 0.
	resp, err := post("first")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-RateLimit-Limit"); got != "10" {
		t.Errorf("X-RateLimit-Limit = %q, want 10", got)
	}
	if got := resp.Header.Get("X-RateLimit-Remaining"); got != "9" {
		t.Errorf("X-RateLimit-Remaining = %q, want 9", got)
	}
	if got := resp.Header.Get("X-RateLimit-Reset"); got == "" {
		t.Error("X-RateLimit-Reset is empty, want unix timestamp")
	}

	// Exhaust the rest of the quota — last in-window response should
	// carry remaining=0 and the 402 status.
	for i := 0; i < 9; i++ {
		r, err := post(fmt.Sprintf("fill-%d", i))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		r.Body.Close()
	}
	resp, err = post("overflow")
	if err != nil {
		t.Fatalf("overflow: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("overflow status = %d, want 402", resp.StatusCode)
	}
	if got := resp.Header.Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("overflow remaining = %q, want 0", got)
	}
	if got := resp.Header.Get("X-RateLimit-Limit"); got != "10" {
		t.Errorf("overflow limit = %q, want 10", got)
	}
}

// Pro-tier callers have no quota and shouldn't see rate-limit headers.
// The absence is the contract: CI tooling reading the headers takes
// missing headers as "unlimited".
func TestSaveProof_RateLimitHeaders_ProTierAbsent(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000078"
	token := seedAPIKey(t, db, userID, "pro")

	b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: "pro-1"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	for _, h := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("Pro tier should not emit %s, got %q", h, got)
		}
	}
}

// TestHistory_TenantScoping is the "do not leak the ledger" guarantee: two
// users each save a proof via the CLI path (API key) and read their
// dashboard via the browser path (Supabase JWT). Each /api/history call
// must see only its own row.
//
// The route swap in Wave 3b is the relevant regression: /api/history moved
// from RequireAPIKey to RequireSupabaseJWT. If that swap broke tenant
// scoping we'd see Alice's JWT returning Bob's rows.
func TestHistory_TenantScoping(t *testing.T) {
	srv, db := setup(t)
	alice := "00000000-0000-0000-0000-000000000010"
	bob := "00000000-0000-0000-0000-000000000020"
	aliceAPIKey := seedAPIKey(t, db, alice, "pro")
	bobAPIKey := seedAPIKey(t, db, bob, "pro")

	// CI path (still uses API keys): each user pushes one scan.
	for _, p := range []struct{ tok, commit string }{
		{aliceAPIKey, "alice-sha"}, {bobAPIKey, "bob-sha"},
	} {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: p.commit})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+p.tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("seed %s: %v", p.commit, err)
		}
		resp.Body.Close()
	}

	// Dashboard path (Wave 3b: Supabase JWT): Alice's history must contain
	// alice-sha and exactly one row.
	aliceJWT := mintJWT(t, alice, "alice@example.com")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+aliceJWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	defer resp.Body.Close()
	var records []types.ProofRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("alice saw %d rows, want 1 — possible tenant leak", len(records))
	}
	if records[0].CommitSha != "alice-sha" {
		t.Errorf("alice saw commit %q, want alice-sha", records[0].CommitSha)
	}
}

// TestHistory_RejectsAPIKey is the explicit regression for Wave 3b's route
// swap: a caller presenting a valid API key (CLI credential) must now be
// rejected at the dashboard endpoint. This prevents accidental regression
// back to the old model that stored raw keys in the browser.
func TestHistory_RejectsAPIKey(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000a1"
	apiKey := seedAPIKey(t, db, userID, "pro")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/history: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (API key must not authenticate dashboard routes)", resp.StatusCode)
	}
}

// TestGenerateKey_OneTimeReveal covers the Wave 3b one-time-reveal contract:
//   - First call: 201 with a plaintext aicap_pro_sk_* key in the response body.
//   - Second call (no rotation): 409 because the raw key is unrecoverable
//     and we must not silently re-issue.
//   - /api/rotate-key produces a *different* plaintext and leaves the DB
//     with exactly one row for the user (UNIQUE(user_id) enforcement).
//
// The regression we're blocking: any path that returns a raw key by reading
// it from the database. After migration 00009 the plaintext column is gone,
// so such a path would have to materialise a new key every call — which is
// exactly the silent-double-provision bug Wave 3b closed.
func TestGenerateKey_OneTimeReveal(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000b2"
	tok := mintJWT(t, userID, "b@example.com")

	call := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		var body struct{ APIKey string `json:"apiKey"` }
		json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.APIKey
	}

	status, firstKey := call("/api/generate-key")
	if status != http.StatusCreated {
		t.Fatalf("first generate-key status = %d, want 201", status)
	}
	if firstKey == "" {
		t.Fatal("first generate-key returned empty apiKey")
	}

	// Second call must refuse to re-issue — the raw key is gone from the
	// server's point of view.
	status, _ = call("/api/generate-key")
	if status != http.StatusConflict {
		t.Errorf("second generate-key status = %d, want 409", status)
	}

	// Rotation must produce a different plaintext.
	status, rotatedKey := call("/api/rotate-key")
	if status != http.StatusOK {
		t.Fatalf("rotate-key status = %d, want 200", status)
	}
	if rotatedKey == firstKey {
		t.Error("rotate-key returned the original key — rotation is a no-op")
	}

	// And the user still has exactly one row (UNIQUE(user_id) held).
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("api_keys rows for user = %d, want 1", rows)
	}
}

// TestGenerateKey_AfterCheckoutWebhook covers the handoff between the
// Stripe webhook and the frontend's post-redirect generate-key call.
// The webhook creates a Pro-tier row with NULL token_hash; the subsequent
// generate-key call must materialise the hash and preserve the 'pro' tier
// (not silently downgrade the user).
func TestGenerateKey_AfterCheckoutWebhook(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000b3"

	// Simulate the webhook's effect directly — this test is about the
	// generate-key handoff, not the webhook signature path.
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier)
		 VALUES ($1, 'cus_test_handoff', 'pro')`, userID,
	); err != nil {
		t.Fatalf("simulate webhook upsert: %v", err)
	}

	tok := mintJWT(t, userID, "handoff@example.com")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate-key", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("generate-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	// Tier must still be 'pro' — the generate-key UPSERT must not clobber
	// the subscription_tier the webhook recorded.
	var tier string
	if err := db.QueryRow(
		`SELECT subscription_tier FROM api_keys WHERE user_id = $1`, userID,
	).Scan(&tier); err != nil {
		t.Fatalf("read tier: %v", err)
	}
	if tier != "pro" {
		t.Errorf("tier after generate-key = %q, want pro (silent downgrade!)", tier)
	}
}

// TestCheckoutSession_RequiresValidJWT — a missing or bogus Supabase token
// must not reach the Stripe call. We don't verify the Stripe side here; we
// just assert the gate held.
func TestCheckoutSession_RequiresValidJWT(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/create-checkout-session",
		bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestGenerateKey_DerivesUserFromJWT — the endpoint must never trust a
// user_id in the request body. We only present a JWT; the key that gets
// issued must belong to the JWT's sub claim.
func TestGenerateKey_DerivesUserFromJWT(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000099"
	tok := mintJWT(t, userID, "u@example.com")

	// Body carries a *different* user_id. If the handler honours it we fail.
	body := `{"userID":"00000000-0000-0000-0000-0000000000ff"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate-key",
		bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 2xx", resp.StatusCode)
	}

	// The DB row must be attributed to the JWT sub, not the body claim.
	var storedUser string
	if err := db.QueryRow(
		`SELECT user_id::text FROM api_keys WHERE user_id = $1`, userID,
	).Scan(&storedUser); err != nil {
		t.Fatalf("lookup: %v (tenant confusion possible)", err)
	}
	if storedUser != userID {
		t.Errorf("api_keys.user_id = %q, want %q", storedUser, userID)
	}
}

// TestStripeWebhook_IdempotencyReplay is the contract for Wave 3's replay
// protection: Stripe delivers each event at least once, so our handler must
// treat a second delivery of the same event_id as a no-op.
//
// We drive this end-to-end through the real webhook endpoint (signature
// verification and all) rather than unit-testing the INSERT logic directly,
// because the bug we're defending against is the whole pipeline double-firing.
// A `checkout.session.completed` event is used because it has an observable
// side effect (inserts an api_keys row) — the assertion "one row after two
// deliveries" would fail loudly if the guard ever regresses.
func TestStripeWebhook_IdempotencyReplay(t *testing.T) {
	const webhookSecret = "whsec_integration_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", webhookSecret)
	srv, db := setup(t)

	userID := "00000000-0000-0000-0000-0000000000aa"
	eventID := "evt_test_idem_replay_1"

	// Minimal but valid Stripe event JSON. The handler extracts user_id from
	// metadata and customer from cs.Customer; everything else is decoration.
	// api_version must match what the installed stripe-go library expects or
	// ConstructEvent rejects the payload before it ever reaches our handler.
	payload := []byte(fmt.Sprintf(`{
		"id": %q,
		"object": "event",
		"api_version": "2024-06-20",
		"type": "checkout.session.completed",
		"data": {
			"object": {
				"id": "cs_test_idem_1",
				"object": "checkout.session",
				"customer": "cus_test_idem_1",
				"metadata": {"user_id": %q}
			}
		}
	}`, eventID, userID))

	send := func() int {
		signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
			Payload: payload,
			Secret:  webhookSecret,
		})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stripe-webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", signed.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post webhook: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First delivery: expect the full provision flow to run.
	if code := send(); code != http.StatusOK {
		t.Fatalf("first delivery status = %d, want 200", code)
	}
	var apiKeysAfter1 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&apiKeysAfter1); err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if apiKeysAfter1 != 1 {
		t.Fatalf("after first delivery: api_keys rows = %d, want 1 (side effect didn't run)", apiKeysAfter1)
	}

	// Second delivery: same event_id. The guard must short-circuit before
	// any side effect runs, so api_keys stays at exactly one row.
	if code := send(); code != http.StatusOK {
		t.Fatalf("second delivery status = %d, want 200 (idempotency should still acknowledge)", code)
	}
	var apiKeysAfter2 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&apiKeysAfter2); err != nil {
		t.Fatalf("count api_keys after replay: %v", err)
	}
	if apiKeysAfter2 != 1 {
		t.Errorf("after replay: api_keys rows = %d, want 1 — idempotency guard failed", apiKeysAfter2)
	}

	// And the stripe_events ledger records the event exactly once.
	var eventsRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events WHERE event_id = $1`, eventID).Scan(&eventsRows); err != nil {
		t.Fatalf("count stripe_events: %v", err)
	}
	if eventsRows != 1 {
		t.Errorf("stripe_events rows for %s = %d, want 1", eventID, eventsRows)
	}
}

// TestStripeWebhook_RejectsBadSignature — belt-and-braces: an attacker
// replaying a captured payload with the wrong secret must not even reach the
// idempotency logic. 400 is the correct response per Stripe's docs, and it
// prevents a bad actor from seeding fake event_ids into our stripe_events
// table to block legitimate replays.
func TestStripeWebhook_RejectsBadSignature(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_integration_test")
	srv, db := setup(t)

	payload := []byte(`{"id":"evt_bogus","object":"event","api_version":"2024-06-20","type":"checkout.session.completed","data":{"object":{}}}`)
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
		Payload: payload,
		Secret:  "whsec_not_the_real_secret",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stripe-webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", signed.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}

	// No stripe_events row must have been inserted — the signature gate is
	// strictly upstream of the idempotency INSERT.
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events WHERE event_id = 'evt_bogus'`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Errorf("stripe_events inserted on bad signature: rows = %d, want 0", rows)
	}
}

// --- Hash-chain anchoring (Wave 4) ------------------------------------------
// These tests cover migration 00010: each save-proof writes a row whose
// crypto_hash mixes in the previous row's hash, and /api/verify-chain
// walks the chain and reports tampering.

// saveProof is a small CLI-style helper used by the chain tests below to
// keep the noise down — they care about the chain shape, not request
// plumbing.
func saveProof(t *testing.T, srv *httptest.Server, token string, bom types.AIBOM) {
	t.Helper()
	b, _ := json.Marshal(bom)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save-proof: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("save-proof status = %d, want 201", resp.StatusCode)
	}
}

func getVerifyChain(t *testing.T, srv *httptest.Server, jwt string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/verify-chain", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify-chain: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify-chain status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// TestSaveProof_ChainsHashes proves that consecutive save-proof calls for
// the same user produce a linked chain: each row's prev_hash equals the
// previous row's crypto_hash, the genesis row's prev_hash is NULL, and
// subsequent crypto_hashes differ even when the BOM payload is identical
// (because prev_hash changes).
func TestSaveProof_ChainsHashes(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000100"
	token := seedAPIKey(t, db, userID, "pro")

	// Three distinct commits so Wave 6's idempotency doesn't collapse them.
	// The chain property under test is: each new row's crypto_hash mixes in
	// the previous row's, so even payload-identical BOMs produce different
	// hashes — provided commit_sha differs.
	for i := 0; i < 3; i++ {
		saveProof(t, srv, token, types.AIBOM{
			ProjectName: "demo/repo",
			CommitSha:   fmt.Sprintf("sha-%d", i),
		})
	}

	rows, err := db.Query(`
		SELECT crypto_hash, prev_hash
		FROM proof_drills
		WHERE user_id = $1
		ORDER BY created_at ASC, id ASC`, userID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var hashes []string
	var prevs []sql.NullString
	for rows.Next() {
		var h string
		var p sql.NullString
		if err := rows.Scan(&h, &p); err != nil {
			t.Fatalf("scan: %v", err)
		}
		hashes = append(hashes, h)
		prevs = append(prevs, p)
	}
	if len(hashes) != 3 {
		t.Fatalf("got %d rows, want 3", len(hashes))
	}
	if prevs[0].Valid {
		t.Errorf("genesis row has prev_hash = %q, want NULL", prevs[0].String)
	}
	for i := 1; i < 3; i++ {
		if !prevs[i].Valid {
			t.Errorf("row %d prev_hash is NULL, want chain link", i)
		} else if prevs[i].String != hashes[i-1] {
			t.Errorf("row %d prev_hash = %q, want %q", i, prevs[i].String, hashes[i-1])
		}
	}
	// Same BOM but different chain → different hashes.
	if hashes[0] == hashes[1] || hashes[1] == hashes[2] {
		t.Errorf("hashes collide despite chain links: %v", hashes)
	}
}

// TestVerifyChain_OK returns ok:true when nothing has been tampered with.
func TestVerifyChain_OK(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000101"
	token := seedAPIKey(t, db, userID, "pro")
	for i := 0; i < 3; i++ {
		saveProof(t, srv, token, types.AIBOM{ProjectName: "demo", CommitSha: fmt.Sprintf("sha-%d", i)})
	}

	got := getVerifyChain(t, srv, mintJWT(t, userID, "alice@example.com"))
	if ok, _ := got["ok"].(bool); !ok {
		t.Errorf("verify-chain: ok = %v, want true (got %v)", got["ok"], got)
	}
	if got["length"] != float64(3) {
		t.Errorf("verify-chain: length = %v, want 3", got["length"])
	}
}

// TestVerifyChain_DetectsPayloadTamper proves the value of the chain: if
// an attacker silently rewrites a historical row's payload, verify-chain
// reports the tampered hash and stops walking.
func TestVerifyChain_DetectsPayloadTamper(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000102"
	token := seedAPIKey(t, db, userID, "pro")
	for i := 0; i < 3; i++ {
		saveProof(t, srv, token, types.AIBOM{ProjectName: "demo", CommitSha: fmt.Sprintf("sha-%d", i)})
	}

	// Forge edit: rewrite the middle row's commit_sha. crypto_hash stays
	// the original, so the recomputed hash will diverge.
	if _, err := db.Exec(`
		UPDATE proof_drills SET commit_sha = 'forged'
		WHERE user_id = $1 AND commit_sha = 'sha-1'`, userID); err != nil {
		t.Fatalf("forge: %v", err)
	}

	got := getVerifyChain(t, srv, mintJWT(t, userID, "alice@example.com"))
	if ok, _ := got["ok"].(bool); ok {
		t.Errorf("verify-chain: ok = true after payload tamper, want false (got %v)", got)
	}
	if reason, _ := got["reason"].(string); reason == "" {
		t.Errorf("verify-chain: missing reason on tamper detection (got %v)", got)
	}
}

// TestVerifyChain_DetectsRowDeletion proves that deleting a middle row
// breaks the chain — the next row's prev_hash no longer matches the new
// "previous" row's crypto_hash.
func TestVerifyChain_DetectsRowDeletion(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000103"
	token := seedAPIKey(t, db, userID, "pro")
	for i := 0; i < 3; i++ {
		saveProof(t, srv, token, types.AIBOM{ProjectName: "demo", CommitSha: fmt.Sprintf("sha-%d", i)})
	}

	// Delete the middle row — chain link from row 3 → row 1 is now broken.
	if _, err := db.Exec(`
		DELETE FROM proof_drills WHERE user_id = $1 AND commit_sha = 'sha-1'`, userID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got := getVerifyChain(t, srv, mintJWT(t, userID, "alice@example.com"))
	if ok, _ := got["ok"].(bool); ok {
		t.Errorf("verify-chain: ok = true after deletion, want false (got %v)", got)
	}
}

// TestVerifyChain_PerUserChains proves chains don't cross tenants: Alice
// tampering with her own ledger doesn't change Bob's verification result.
func TestVerifyChain_PerUserChains(t *testing.T) {
	srv, db := setup(t)
	alice := "00000000-0000-0000-0000-000000000104"
	bob := "00000000-0000-0000-0000-000000000105"
	aliceTok := seedAPIKey(t, db, alice, "pro")
	bobTok := seedAPIKey(t, db, bob, "pro")
	saveProof(t, srv, aliceTok, types.AIBOM{ProjectName: "alice/demo", CommitSha: "a1"})
	saveProof(t, srv, aliceTok, types.AIBOM{ProjectName: "alice/demo", CommitSha: "a2"})
	saveProof(t, srv, bobTok, types.AIBOM{ProjectName: "bob/demo", CommitSha: "b1"})
	saveProof(t, srv, bobTok, types.AIBOM{ProjectName: "bob/demo", CommitSha: "b2"})

	// Tamper Alice's ledger only.
	if _, err := db.Exec(`
		UPDATE proof_drills SET commit_sha = 'forged'
		WHERE user_id = $1 AND commit_sha = 'a1'`, alice); err != nil {
		t.Fatalf("forge: %v", err)
	}

	aliceResult := getVerifyChain(t, srv, mintJWT(t, alice, "alice@example.com"))
	if ok, _ := aliceResult["ok"].(bool); ok {
		t.Errorf("alice: ok = true after tamper, want false")
	}
	bobResult := getVerifyChain(t, srv, mintJWT(t, bob, "bob@example.com"))
	if ok, _ := bobResult["ok"].(bool); !ok {
		t.Errorf("bob: ok = false despite untampered chain (got %v)", bobResult)
	}
}

// --- Wave 6 Phase A: idempotency + Stripe lifecycle ----------------------
//
// These tests cover three pieces of correctness work landed together:
//   1. /api/save-proof is idempotent by (user_id, commit_sha)
//   2. customer.subscription.updated reflects Stripe status into the tier
//   3. subscription.deleted / payment_failed soft-revoke (tier=free,
//      token_hash preserved)

// saveProofResp is like saveProof but returns the parsed body — Wave 6
// added cryptoHash + idempotent fields the chain tests don't care about.
func saveProofResp(t *testing.T, srv *httptest.Server, token string, bom types.AIBOM) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(bom)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("save-proof: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// TestSaveProof_IdempotentRetry: a CI retry on the same (user_id,
// commit_sha) returns 200 OK with the existing crypto_hash and creates
// no new row. Without this guard, every retry would append a duplicate
// audit entry with a different hash (BOM may differ slightly run-over-run).
func TestSaveProof_IdempotentRetry(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000200"
	token := seedAPIKey(t, db, userID, "pro")

	bom := types.AIBOM{ProjectName: "demo/repo", CommitSha: "deadbeef"}
	code1, body1 := saveProofResp(t, srv, token, bom)
	if code1 != http.StatusCreated {
		t.Fatalf("first save: status = %d, want 201", code1)
	}
	if got, _ := body1["idempotent"].(bool); got {
		t.Errorf("first save: idempotent = true, want false")
	}
	hash1, _ := body1["cryptoHash"].(string)
	if hash1 == "" {
		t.Errorf("first save: missing cryptoHash in response")
	}

	// Second call: same payload, same commit_sha, same user. Must
	// short-circuit and return the existing hash.
	code2, body2 := saveProofResp(t, srv, token, bom)
	if code2 != http.StatusOK {
		t.Errorf("retry: status = %d, want 200 (idempotent)", code2)
	}
	if got, _ := body2["idempotent"].(bool); !got {
		t.Errorf("retry: idempotent = false, want true")
	}
	hash2, _ := body2["cryptoHash"].(string)
	if hash2 != hash1 {
		t.Errorf("retry returned different hash: got %q, want %q", hash2, hash1)
	}

	// And the DB has exactly one row for (user, commit) — no append.
	var rows int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM proof_drills WHERE user_id = $1 AND commit_sha = $2`,
		userID, "deadbeef").Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("proof_drills rows = %d, want 1 (idempotency leaked)", rows)
	}
}

// TestSaveProof_DifferentCommitsAppend confirms that the idempotency
// only triggers on commit_sha matches — different commits still append
// and chain normally.
func TestSaveProof_DifferentCommitsAppend(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000201"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{ProjectName: "demo", CommitSha: "sha-1"})
	saveProof(t, srv, token, types.AIBOM{ProjectName: "demo", CommitSha: "sha-2"})

	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM proof_drills WHERE user_id = $1`, userID).Scan(&rows)
	if rows != 2 {
		t.Errorf("rows = %d, want 2 (idempotency over-fired on different commits)", rows)
	}
}

// stripeWebhookEvent posts a signed Stripe event payload and returns
// the response status. Helper because Wave 6 webhook tests reuse it.
func stripeWebhookEvent(t *testing.T, srv *httptest.Server, secret string, payload []byte) int {
	t.Helper()
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
		Payload: payload,
		Secret:  secret,
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stripe-webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", signed.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestStripeWebhook_SubscriptionUpdated_DowngradesOnPastDue: when Stripe
// flips a subscription to `past_due` (card declined, retry pending), the
// user must lose Pro privileges immediately. Without this they keep Pro
// for the full Stripe retry window (typically 3 weeks).
func TestStripeWebhook_SubscriptionUpdated_DowngradesOnPastDue(t *testing.T) {
	const secret = "whsec_integration_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", secret)
	srv, db := setup(t)

	userID := "00000000-0000-0000-0000-000000000300"
	cid := "cus_wave6_pastdue"
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier, token_hash)
		 VALUES ($1, $2, 'pro', 'hash_pro_key')`, userID, cid); err != nil {
		t.Fatalf("seed: %v", err)
	}

	payload := []byte(fmt.Sprintf(`{
		"id": "evt_sub_pastdue_1",
		"object": "event",
		"api_version": "2024-06-20",
		"type": "customer.subscription.updated",
		"data": {"object": {"id":"sub_1","object":"subscription","customer":%q,"status":"past_due"}}
	}`, cid))
	if code := stripeWebhookEvent(t, srv, secret, payload); code != http.StatusOK {
		t.Fatalf("webhook status = %d, want 200", code)
	}

	var tier, tokenHash string
	if err := db.QueryRow(
		`SELECT subscription_tier, COALESCE(token_hash, '') FROM api_keys WHERE user_id = $1`,
		userID).Scan(&tier, &tokenHash); err != nil {
		t.Fatalf("read: %v", err)
	}
	if tier != "free" {
		t.Errorf("tier = %q, want free (past_due should downgrade)", tier)
	}
	// Soft-revoke contract: the row stays, the token_hash stays. If
	// the user pays the bill, subscription.updated -> active flips them
	// back without forcing a key rotate.
	if tokenHash != "hash_pro_key" {
		t.Errorf("token_hash = %q, want it preserved through downgrade", tokenHash)
	}
}

// TestStripeWebhook_SubscriptionUpdated_RestoresOnActive: a previously-
// downgraded user pays the bill, Stripe sends `active`, we flip back to
// pro WITHOUT requiring them to regenerate their CI key.
func TestStripeWebhook_SubscriptionUpdated_RestoresOnActive(t *testing.T) {
	const secret = "whsec_integration_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", secret)
	srv, db := setup(t)

	userID := "00000000-0000-0000-0000-000000000301"
	cid := "cus_wave6_recover"
	db.Exec(
		`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier, token_hash)
		 VALUES ($1, $2, 'free', 'hash_dormant')`, userID, cid)

	payload := []byte(fmt.Sprintf(`{
		"id": "evt_sub_active_1",
		"object": "event",
		"api_version": "2024-06-20",
		"type": "customer.subscription.updated",
		"data": {"object": {"id":"sub_1","object":"subscription","customer":%q,"status":"active"}}
	}`, cid))
	if code := stripeWebhookEvent(t, srv, secret, payload); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	var tier string
	db.QueryRow(`SELECT subscription_tier FROM api_keys WHERE user_id = $1`, userID).Scan(&tier)
	if tier != "pro" {
		t.Errorf("tier after active = %q, want pro", tier)
	}
}

// TestSaveProof_PersistsRiskRegister (Wave 6 Phase B): every save-proof
// call must populate proof_drills.risk_register_state with the cross-
// referenced register computed from the BOM. The column has existed
// since migration 00002 but was never written to before this wave.
func TestSaveProof_PersistsRiskRegister(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000400"
	token := seedAPIKey(t, db, userID, "pro")

	// BOM that hits two catalogued libraries: tensorflow (High) +
	// openai (Medium) — covers both severity counters.
	saveProof(t, srv, token, types.AIBOM{
		ProjectName: "demo",
		CommitSha:   "rr-1",
		Dependencies: []types.AIDependency{
			{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
			{Name: "openai", Version: "1.12.0", Ecosystem: "Python (pip)"},
		},
	})

	var registerJSON []byte
	if err := db.QueryRow(
		`SELECT risk_register_state::text FROM proof_drills WHERE user_id = $1 AND commit_sha = $2`,
		userID, "rr-1").Scan(&registerJSON); err != nil {
		t.Fatalf("read register: %v", err)
	}
	if len(registerJSON) == 0 || string(registerJSON) == "null" {
		t.Fatalf("risk_register_state is empty/null — Wave 6 persistence regressed")
	}

	var register map[string]any
	if err := json.Unmarshal(registerJSON, &register); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, registerJSON)
	}

	summary, _ := register["summary"].(map[string]any)
	if got := summary["total"]; got != float64(2) {
		t.Errorf("summary.total = %v, want 2", got)
	}
	if got := summary["high"]; got != float64(1) {
		t.Errorf("summary.high = %v, want 1 (tensorflow)", got)
	}
	if got := summary["medium"]; got != float64(1) {
		t.Errorf("summary.medium = %v, want 1 (openai)", got)
	}

	findings, _ := register["findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	// Per-finding spot check: tensorflow entry must carry OWASP +
	// EU AI Act articles, not just a severity.
	for _, raw := range findings {
		f, _ := raw.(map[string]any)
		if f["component"] == "tensorflow" {
			if owasp, _ := f["owaspCategory"].(string); owasp == "" {
				t.Errorf("tensorflow finding missing owaspCategory: %v", f)
			}
			articles, _ := f["euAiActArticles"].([]any)
			if len(articles) == 0 {
				t.Errorf("tensorflow finding missing euAiActArticles: %v", f)
			}
		}
	}
}

// --- Wave 7e: Stripe customer portal ------------------------------------

// TestCustomerPortal_RequiresStripeCustomer: a free-tier user with no
// stripe_customer_id should get 400, not a 500 or a phantom portal
// session. The frontend hides the button in this state, but the API
// still guards in case the UI is out of sync.
func TestCustomerPortal_RequiresStripeCustomer(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000700"
	// Seed an api_keys row WITHOUT stripe_customer_id (free tier path).
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, subscription_tier, token_hash) VALUES ($1, 'free', 'free_hash')`,
		userID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	jwt := mintJWT(t, userID, "free@example.com")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/customer-portal", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no stripe customer)", resp.StatusCode)
	}
}

// TestCustomerPortal_UnauthedRejected: no JWT → 401. Belt-and-braces
// confirmation that RequireSupabaseJWT covers the route.
func TestCustomerPortal_UnauthedRejected(t *testing.T) {
	srv, _ := setup(t)
	resp, err := http.Post(srv.URL+"/api/customer-portal", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestCustomerPortal_CORSPreflight: OPTIONS must pass through unauth'd
// (Wave 1 regression). Without this, browsers can't reach the endpoint
// cross-origin.
func TestCustomerPortal_CORSPreflight(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/customer-portal", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("preflight returned 401 — CORS will break for /api/customer-portal")
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("preflight missing Access-Control-Allow-Origin")
	}
}

// TestSaveProof_AnnexIVContainsCostEstimate (Wave 7b): when the BOM
// carries a populated FinOpsCostEstimate, the saved Annex IV markdown
// must surface the per-finding cost line + the BOM-level total + the
// assumptions block. Auditors should never see the dollar figure
// without the disclaimer that disclosed the assumptions.
func TestSaveProof_AnnexIVContainsCostEstimate(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000600"
	token := seedAPIKey(t, db, userID, "pro")

	bom := types.AIBOM{
		ProjectName: "demo",
		CommitSha:   "cost-1",
		FinOps: []types.FinOpsFinding{{
			Resource: "infra.tf", Severity: "Warning",
			Description: "AWS instance detected.",
			EstimatedCost: &types.FinOpsCost{
				InstanceFamily: "p4d.", Cloud: "AWS",
				HourlyUSDLow: 32.77, HourlyUSDHigh: 32.77,
				MonthlyUSDLow: 23922.10, MonthlyUSDHigh: 23922.10,
				Description: "NVIDIA A100 40GB GPU (p4d.24xlarge)",
			},
		}},
		FinOpsCostEstimate: &types.FinOpsCostSummary{
			TotalMonthlyUSDLow:   23922.10,
			TotalMonthlyUSDHigh:  23922.10,
			Currency:             "USD",
			AssumedHoursPerMonth: 730,
			Disclaimer:           "Estimates assume 730 hours/month at on-demand list pricing.",
			CostedFindings:       1,
			UncostedFindings:     0,
		},
	}
	saveProof(t, srv, token, bom)

	var md string
	if err := db.QueryRow(
		`SELECT annex_iv_markdown FROM proof_drills WHERE user_id = $1 AND commit_sha = $2`,
		userID, "cost-1").Scan(&md); err != nil {
		t.Fatalf("read annex iv: %v", err)
	}
	for _, want := range []string{
		"Estimated cost:",
		"$32.77",
		"AWS family `p4d.`",
		"Estimated total monthly cost:",
		"1 costed finding(s)",
		"Assumptions:",
		"730 hours/month",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Annex IV missing FinOps cost line %q", want)
		}
	}
}

// TestSaveProof_AnnexIVContainsGovernance (Wave 7a): when the BOM
// carries governance signals from the IaC scan, the saved Annex IV
// markdown must surface them in § 3(c) (prompt-injection defences)
// and § 4 (HITL, Training Data, Bias Monitoring) — and the
// `[REQUIRES MANUAL INPUT]` placeholders for those four buckets must
// NOT appear, since auditors should see evidence-OR-prompt, never both.
func TestSaveProof_AnnexIVContainsGovernance(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000500"
	token := seedAPIKey(t, db, userID, "pro")

	bom := types.AIBOM{
		ProjectName: "demo",
		CommitSha:   "gov-1",
		Governance: types.GovernanceTelemetry{
			HITL: []types.GovernanceSignal{{
				Source: "k8s manifest", Location: "deploy.yaml",
				Evidence: "review-queue", Description: "HITL via k8s service.",
			}},
			TrainingData: []types.GovernanceSignal{{
				Source: "dvc", Location: "data.dvc",
				Evidence: "data.dvc", Description: "DVC training-data tracking.",
			}},
			BiasMonitoring: []types.GovernanceSignal{{
				Source: "python import", Location: "guard.py",
				Evidence: "fairlearn", Description: "Fairlearn imported.",
			}},
			PromptInjectionDefenses: []types.GovernanceSignal{{
				Source: "python import", Location: "guard.py",
				Evidence: "lakera", Description: "Lakera guardrail imported.",
			}},
		},
	}
	saveProof(t, srv, token, bom)

	var md string
	if err := db.QueryRow(
		`SELECT annex_iv_markdown FROM proof_drills WHERE user_id = $1 AND commit_sha = $2`,
		userID, "gov-1").Scan(&md); err != nil {
		t.Fatalf("read annex iv: %v", err)
	}

	for _, want := range []string{
		"HITL via k8s service.",
		"DVC training-data tracking.",
		"Fairlearn imported.",
		"Prompt-injection defences detected",
		"`lakera`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Annex IV missing governance evidence %q", want)
		}
	}
	for _, banned := range []string{
		"Human-in-the-loop (HITL) Controls:** `[REQUIRES MANUAL INPUT]`",
		"Training Data Provenance:** `[REQUIRES MANUAL INPUT]`",
		"Bias Monitoring:** `[REQUIRES MANUAL INPUT]`",
		"[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]",
	} {
		if strings.Contains(md, banned) {
			t.Errorf("Annex IV leaked placeholder %q despite signals being present", banned)
		}
	}
}

// TestSaveProof_AnnexIVContainsRiskRegister: the Annex IV markdown
// stored alongside the proof must surface the register findings.
// Auditors read the markdown — without this they don't see what
// risks were known at scan time.
func TestSaveProof_AnnexIVContainsRiskRegister(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000401"
	token := seedAPIKey(t, db, userID, "pro")

	saveProof(t, srv, token, types.AIBOM{
		ProjectName: "demo",
		CommitSha:   "rr-2",
		Dependencies: []types.AIDependency{
			{Name: "langchain", Version: "0.1.0", Ecosystem: "Python (pip)"},
		},
	})

	var md string
	db.QueryRow(
		`SELECT annex_iv_markdown FROM proof_drills WHERE user_id = $1 AND commit_sha = $2`,
		userID, "rr-2").Scan(&md)
	for _, want := range []string{
		"Cross-Referenced Risk Register",
		"langchain",
		"OWASP",
		"Article 9",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Annex IV markdown missing %q", want)
		}
	}
}

// TestStripeWebhook_SubscriptionDeleted_SoftRevoke: Wave 6 changed the
// behaviour from DELETE to UPDATE … SET tier='free'. The api_keys row
// must survive so a re-subscribe doesn't force key rotation.
func TestStripeWebhook_SubscriptionDeleted_SoftRevoke(t *testing.T) {
	const secret = "whsec_integration_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", secret)
	srv, db := setup(t)

	userID := "00000000-0000-0000-0000-000000000302"
	cid := "cus_wave6_deleted"
	db.Exec(
		`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier, token_hash)
		 VALUES ($1, $2, 'pro', 'hash_will_survive')`, userID, cid)

	payload := []byte(fmt.Sprintf(`{
		"id": "evt_sub_del_1",
		"object": "event",
		"api_version": "2024-06-20",
		"type": "customer.subscription.deleted",
		"data": {"object": {"id":"sub_1","object":"subscription","customer":%q,"status":"canceled"}}
	}`, cid))
	if code := stripeWebhookEvent(t, srv, secret, payload); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}

	var tier, tokenHash string
	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&rows)
	if rows != 1 {
		t.Fatalf("rows = %d, want 1 (soft revoke must not delete the row)", rows)
	}
	db.QueryRow(`SELECT subscription_tier, token_hash FROM api_keys WHERE user_id = $1`, userID).
		Scan(&tier, &tokenHash)
	if tier != "free" {
		t.Errorf("tier = %q, want free", tier)
	}
	if tokenHash != "hash_will_survive" {
		t.Errorf("token_hash = %q, must be preserved through soft revoke", tokenHash)
	}
}

// TestGenerateKey_SetsTrial verifies that a brand-new free-tier user gets a
// 14-day trial window recorded in trial_ends_at when they first call
// /api/generate-key.
func TestGenerateKey_SetsTrial(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000f01"
	tok := mintJWT(t, userID, "trial@example.com")

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate-key", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("generate-key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var trialEndsAt sql.NullTime
	db.QueryRow(`SELECT trial_ends_at FROM api_keys WHERE user_id = $1`, userID).Scan(&trialEndsAt)
	if !trialEndsAt.Valid {
		t.Fatal("trial_ends_at is NULL — trial was not set on generate-key")
	}
	daysUntil := int(time.Until(trialEndsAt.Time).Hours() / 24)
	if daysUntil < 13 || daysUntil > 14 {
		t.Errorf("trial_ends_at gives %d days remaining, want 13–14", daysUntil)
	}
}

// TestSaveProof_TrialBypassesQuota verifies that a free-tier user on an active
// trial can save more than 10 proof drills (the normal free-tier quota).
func TestSaveProof_TrialBypassesQuota(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000f02"
	token := seedAPIKey(t, db, userID, "free")

	// Set an active trial for this user.
	if _, err := db.Exec(
		`UPDATE api_keys SET trial_ends_at = NOW() + INTERVAL '7 days' WHERE user_id = $1`, userID,
	); err != nil {
		t.Fatalf("set trial: %v", err)
	}

	post := func(commit string) int {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "trial-demo", CommitSha: commit})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 15 scans — all should succeed because the trial bypasses the free-tier quota.
	for i := 0; i < 15; i++ {
		if got := post(fmt.Sprintf("trial-sha-%d", i)); got != 201 {
			t.Fatalf("scan %d: status = %d, want 201 (trial should bypass quota)", i+1, got)
		}
	}
}

// TestMe_ReturnsTrial verifies that /api/me includes trialDaysRemaining when
// a trial is active and omits the field when no trial is set.
func TestMe_ReturnsTrial(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000f03"
	tok := mintJWT(t, userID, "me-trial@example.com")

	getMe := func() map[string]any {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/me: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/api/me status = %d, want 200", resp.StatusCode)
		}
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		return body
	}

	// No row yet — me returns defaults with no trialDaysRemaining.
	me := getMe()
	if _, ok := me["trialDaysRemaining"]; ok {
		t.Error("/api/me should omit trialDaysRemaining when no row exists")
	}

	// Create a row with an active trial.
	seedAPIKey(t, db, userID, "free")
	db.Exec(`UPDATE api_keys SET trial_ends_at = NOW() + INTERVAL '10 days' WHERE user_id = $1`, userID)

	me = getMe()
	days, ok := me["trialDaysRemaining"]
	if !ok {
		t.Fatal("/api/me missing trialDaysRemaining for active trial")
	}
	// JSON numbers decode as float64.
	if d := int(days.(float64)); d < 9 || d > 10 {
		t.Errorf("trialDaysRemaining = %d, want 9–10", d)
	}

	// Expired trial (trial_ends_at in the past) → trialDaysRemaining == 0.
	db.Exec(`UPDATE api_keys SET trial_ends_at = NOW() - INTERVAL '1 day' WHERE user_id = $1`, userID)
	me = getMe()
	days, ok = me["trialDaysRemaining"]
	if !ok {
		t.Fatal("/api/me missing trialDaysRemaining for expired trial")
	}
	if d := int(days.(float64)); d != 0 {
		t.Errorf("expired trial: trialDaysRemaining = %d, want 0", d)
	}
}
