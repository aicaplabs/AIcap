package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"aicap/pkg/auth"
	"aicap/pkg/compliance"
	"aicap/pkg/httplog"
	"aicap/pkg/ledger"
	"aicap/pkg/scanner"
	"aicap/pkg/types"

	"github.com/stripe/stripe-go/v79"
	billingportalsession "github.com/stripe/stripe-go/v79/billingportal/session"
	"github.com/stripe/stripe-go/v79/checkout/session"
	"github.com/stripe/stripe-go/v79/webhook"
)

//go:embed openapi.json
var openapiJSON []byte

// RegisterRoutes wires all AIcap HTTP handlers onto `mux`. `db` may be nil in
// local/headless mode — in that case the SaaS-only endpoints short-circuit to
// a 500. `isCloudSaaS` is true when SUPABASE_DB_URL was set at boot and turns
// on authentication + disables local-dev-only conveniences (db-config POST,
// filesystem scanning).
func RegisterRoutes(mux *http.ServeMux, db *sql.DB, isCloudSaaS bool) {
	// Build the CORS origin allowlist once at startup.
	// VITE_FRONTEND_URL can be a single origin or a comma-separated list.
	allowedOrigins := parseAllowedOrigins(os.Getenv("VITE_FRONTEND_URL"), isCloudSaaS)

	// Ledger signing key (Wave 17). A nil signer means signing is not
	// configured: rows are written unsigned and verification reports
	// them as such, rather than writes failing. A *malformed* key is
	// different — that is an operator who intended signing to happen, so
	// it is logged loudly rather than silently degrading to unsigned.
	ledgerSigner, err := ledger.LoadSigner()
	if err != nil && !errors.Is(err, ledger.ErrNoKey) {
		slog.Error("ledger signing key is set but unusable; entries will be written UNSIGNED",
			slog.Any("error", err))
		ledgerSigner = nil
	}
	if isCloudSaaS && !ledgerSigner.Enabled() {
		slog.Warn("ledger signing is not configured; proof-drill entries will be unsigned " +
			"and cannot be independently attributed (set AICAP_LEDGER_SIGNING_KEY)")
	}

	// cors applies consistent CORS headers for browser clients.
	// For CLI callers (no Origin header) it is a no-op.
	cors := func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return
		}
		if isAllowedOrigin(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
	}

	// withCORS guarantees CORS origin headers are appended before subsequent
	// middleware (e.g. auth validation) can intercept and throw an early HTTP error.
	withCORS := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cors(w, r)
			next(w, r)
		}
	}

	// --- Health --------------------------------------------------------------
	// Three endpoints, each answering a different question:
	//
	//   /livez   — "is the process alive?"       Always 200 if we can serve.
	//   /readyz  — "can we serve real traffic?"  200 iff dependencies are up.
	//   /healthz — legacy combined probe, same semantics as /readyz. Kept so
	//              existing Render/K8s probes don't break during rollout.
	//
	// Splitting them matters for orchestrators: a failing /livez causes the pod
	// to be restarted, while a failing /readyz only pulls it out of the load
	// balancer. If a transient DB blip were wired into a liveness probe it
	// would trigger pointless restart loops.
	livez := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
	readyz := func(w http.ResponseWriter, r *http.Request) {
		status := "ok"
		code := http.StatusOK
		if isCloudSaaS && (db == nil || db.Ping() != nil) {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"status": status})
	}
	mux.HandleFunc("/livez", livez)
	mux.HandleFunc("/readyz", readyz)
	mux.HandleFunc("/healthz", readyz)

	// --- OpenAPI spec (Wave 11) --------------------------------------------
	// Static document describing the public HTTP surface. The CLI uses it
	// for client generation; auditors use it to confirm route + auth
	// shape. Cached for 1h since the spec changes only on deploy.
	mux.HandleFunc("/api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		if r.Method == http.MethodOptions {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(openapiJSON)
	})

	// --- Local scan (dev only) ----------------------------------------------
	// /api/scan runs a filesystem scan on the server's working directory. That
	// is only safe during local development; in cloud mode we refuse to expose
	// it because scanning belongs in the CLI (which runs inside the customer's
	// CI/CD pipeline and never ships source to us).
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		if isCloudSaaS {
			http.Error(w, "Not available in cloud mode — use the AIcap CLI", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		bom := scanner.PerformScan(".")
		json.NewEncoder(w).Encode(bom)
	})

	// --- DB config (dev only) -----------------------------------------------
	// /api/db-config was a local-dev convenience that let the UI point a
	// running Go backend at any Postgres URL. In cloud mode exposing this
	// endpoint would let any anonymous caller repoint the production database,
	// so it is disabled entirely there.
	mux.HandleFunc("/api/db-config", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			return
		}

		if isCloudSaaS {
			http.Error(w, "Not available in cloud mode", http.StatusNotFound)
			return
		}

		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]bool{"connected": db != nil})
			return
		}

		if r.Method == "POST" {
			var req struct {
				URL     string `json:"url"`
				Enabled bool   `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if !req.Enabled {
				db = nil
				json.NewEncoder(w).Encode(map[string]bool{"connected": false})
				return
			}
			newDB, err := sql.Open("postgres", req.URL)
			if err == nil && newDB.Ping() == nil {
				db = newDB
				json.NewEncoder(w).Encode(map[string]bool{"connected": true})
			} else {
				http.Error(w, "Failed to connect to database", http.StatusBadRequest)
			}
		}
	})

	// --- Proof drill persistence --------------------------------------------
	// /api/save-proof is called by the CLI from CI/CD pipelines. It requires
	// a valid aicap_pro_sk_* API key, enforces per-tier rate limits, and
	// records the authenticated user's ID on each ledger row so /api/history
	// and /api/proof can filter to the caller's own projects.
	saveProof := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		tier := auth.SubscriptionTier(r)

		// Rate-limit check: rolling 30-day count of the caller's own proof
		// drills. This supersedes the old `api_keys.scans_this_month` counter,
		// which required a monthly reset job we never shipped — so free-tier
		// users hit a permanent ceiling after their first 10 scans.
		//
		// Counting rows is O(log n) per lookup thanks to the composite index
		// on (user_id, created_at) added by migration 00006. No counter means
		// no reset job, no writer contention on UPDATE, and no race where a
		// scan is recorded but the counter increment fails.
		if tier == "free" {
			// Trial users (trial_ends_at > NOW()) get Pro-equivalent access for
			// the trial window; only apply the quota to post-trial free accounts.
			var onTrial bool
			if err := db.QueryRow(
				`SELECT COALESCE(trial_ends_at > NOW(), false) FROM api_keys WHERE user_id = $1`,
				userID,
			).Scan(&onTrial); err != nil && err != sql.ErrNoRows {
				httplog.From(r.Context()).Error("trial check failed",
					slog.String("user_id", userID), slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !onTrial {
				// Single round-trip for the count + the oldest in-window
				// timestamp — the oldest scan in the rolling window is
				// what aged-out-time `X-RateLimit-Reset` keys off.
				var recent int
				var oldestUnix sql.NullInt64
				if err := db.QueryRow(`
					SELECT COUNT(*),
					       COALESCE(EXTRACT(EPOCH FROM MIN(created_at))::BIGINT, 0)
					FROM proof_drills
					WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days'`,
					userID,
				).Scan(&recent, &oldestUnix); err != nil {
					httplog.From(r.Context()).Error("rate-limit check failed",
						slog.String("user_id", userID), slog.Any("error", err))
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
				const freeLimit = 10
				// Reset = oldest scan in the rolling 30-day window aging
				// out (i.e. when one quota slot opens up). When no scans
				// have been made yet, the reset point is "right now" —
				// the user can proceed immediately.
				reset := time.Now().Unix()
				if oldestUnix.Valid && oldestUnix.Int64 > 0 {
					reset = oldestUnix.Int64 + int64(30*24*60*60)
				}
				// Headers report state AFTER this request, matching the
				// convention CI tooling expects (GitHub, Cloudflare,
				// Stripe): if the request will be admitted, the slot it
				// consumes is already deducted from Remaining.
				remaining := freeLimit - recent
				if recent < freeLimit {
					remaining = freeLimit - recent - 1
				}
				if remaining < 0 {
					remaining = 0
				}
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(freeLimit))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
				if recent >= freeLimit {
					http.Error(w, "Payment Required: Free tier limit of 10 cloud syncs per 30 days reached. Please upgrade to Pro.", http.StatusPaymentRequired)
					return
				}
			}
		}

		var bom types.AIBOM
		json.NewDecoder(r.Body).Decode(&bom)
		bomJSON, _ := json.Marshal(bom)

		var projectID string
		err := db.QueryRow(`
			INSERT INTO projects (name) VALUES ($1)
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, bom.ProjectName).Scan(&projectID)
		if err != nil {
			httplog.From(r.Context()).Error("upsert project failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		commitSha := bom.CommitSha
		if commitSha == "" {
			commitSha = "local-dev-uncommitted"
		}

		// Wave 6: build the Article 9 risk register alongside the Annex IV
		// markdown. The register is JSON-serialised into proof_drills.
		// risk_register_state so dashboards can render it without re-
		// parsing the markdown blob, and so the saved register is the
		// canonical evidence of "what we knew at scan time" for auditors.
		//
		// Wave 7f: enrich the register with live OSV.dev CVE/GHSA data
		// before persisting. We bound the call with a hard timeout
		// derived from the request context so a slow OSV doesn't block
		// the whole save-proof flow — when the budget runs out, the
		// findings still land, just without the LiveVulnIDs decoration.
		// We also re-render Annex IV from a BOM whose dependencies have
		// been updated with the enriched register so the markdown table
		// surfaces the same CVE list that the JSONB carries.
		register := compliance.ComputeRiskRegister(bom)
		if osvClient := compliance.NewOSVClient(); osvClient != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			compliance.EnrichWithOSV(ctx, &register, bom, osvClient)
			cancel()
		}
		registerJSON, err := json.Marshal(register)
		if err != nil {
			httplog.From(r.Context()).Error("marshal risk register failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		annexIVMarkdown := compliance.GenerateAnnexIVMarkdownWithRegister(bom, register)

		// Use sql.NullString so that an empty userID (possible during a
		// schema-migration race where the middleware ran on old code) is stored
		// as NULL rather than rejected as an invalid UUID literal.
		nullableUserID := sql.NullString{String: userID, Valid: userID != ""}

		// --- Hash-chain anchoring (Wave 4) -----------------------------------
		// Each row's crypto_hash mixes in the previous row's crypto_hash so
		// tampering with any historical row breaks the link to every later row.
		// Verification (GET /api/verify-chain) walks the chain and reports the
		// first divergence.
		//
		// We need the read-of-tail and the insert to be one atomic step,
		// otherwise two concurrent inserts for the same user would both
		// observe the same prev_hash and produce a forked chain. A
		// transaction-scoped advisory lock keyed on user_id serialises
		// inserts per user without holding a row lock (the genesis case has
		// no row to lock) and without serialising across users.
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			httplog.From(r.Context()).Error("begin tx failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		if userID != "" {
			// hashtextextended produces a stable bigint from the user_id string,
			// so concurrent inserts for the same user serialise on the same
			// advisory-lock key. Different users get different keys and run
			// in parallel.
			if _, err := tx.ExecContext(r.Context(),
				`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
				userID); err != nil {
				httplog.From(r.Context()).Error("advisory lock failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// --- Idempotency short-circuit (Wave 6) ------------------------------
		// A CI retry sends save-proof again with the same (user_id, commit_sha).
		// Without this check we'd append a second row whose ai_bom may differ
		// slightly (timestamps, file ordering) — duplicate audit entries with
		// different crypto_hashes is exactly the corruption we want to avoid.
		// Migration 00011 enforces uniqueness at the DB level as a backstop.
		// Inside the advisory lock so concurrent retries can't both pass the
		// check and race on the INSERT.
		if userID != "" {
			var existing string
			err := tx.QueryRowContext(r.Context(),
				`SELECT crypto_hash FROM proof_drills
				 WHERE user_id = $1 AND commit_sha = $2`,
				userID, commitSha).Scan(&existing)
			if err == nil {
				// Found — return the canonical hash without appending.
				if err := tx.Commit(); err != nil {
					httplog.From(r.Context()).Error("commit idempotent tx failed", slog.Any("error", err))
				}
				httplog.From(r.Context()).Info("save-proof idempotent retry",
					slog.String("user_id", userID), slog.String("commit_sha", commitSha))
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status":     "success",
					"cryptoHash": existing,
					"idempotent": true,
				})
				return
			}
			if err != sql.ErrNoRows {
				httplog.From(r.Context()).Error("idempotency check failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		var prevHash sql.NullString
		if userID != "" {
			err = tx.QueryRowContext(r.Context(), `
				SELECT crypto_hash FROM proof_drills
				WHERE user_id = $1
				ORDER BY created_at DESC
				LIMIT 1`, userID).Scan(&prevHash)
			if err != nil && err != sql.ErrNoRows {
				httplog.From(r.Context()).Error("read chain head failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Hash on Postgres's canonical JSONB text, not Go's json.Marshal output.
		// Postgres normalises JSONB on storage (whitespace, key ordering) so the
		// bytes returned by SELECT differ from the bytes we just marshaled. If
		// we hashed the raw Go output here, every verify-chain run would report
		// a payload-tamper false positive on its own writes. Round-tripping
		// through `$1::jsonb::text` returns exactly what verify-chain will read.
		var canonicalBOM string
		if err := tx.QueryRowContext(r.Context(),
			`SELECT $1::jsonb::text`, string(bomJSON),
		).Scan(&canonicalBOM); err != nil {
			httplog.From(r.Context()).Error("canonicalise bom failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		cryptoHash := computeChainHash(commitSha, []byte(canonicalBOM), prevHash.String)

		// Sign the entry (Wave 17). The chain alone proves internal
		// consistency; anyone with write access to this database could
		// recompute every hash and produce a chain that verifies. The
		// signing key lives in the process environment, never in the
		// database, so rewriting history requires forging a signature
		// rather than running an UPDATE.
		entry := ledger.Entry{UserID: userID, CommitSha: commitSha, CryptoHash: cryptoHash}
		signature := ledgerSigner.Sign(entry)
		signingKeyID := ledgerSigner.KeyID()

		if _, err := tx.ExecContext(r.Context(), `
			INSERT INTO proof_drills (project_id, user_id, commit_sha, ai_bom_json, risk_register_state, annex_iv_markdown, crypto_hash, prev_hash, signature, signing_key_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			projectID, nullableUserID, commitSha, bomJSON, registerJSON, annexIVMarkdown, cryptoHash,
			sql.NullString{String: prevHash.String, Valid: prevHash.Valid},
			sql.NullString{String: signature, Valid: signature != ""},
			sql.NullString{String: signingKeyID, Valid: signingKeyID != ""},
		); err != nil {
			httplog.From(r.Context()).Error("insert proof_drill failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(); err != nil {
			httplog.From(r.Context()).Error("commit tx failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "success",
			"cryptoHash": cryptoHash,
			"idempotent": false,
		})
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/save-proof", withCORS(auth.RequireAPIKey(db, saveProof)))
	} else {
		mux.HandleFunc("/api/save-proof", saveProof)
	}

	// --- History ------------------------------------------------------------
	// /api/history returns the caller's most recent proof drills. In cloud
	// mode the route is gated by the user's Supabase session JWT — not their
	// API key — because this is a dashboard read and the browser already has
	// a JWT from supabase-js. API keys are for machines (the CI scanner);
	// forcing the browser to send one would mean storing the raw key in
	// localStorage, which is exactly the exposure Wave 3b closed.
	historyHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		// Advertise the methods + headers the browser will actually use so the
		// preflight response satisfies its CORS check. Without these, Chrome
		// blocks the follow-up GET and the user sees a "Failed to fetch".
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		var rows *sql.Rows
		var err error
		if isCloudSaaS {
			userID := auth.UserID(r)
			// Strict tenant scope: the Wave 1 `OR user_id IS NULL` bridge is
			// gone, and migration 00008 makes user_id NOT NULL in the DB so
			// the predicate is exhaustive.
			rows, err = db.Query(`
				SELECT p.name, pd.commit_sha, pd.crypto_hash, pd.created_at
				FROM proof_drills pd
				JOIN projects p ON pd.project_id = p.id
				WHERE pd.user_id = $1
				ORDER BY pd.created_at DESC
				LIMIT 25`, userID)
		} else {
			rows, err = db.Query(`
				SELECT p.name, pd.commit_sha, pd.crypto_hash, pd.created_at
				FROM proof_drills pd
				JOIN projects p ON pd.project_id = p.id
				ORDER BY pd.created_at DESC
				LIMIT 25`)
		}
		if err != nil {
			httplog.From(r.Context()).Error("history query failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		records := []types.ProofRecord{}
		for rows.Next() {
			var rec types.ProofRecord
			rows.Scan(&rec.ProjectName, &rec.CommitSha, &rec.CryptoHash, &rec.Timestamp)
			records = append(records, rec)
		}
		json.NewEncoder(w).Encode(records)
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/history", withCORS(auth.RequireSupabaseJWT(historyHandler)))
	} else {
		mux.HandleFunc("/api/history", historyHandler)
	}

	// --- Single proof -------------------------------------------------------
	// /api/proof returns the Annex IV markdown for a given hash. Dashboard-
	// only read, gated by the Supabase session JWT (same rationale as
	// /api/history — browsers shouldn't carry API keys). Scoped strictly to
	// the caller's user_id so someone who guesses a crypto_hash they did not
	// produce cannot fetch another tenant's Annex IV.
	proofHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, "Missing hash parameter", http.StatusBadRequest)
			return
		}

		var markdown string
		var err error
		if isCloudSaaS {
			userID := auth.UserID(r)
			// Exhaustive user_id predicate after Wave 3b: no more NULL bridge.
			err = db.QueryRow(
				"SELECT annex_iv_markdown FROM proof_drills WHERE crypto_hash = $1 AND user_id = $2",
				hash, userID,
			).Scan(&markdown)
		} else {
			err = db.QueryRow(
				"SELECT annex_iv_markdown FROM proof_drills WHERE crypto_hash = $1", hash,
			).Scan(&markdown)
		}
		if err == sql.ErrNoRows {
			http.Error(w, "Proof drill not found", http.StatusNotFound)
			return
		}
		if err != nil {
			httplog.From(r.Context()).Error("proof query failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"markdown": markdown})
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/proof", withCORS(auth.RequireSupabaseJWT(proofHandler)))
	} else {
		mux.HandleFunc("/api/proof", proofHandler)
	}

	// --- Chain verification -------------------------------------------------
	// /api/verify-chain walks the caller's proof_drills in chronological order
	// and reports the first row whose stored crypto_hash diverges from the
	// hash recomputed from (commit_sha, ai_bom_json, prev_hash). A clean
	// chain returns {ok: true, length: N}; a tampered chain returns
	// {ok: false, brokenAt: <hash>, reason: "..."}.
	//
	// Tamper modes detected:
	//   * Row payload edited in place (recomputed hash != stored hash).
	//   * Row's prev_hash points at something other than the actual previous
	//     row's hash (chain reordering / row deletion).
	//
	// Rows written before migration 00010 have prev_hash = NULL even when
	// they aren't the genesis. We tolerate one NULL prev_hash at the chain
	// start and flag any subsequent NULL as a deletion.
	verifyChainHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		// Cast to ::text so the bytes we hash are exactly what the insert
		// path canonicalised through Postgres — see the matching cast in
		// save-proof. Without this, JSONB normalisation makes every verify
		// look like a tamper.
		// user_id is read from the row rather than taken from the request
		// context: the signature is bound to the owner recorded on the
		// entry, and in local (non-SaaS) mode there is no authenticated
		// caller to ask. Reading it back is also the stricter check —
		// a row whose user_id was altered no longer verifies.
		var rows *sql.Rows
		var err error
		if isCloudSaaS {
			rows, err = db.QueryContext(r.Context(), `
				SELECT commit_sha, ai_bom_json::text, crypto_hash, prev_hash, signature, user_id::text
				FROM proof_drills
				WHERE user_id = $1
				ORDER BY created_at ASC, id ASC`, auth.UserID(r))
		} else {
			rows, err = db.QueryContext(r.Context(), `
				SELECT commit_sha, ai_bom_json::text, crypto_hash, prev_hash, signature, user_id::text
				FROM proof_drills
				ORDER BY created_at ASC, id ASC`)
		}
		if err != nil {
			httplog.From(r.Context()).Error("verify-chain query failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var (
			length       int
			expectedPrev string
			seenFirst    bool
			signedCount  int
		)
		for rows.Next() {
			var commitSha, storedHash string
			var bomJSON []byte
			var prevHash, signature, rowUserID sql.NullString
			if err := rows.Scan(&commitSha, &bomJSON, &storedHash, &prevHash, &signature, &rowUserID); err != nil {
				httplog.From(r.Context()).Error("verify-chain scan failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			length++

			// Chain-link check (skip for the first row's NULL prev_hash, which
			// is either the genesis or a pre-Wave-4 legacy row).
			if seenFirst {
				if !prevHash.Valid {
					json.NewEncoder(w).Encode(map[string]any{
						"ok":       false,
						"brokenAt": storedHash,
						"reason":   "prev_hash is NULL on a non-genesis row (possible deletion)",
						"length":   length,
					})
					return
				}
				if prevHash.String != expectedPrev {
					json.NewEncoder(w).Encode(map[string]any{
						"ok":       false,
						"brokenAt": storedHash,
						"reason":   "prev_hash does not match previous row's crypto_hash",
						"length":   length,
					})
					return
				}
			}

			// Per-row payload check.
			recomputed := computeChainHash(commitSha, bomJSON, prevHash.String)
			if recomputed != storedHash {
				json.NewEncoder(w).Encode(map[string]any{
					"ok":       false,
					"brokenAt": storedHash,
					"reason":   "stored crypto_hash does not match recomputed hash (row payload altered)",
					"length":   length,
				})
				return
			}

			// Signature check (Wave 17). This is the check the hash chain
			// cannot make: the chain proves the rows are consistent with
			// each other, the signature proves this application wrote
			// them. A present-but-invalid signature is a hard failure —
			// somebody produced a row and attached a signature that does
			// not verify.
			//
			// A *missing* signature is not a failure. Rows written before
			// this feature, and rows written while no key was configured,
			// legitimately have none. They are counted and reported so
			// the caller can see exactly how much of the chain carries
			// cryptographic attribution rather than being told an
			// unqualified "ok".
			if signature.Valid && signature.String != "" {
				entry := ledger.Entry{
					UserID:     rowUserID.String,
					CommitSha:  commitSha,
					CryptoHash: storedHash,
				}
				if !ledgerSigner.Verify(entry, signature.String) {
					json.NewEncoder(w).Encode(map[string]any{
						"ok":       false,
						"brokenAt": storedHash,
						"reason":   "ledger signature does not verify (row not written by this service, or signed under a different key)",
						"length":   length,
					})
					return
				}
				signedCount++
			}

			expectedPrev = storedHash
			seenFirst = true
		}
		resp := map[string]any{
			"ok":            true,
			"length":        length,
			"signed":        signedCount,
			"unsigned":      length - signedCount,
			"signingKeyId":  ledgerSigner.KeyID(),
			"publicKeyPath": "/api/ledger/public-key",
		}
		// Say plainly when a chain carries no cryptographic attribution
		// at all, rather than leaving "ok: true" to imply more than it
		// means.
		if signedCount < length {
			resp["note"] = "Some entries are unsigned: they were written before ledger signing " +
				"was enabled. Unsigned entries are consistent with the chain but cannot be " +
				"attributed to this service."
		}
		json.NewEncoder(w).Encode(resp)
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/verify-chain", withCORS(auth.RequireSupabaseJWT(verifyChainHandler)))
	} else {
		mux.HandleFunc("/api/verify-chain", verifyChainHandler)
	}

	// --- Report sharing (Wave 15) --------------------------------------------
	// POST /api/share-report {hash} mints (or re-returns) the share token
	// for one of the caller's proof drills; DELETE ?hash= revokes it.
	// The token is a 256-bit capability generated server-side — possession
	// grants read access to exactly one report via /api/public/report.
	// Idempotent: sharing an already-shared report returns the existing
	// token (200) so the frontend can safely re-request the link.
	//
	// JWT-gated and user_id-scoped like /api/proof: only the owner can
	// mint or revoke, and a hash belonging to another tenant 404s.
	shareReportHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			return
		}
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}
		userID := auth.UserID(r)
		logger := httplog.From(r.Context()).With(slog.String("user_id", userID))

		switch r.Method {
		case http.MethodPost:
			var body struct {
				Hash string `json:"hash"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hash == "" {
				http.Error(w, "Missing hash", http.StatusBadRequest)
				return
			}
			var existing sql.NullString
			err := db.QueryRow(
				`SELECT share_token FROM proof_drills WHERE crypto_hash = $1 AND user_id = $2`,
				body.Hash, userID,
			).Scan(&existing)
			if err == sql.ErrNoRows {
				http.Error(w, "Proof drill not found", http.StatusNotFound)
				return
			}
			if err != nil {
				logger.Error("share-report lookup failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if existing.Valid && existing.String != "" {
				json.NewEncoder(w).Encode(map[string]string{"token": existing.String})
				return
			}
			tokenBytes := make([]byte, 32)
			if _, err := rand.Read(tokenBytes); err != nil {
				logger.Error("share-report token generation failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			token := hex.EncodeToString(tokenBytes)
			if _, err := db.Exec(
				`UPDATE proof_drills SET share_token = $1 WHERE crypto_hash = $2 AND user_id = $3`,
				token, body.Hash, userID,
			); err != nil {
				logger.Error("share-report update failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			logger.Info("report shared", slog.String("hash", body.Hash))
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"token": token})

		case http.MethodDelete:
			hash := r.URL.Query().Get("hash")
			if hash == "" {
				http.Error(w, "Missing hash parameter", http.StatusBadRequest)
				return
			}
			res, err := db.Exec(
				`UPDATE proof_drills SET share_token = NULL WHERE crypto_hash = $1 AND user_id = $2`,
				hash, userID,
			)
			if err != nil {
				logger.Error("share-report revoke failed", slog.Any("error", err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if n, _ := res.RowsAffected(); n == 0 {
				http.Error(w, "Proof drill not found", http.StatusNotFound)
				return
			}
			logger.Info("report share revoked", slog.String("hash", hash))
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
	// Cloud-only: sharing is meaningless without the hosted ledger, and
	// local mode has no JWT to scope ownership with.
	if isCloudSaaS {
		mux.HandleFunc("/api/share-report", withCORS(auth.RequireSupabaseJWT(shareReportHandler)))
	}

	// --- Public shared report (Wave 15, unauthenticated) ----------------------
	// GET /api/public/report?token=… resolves a share token minted above.
	// No auth middleware: the 256-bit token IS the credential. The response
	// deliberately carries only the report and its provenance — never
	// user_id or internal row ids.
	publicReportHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}
		token := r.URL.Query().Get("token")
		// Tokens are exactly 64 lowercase hex chars; reject malformed
		// input before it reaches the database. 404 (not 400) so probing
		// can't distinguish "bad format" from "no such report".
		if !isShareToken(token) {
			http.Error(w, "Report not found", http.StatusNotFound)
			return
		}
		var (
			markdown, commitSha, cryptoHash    string
			projectName                        sql.NullString
			signature, signingKeyID, ownerUser sql.NullString
			createdAt                          time.Time
		)
		err := db.QueryRow(
			`SELECT pd.annex_iv_markdown, pd.commit_sha, pd.crypto_hash, pd.created_at, p.name,
			        pd.signature, pd.signing_key_id, pd.user_id::text
			 FROM proof_drills pd
			 LEFT JOIN projects p ON p.id = pd.project_id
			 WHERE pd.share_token = $1`, token,
		).Scan(&markdown, &commitSha, &cryptoHash, &createdAt, &projectName,
			&signature, &signingKeyID, &ownerUser)
		if err == sql.ErrNoRows {
			http.Error(w, "Report not found", http.StatusNotFound)
			return
		}
		if err != nil {
			httplog.From(r.Context()).Error("public report query failed", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		resp := map[string]any{
			"markdown":    markdown,
			"commitSha":   commitSha,
			"cryptoHash":  cryptoHash,
			"createdAt":   createdAt.Format(time.RFC3339),
			"projectName": projectName.String,
		}

		// Attestation block (Wave 17). Without this, a shared report was
		// a page the report's own subject could have written, and the
		// recipient had no way to tell. Publishing the signature, the
		// signed message, and the key that made it is what turns the
		// share link into something an auditor can actually check —
		// including offline, with no AIcap account and no trust in this
		// endpoint beyond the public key itself.
		//
		// user_id is deliberately NOT returned: it is the tenant's
		// internal identifier and the recipient does not need it. The
		// signed message is published pre-composed instead, so the
		// verifier gets exactly the bytes to check without us disclosing
		// the tenant ID as a separate field.
		if signature.Valid && signature.String != "" {
			entry := ledger.Entry{
				UserID:     ownerUser.String,
				CommitSha:  commitSha,
				CryptoHash: cryptoHash,
			}
			resp["attestation"] = map[string]any{
				"signature":     signature.String,
				"signedMessage": base64.StdEncoding.EncodeToString(entry.Message()),
				"algorithm":     "Ed25519",
				"signingKeyId":  signingKeyID.String,
				"publicKeyPath": "/api/ledger/public-key",
				"howToVerify": "Base64-decode signedMessage and signature, fetch the Ed25519 " +
					"public key from publicKeyPath, and check the signature over those bytes. " +
					"A valid signature proves this record was produced by AIcap and has not " +
					"been altered since — including by the party that shared it with you.",
			}
		} else {
			// Say so rather than omitting the field. A recipient who sees
			// no attestation block should not have to wonder whether it
			// was absent or merely not rendered.
			resp["attestation"] = map[string]any{
				"signature": "",
				"note": "This entry is unsigned. It predates ledger signing, or signing was " +
					"not configured when it was written. Its hash chain is intact but the " +
					"record cannot be cryptographically attributed to AIcap.",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
	mux.HandleFunc("/api/public/report", publicReportHandler)

	// /api/ledger/public-key publishes the Ed25519 public key used to
	// sign ledger entries. Unauthenticated by design: a signature is
	// only useful to someone who can obtain the verifying key, and
	// requiring an account to fetch it would defeat the purpose of
	// shareable reports.
	//
	// Publishing the key here means a verifier who trusts this endpoint
	// can check any shared report. A verifier who does not should obtain
	// the key out of band — it is stable, and belongs in a DPA annex or
	// published documentation for exactly that reason.
	mux.HandleFunc("/api/ledger/public-key", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !ledgerSigner.Enabled() {
			// 200 with enabled:false, not an error: "this deployment does
			// not sign" is a legitimate, useful answer to the question.
			json.NewEncoder(w).Encode(map[string]any{
				"enabled": false,
				"note":    "Ledger signing is not configured on this deployment.",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"enabled":   true,
			"algorithm": "Ed25519",
			"publicKey": ledgerSigner.PublicKeyBase64(),
			"keyId":     ledgerSigner.KeyID(),
		})
	})

	// --- Stripe checkout ----------------------------------------------------
	// /api/create-checkout-session derives user_id + email from the verified
	// Supabase JWT; the request body is ignored for those fields so a caller
	// cannot claim someone else's identity.
	checkoutHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment and database connection", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		userEmail := auth.UserEmail(r)

		stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
		if stripe.Key == "" {
			httplog.From(r.Context()).Error("STRIPE_SECRET_KEY not set")
			http.Error(w, "Stripe secret key not configured", http.StatusInternalServerError)
			return
		}

		priceID := "price_1Pdtg1E5iL2Zl43n5G4YhI9t"
		if v := os.Getenv("STRIPE_PRICE_ID"); v != "" {
			priceID = v
		}

		frontendURL := os.Getenv("VITE_FRONTEND_URL")
		if frontendURL == "" {
			frontendURL = "http://localhost:5173"
		} else if idx := strings.Index(frontendURL, ","); idx >= 0 {
			// If an allowlist was supplied, use the first entry for redirects.
			frontendURL = strings.TrimSpace(frontendURL[:idx])
		}

		params := &stripe.CheckoutSessionParams{
			LineItems: []*stripe.CheckoutSessionLineItemParams{
				{Price: stripe.String(priceID), Quantity: stripe.Int64(1)},
			},
			Mode:          stripe.String(string(stripe.CheckoutSessionModeSubscription)),
			SuccessURL:    stripe.String(frontendURL + "/?session_id={CHECKOUT_SESSION_ID}"),
			CancelURL:     stripe.String(frontendURL + "/"),
			CustomerEmail: stripe.String(userEmail),
			Metadata:      map[string]string{"user_id": userID},
		}
		checkoutSession, err := session.New(params)
		if err != nil {
			httplog.From(r.Context()).Error("creating Stripe checkout session", slog.Any("error", err))
			// Do not leak the raw Stripe error to the browser — it can include
			// internal IDs / customer hints. A generic message is enough for
			// the client; ops has the request_id to correlate to the log line.
			http.Error(w, "Unable to create checkout session. Please try again.", http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionId": checkoutSession.ID, "url": checkoutSession.URL})
	}
	mux.HandleFunc("/api/create-checkout-session", withCORS(auth.RequireSupabaseJWT(checkoutHandler)))

	// --- Stripe customer portal (Wave 7e) -----------------------------------
	// /api/customer-portal redirects an authenticated Pro user into Stripe's
	// hosted billing portal so they can self-serve cancellations, payment-
	// method updates, and invoice history. Without this, every billing
	// change is a support ticket — and the analysis flagged it as the
	// last meaningful Phase 7 gap.
	//
	// Contract:
	//   * Reads stripe_customer_id from api_keys for the authenticated
	//     userID. If the row has no Stripe customer (free tier, no
	//     checkout completed), 400 — there's nothing to manage.
	//   * Creates a fresh BillingPortal session per call. Stripe's
	//     portal sessions are short-lived and single-use; we don't
	//     cache them.
	//   * Returns {url}. Frontend window.location.hrefs to it.
	customerPortalHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment and database connection", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		var customerID string
		err := db.QueryRow(
			`SELECT COALESCE(stripe_customer_id, '') FROM api_keys WHERE user_id = $1`,
			userID,
		).Scan(&customerID)
		if err == sql.ErrNoRows || customerID == "" {
			// Free-tier users (or Pro users where the webhook hasn't
			// fired yet) have no Stripe customer to manage. The frontend
			// should hide the button in this state, but the API guards
			// it too in case the UI gets out of sync.
			http.Error(w, "No Stripe customer associated with this account. Subscribe to Pro first.", http.StatusBadRequest)
			return
		}
		if err != nil {
			httplog.From(r.Context()).Error("read stripe_customer_id failed",
				slog.String("user_id", userID), slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
		if stripe.Key == "" {
			httplog.From(r.Context()).Error("STRIPE_SECRET_KEY not set")
			http.Error(w, "Stripe secret key not configured", http.StatusInternalServerError)
			return
		}

		// Default the return-URL to the frontend root. Stripe sends the
		// user back here after they finish in the portal; if the
		// VITE_FRONTEND_URL allowlist is comma-separated, we use the
		// first entry just like /api/create-checkout-session does.
		frontendURL := os.Getenv("VITE_FRONTEND_URL")
		if frontendURL == "" {
			frontendURL = "http://localhost:5173"
		} else if idx := strings.Index(frontendURL, ","); idx >= 0 {
			frontendURL = strings.TrimSpace(frontendURL[:idx])
		}

		params := &stripe.BillingPortalSessionParams{
			Customer:  stripe.String(customerID),
			ReturnURL: stripe.String(frontendURL + "/"),
		}
		portalSession, err := billingportalsession.New(params)
		if err != nil {
			httplog.From(r.Context()).Error("creating Stripe billing portal session",
				slog.String("user_id", userID), slog.Any("error", err))
			http.Error(w, "Unable to open billing portal. Please try again.", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"url": portalSession.URL})
	}
	mux.HandleFunc("/api/customer-portal", withCORS(auth.RequireSupabaseJWT(customerPortalHandler)))

	// --- Stripe webhook -----------------------------------------------------
	// The webhook itself is authenticated by Stripe's signature, not by us.
	// customerID() guards against nil pointer panics on test-clock events
	// where the Customer reference can be absent.
	mux.HandleFunc("/api/stripe-webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "Webhook features require cloud deployment and database connection", http.StatusInternalServerError)
			return
		}

		const MaxBodyBytes = int64(65536)
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		logger := httplog.From(r.Context())
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error("read webhook body", slog.Any("error", err))
			http.Error(w, "Unable to read request body", http.StatusServiceUnavailable)
			return
		}
		endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
		event, err := webhook.ConstructEvent(payload, r.Header.Get("stripe-signature"), endpointSecret)
		if err != nil {
			logger.Error("verify webhook signature", slog.Any("error", err))
			http.Error(w, "Webhook signature verification failed", http.StatusBadRequest)
			return
		}
		// Add event-scoped fields to every log line for the rest of this
		// request — makes it easy to pivot the log stream by stripe event.
		logger = logger.With(slog.String("stripe_event_id", event.ID), slog.String("stripe_event_type", string(event.Type)))

		// Idempotency guard. Stripe delivers each event at least once; a
		// network blip on our 200 response triggers a retry 5 minutes later.
		// We INSERT the event id up front — the PRIMARY KEY makes a second
		// attempt fail with a unique-violation, at which point we return 200
		// immediately without running the side effects a second time.
		//
		// Side effects (INSERT api_keys, UPDATE tier, DELETE api_keys) are
		// not wrapped in the same transaction as the idempotency INSERT.
		// The chosen trade-off: if we crash between "recorded the event" and
		// "ran the side effect" we lose that event's effect. That is
		// strictly safer than the inverse (running the side effect twice),
		// and Stripe's dashboard lets an operator re-send any event by hand
		// if we need recovery. Doing both in one tx would require moving the
		// INSERT to the end, which reopens the double-apply window.
		if _, err := db.Exec(
			`INSERT INTO stripe_events (event_id, event_type) VALUES ($1, $2)`,
			event.ID, event.Type,
		); err != nil {
			// pq encodes unique violations as SQLSTATE 23505. Any other
			// error is a real DB problem and deserves a 500 so Stripe
			// retries later rather than silently dropping the event.
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "23505") {
				logger.Info("duplicate webhook event — ignoring replay")
				w.WriteHeader(http.StatusOK)
				return
			}
			logger.Error("record webhook event", slog.Any("error", err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		switch event.Type {
		case "checkout.session.completed":
			var cs stripe.CheckoutSession
			if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
				logger.Error("parse checkout event", slog.Any("error", err))
				http.Error(w, "Error parsing webhook JSON", http.StatusBadRequest)
				return
			}
			userID := cs.Metadata["user_id"]
			cid := customerID(cs.Customer)
			logger.Info("checkout completed", slog.String("stripe_customer_id", cid), slog.String("user_id", userID))
			if userID == "" {
				logger.Warn("checkout.session.completed missing user_id metadata — skipping provision")
				break
			}

			// Wave 3b: the webhook no longer materialises a raw API key —
			// the user never sees it if we do, because this runs server-side.
			// Instead we upsert a row recording "Pro tier active" with a NULL
			// token_hash; when the browser lands back on the success page it
			// calls /api/generate-key, which UPDATEs the existing row with
			// a fresh hash and returns the plaintext ONCE.
			//
			// ON CONFLICT (user_id) relies on the UNIQUE(user_id) constraint
			// added in migration 00009. We only clobber the subscription
			// fields — never touch token_hash here, so a user who already
			// has a materialised key keeps it through a re-subscribe.
			if _, err := db.Exec(
				`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier)
				 VALUES ($1, $2, 'pro')
				 ON CONFLICT (user_id) DO UPDATE
				 SET stripe_customer_id = EXCLUDED.stripe_customer_id,
				     subscription_tier  = 'pro'`,
				userID, cid,
			); err != nil {
				logger.Error("mark user pro", slog.String("user_id", userID), slog.Any("error", err))
			} else {
				logger.Info("user marked Pro (awaiting key materialisation)", slog.String("user_id", userID))
			}

		case "customer.subscription.deleted":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				logger.Error("parse subscription deleted event", slog.Any("error", err))
				break
			}
			cid := customerID(sub.Customer)
			if cid == "" {
				break
			}
			logger.Info("subscription deleted", slog.String("stripe_customer_id", cid))
			// Soft revoke (Wave 6): downgrade tier but keep the row + token_hash.
			// If the customer re-subscribes their existing CI key still works
			// once the next checkout.session.completed flips tier back to 'pro';
			// hard-deleting forced an awkward rotate-after-resubscribe flow.
			// The rate-limiter (rolling 30-day count, 10 free) automatically
			// applies the moment tier flips back to 'free', so the user
			// loses Pro privileges immediately.
			result, err := db.Exec(
				`UPDATE api_keys SET subscription_tier = 'free' WHERE stripe_customer_id = $1`,
				cid)
			if err != nil {
				logger.Error("revoke (soft)", slog.String("stripe_customer_id", cid), slog.Any("error", err))
			} else {
				rows, _ := result.RowsAffected()
				logger.Info("API key downgraded to free",
					slog.String("stripe_customer_id", cid),
					slog.Int64("count", rows))
			}

		case "invoice.payment_failed":
			var invoice stripe.Invoice
			if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
				logger.Error("parse invoice event", slog.Any("error", err))
				break
			}
			cid := customerID(invoice.Customer)
			logger.Warn("payment failed",
				slog.String("stripe_customer_id", cid),
				slog.String("invoice_id", invoice.ID),
				slog.Int64("attempt", invoice.AttemptCount))
			if cid != "" && invoice.AttemptCount >= 3 {
				// Soft revoke (Wave 6): see customer.subscription.deleted comment.
				logger.Warn("max retry attempts reached — downgrading to free",
					slog.String("stripe_customer_id", cid))
				db.Exec(
					`UPDATE api_keys SET subscription_tier = 'free' WHERE stripe_customer_id = $1`,
					cid)
			}

		case "customer.subscription.updated":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				logger.Error("parse subscription update event", slog.Any("error", err))
				break
			}
			cid := customerID(sub.Customer)
			logger.Info("subscription updated",
				slog.String("stripe_customer_id", cid),
				slog.String("status", string(sub.Status)))
			// Wave 6: reflect Stripe's status into subscription_tier so users
			// whose card declined or who are mid-cancellation lose Pro access
			// without us needing a separate cron. Pro applies only while the
			// subscription is `active` or `trialing`. Other terminal states
			// (`past_due`, `canceled`, `incomplete_expired`, `unpaid`,
			// `paused`) downgrade to free; the rate-limiter takes effect
			// on the next save-proof.
			if cid == "" {
				break
			}
			tier := "free"
			switch sub.Status {
			case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusTrialing:
				tier = "pro"
			}
			if _, err := db.Exec(
				`UPDATE api_keys SET subscription_tier = $1 WHERE stripe_customer_id = $2`,
				tier, cid); err != nil {
				logger.Error("reflect subscription status",
					slog.String("stripe_customer_id", cid),
					slog.String("status", string(sub.Status)),
					slog.Any("error", err))
			} else {
				logger.Info("subscription tier updated from Stripe status",
					slog.String("stripe_customer_id", cid),
					slog.String("status", string(sub.Status)),
					slog.String("tier", tier))
			}

		default:
			logger.Info("unhandled event type")
		}

		w.WriteHeader(http.StatusOK)
	})

	// --- API key issuance ---------------------------------------------------
	// /api/generate-key implements the one-time-reveal model Wave 3b picked
	// (GitHub / Stripe / AWS style). Called by the dashboard after a fresh
	// user either signs up for free tier or lands back from Stripe checkout.
	//
	// Contract:
	//   * 201 Created with {"apiKey": "<raw>"} when a brand-new key is
	//     materialised. This is the ONLY moment the raw key leaves the
	//     server — subsequent calls cannot re-read it because we only store
	//     its SHA-256 hash.
	//   * 409 Conflict when the user already has a materialised key. Client
	//     is expected to offer "Rotate" (which revokes + reissues) rather
	//     than silently re-displaying a key we no longer possess in plaintext.
	//
	// userID always comes from the verified JWT, never the request body.
	generateKeyHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		logger := httplog.From(r.Context()).With(slog.String("user_id", userID))

		// Three possible states for api_keys.user_id = $1:
		//   1. No row           → INSERT fresh (free-tier signup path)
		//   2. Row with NULL hash → UPDATE hash (post-checkout webhook left
		//                          a Pro marker; this materialises the key)
		//   3. Row with non-NULL hash → 409 (already materialised; must rotate)
		var existingHash sql.NullString
		err := db.QueryRow(
			`SELECT token_hash FROM api_keys WHERE user_id = $1`, userID,
		).Scan(&existingHash)
		if err != nil && err != sql.ErrNoRows {
			logger.Error("lookup existing api key", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if err == nil && existingHash.Valid && existingHash.String != "" {
			// Case 3. The raw key is unrecoverable; force the client down the
			// rotate path instead of silently re-issuing.
			logger.Info("generate-key rejected: key already materialised")
			http.Error(w, "API key already exists; rotate it to issue a new one", http.StatusConflict)
			return
		}

		rawKey, hashed, err := newAPIKey()
		if err != nil {
			logger.Error("generate api key bytes", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Case 1 vs 2 handled by a single UPSERT. If the webhook pre-created
		// a Pro marker (NULL hash), we fill it in and preserve the 'pro'
		// tier; if there's no row at all, the INSERT path creates a 'free'
		// key for a user who is generating before paying.
		// trial_ends_at is only set on INSERT (new users) — existing rows keep
		// whatever trial window (or NULL) they already have.
		if _, err := db.Exec(
			`INSERT INTO api_keys (user_id, token_hash, subscription_tier, trial_ends_at)
			 VALUES ($1, $2, 'free', NOW() + INTERVAL '14 days')
			 ON CONFLICT (user_id) DO UPDATE
			 SET token_hash = EXCLUDED.token_hash`,
			userID, hashed,
		); err != nil {
			logger.Error("store api key", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("api key materialised")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"apiKey": rawKey})
	}
	mux.HandleFunc("/api/generate-key", withCORS(auth.RequireSupabaseJWT(generateKeyHandler)))

	// --- API key rotation ---------------------------------------------------
	// /api/rotate-key revokes the caller's current key and issues a fresh
	// one. Same one-time-reveal contract as /api/generate-key — the new
	// plaintext is only in this response body, never retrievable later.
	//
	// Idempotency: calling rotate when no row exists behaves identically
	// to generate-key (creates a free-tier row). The existing tier is
	// preserved on rotate so a Pro user doesn't accidentally downgrade.
	rotateKeyHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		logger := httplog.From(r.Context()).With(slog.String("user_id", userID))

		rawKey, hashed, err := newAPIKey()
		if err != nil {
			logger.Error("generate api key bytes", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// UPSERT rather than UPDATE so a user who never materialised a key
		// before calling rotate still gets one. Tier is left untouched on
		// the conflict path so a Pro user stays Pro.
		if _, err := db.Exec(
			`INSERT INTO api_keys (user_id, token_hash, subscription_tier)
			 VALUES ($1, $2, 'free')
			 ON CONFLICT (user_id) DO UPDATE
			 SET token_hash = EXCLUDED.token_hash`,
			userID, hashed,
		); err != nil {
			logger.Error("rotate api key", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("api key rotated")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"apiKey": rawKey})
	}
	mux.HandleFunc("/api/rotate-key", withCORS(auth.RequireSupabaseJWT(rotateKeyHandler)))

	// --- Checkout verification (webhook fallback) ----------------------------
	// /api/verify-checkout is called by the frontend on the checkout-return
	// page when the Stripe webhook hasn't updated the tier within a few
	// seconds. It fetches the Checkout Session directly from the Stripe API,
	// confirms payment_status == "paid", and writes Pro tier to the DB.
	//
	// This makes checkout reliable even when the webhook is mis-configured,
	// delayed, or simply hasn't been set up yet on a staging environment.
	// The upsert is idempotent so calling this after the webhook has already
	// run is harmless.
	verifyCheckoutHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		logger := httplog.From(r.Context()).With(slog.String("user_id", userID))

		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			http.Error(w, "Missing session_id parameter", http.StatusBadRequest)
			return
		}

		stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
		if stripe.Key == "" {
			logger.Error("STRIPE_SECRET_KEY not set")
			http.Error(w, "Stripe not configured", http.StatusInternalServerError)
			return
		}

		cs, err := session.Get(sessionID, nil)
		if err != nil {
			logger.Error("retrieve checkout session from Stripe", slog.Any("error", err))
			http.Error(w, "Unable to verify checkout session", http.StatusBadGateway)
			return
		}

		// Ensure the session was created for this authenticated user so a
		// caller can't pass someone else's session_id and steal their tier.
		if cs.Metadata["user_id"] != userID {
			logger.Warn("checkout session user_id mismatch",
				slog.String("session_user_id", cs.Metadata["user_id"]))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Log both status fields so webhook / verify-checkout discrepancies
		// are easy to spot in production logs.
		logger.Info("checkout session retrieved",
			slog.String("cs_status", string(cs.Status)),
			slog.String("cs_payment_status", string(cs.PaymentStatus)))

		w.Header().Set("Content-Type", "application/json")

		// Use cs.Status == "complete" rather than PaymentStatus == "paid".
		// For mode=subscription Stripe fires checkout.session.completed (and
		// redirects the browser) before the first invoice is confirmed, so
		// PaymentStatus can still be "unpaid" or "no_payment_required" at
		// the moment we call session.Get. "complete" is set the instant the
		// checkout flow finishes — the same signal the webhook uses.
		if cs.Status != stripe.CheckoutSessionStatusComplete {
			json.NewEncoder(w).Encode(map[string]string{"tier": "free"})
			return
		}

		cid := customerID(cs.Customer)
		logger.Info("checkout verified via Stripe API",
			slog.String("stripe_customer_id", cid),
			slog.String("payment_status", string(cs.PaymentStatus)))

		if _, err := db.Exec(
			`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier)
			 VALUES ($1, $2, 'pro')
			 ON CONFLICT (user_id) DO UPDATE
			 SET stripe_customer_id = EXCLUDED.stripe_customer_id,
			     subscription_tier  = 'pro'`,
			userID, cid,
		); err != nil {
			logger.Error("upgrade user to pro via verify-checkout", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("user upgraded to Pro via checkout verification")
		json.NewEncoder(w).Encode(map[string]string{"tier": "pro"})
	}
	mux.HandleFunc("/api/verify-checkout", withCORS(auth.RequireSupabaseJWT(verifyCheckoutHandler)))

	// --- Session/profile read -----------------------------------------------
	// /api/me returns the caller's subscription tier and whether their API
	// key has been materialised. The frontend uses this instead of reading
	// api_keys directly through the Supabase JS client so the read path does
	// not depend on RLS policies being configured in the Supabase dashboard.
	// Backend access bypasses RLS via the direct Postgres connection.
	meHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		logger := httplog.From(r.Context()).With(slog.String("user_id", userID))

		var tokenHash sql.NullString
		var tier sql.NullString
		var trialEndsAt sql.NullTime
		err := db.QueryRow(
			`SELECT token_hash, subscription_tier, trial_ends_at FROM api_keys WHERE user_id = $1`,
			userID,
		).Scan(&tokenHash, &tier, &trialEndsAt)
		if err != nil && err != sql.ErrNoRows {
			logger.Error("me lookup", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		resolvedTier := "free"
		if tier.Valid && tier.String != "" {
			resolvedTier = tier.String
		}
		resp := map[string]any{
			"hasKey": tokenHash.Valid && tokenHash.String != "",
			"tier":   resolvedTier,
		}
		if trialEndsAt.Valid {
			remaining := int(time.Until(trialEndsAt.Time).Hours() / 24)
			if remaining < 0 {
				remaining = 0
			}
			resp["trialDaysRemaining"] = remaining
		}
		json.NewEncoder(w).Encode(resp)
	}
	mux.HandleFunc("/api/me", withCORS(auth.RequireSupabaseJWT(meHandler)))
}

// newAPIKey generates a fresh aicap_pro_sk_* token and returns both the raw
// plaintext (to echo to the caller exactly once) and its SHA-256 hash (to
// persist). Shared by /api/generate-key and /api/rotate-key to keep the
// token prefix and hash algorithm in one place.
// isShareToken reports whether s looks like a token we could have
// minted: exactly 64 lowercase hex characters (32 random bytes).
func isShareToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func newAPIKey() (raw, hashed string, err error) {
	keyBytes := make([]byte, 24)
	if _, err = rand.Read(keyBytes); err != nil {
		return "", "", err
	}
	raw = "aicap_pro_sk_" + hex.EncodeToString(keyBytes)
	hashed = auth.HashAPIKey(raw)
	return raw, hashed, nil
}

// parseAllowedOrigins splits a comma-separated VITE_FRONTEND_URL into a set of
// trimmed origins. In local mode (no DB configured) we fall back to "*" so
// `go run` against a Vite dev server on an arbitrary port still works.
func parseAllowedOrigins(env string, isCloudSaaS bool) []string {
	if env == "" {
		if isCloudSaaS {
			return []string{"https://aicap.vercel.app", "https://*.vercel.app"}
		}
		return []string{"*"}
	}
	parts := strings.Split(env, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isAllowedOrigin(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
		// Support dynamic wildcard subdomains (e.g., https://*.vercel.app)
		if strings.HasPrefix(a, "https://*.") {
			suffix := strings.TrimPrefix(a, "https://*")
			if strings.HasPrefix(origin, "https://") && strings.HasSuffix(origin, suffix) {
				return true
			}
		}
	}
	return false
}

// customerID safely extracts a Stripe customer ID from a potentially-nil
// *stripe.Customer reference. Returns "" when the pointer is nil — this
// shows up on test-clock events and certain partial payloads and would
// otherwise cause a nil-pointer dereference.
func customerID(c *stripe.Customer) string {
	if c == nil {
		return ""
	}
	return c.ID
}

// computeChainHash is the canonical crypto_hash formula for proof_drills.
// Used by both save-proof (at insert) and verify-chain (at verify); they
// must match exactly or every row looks tampered.
//
// When prevHash == "" we fall through to the pre-Wave-4 formula
// (sha256(commit_sha || ai_bom_json)), so rows written before migration
// 00010 still hash-match. New non-genesis rows mix in the previous
// crypto_hash so any historical edit breaks every later link.
func computeChainHash(commitSha string, bomJSON []byte, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(commitSha))
	h.Write(bomJSON)
	if prevHash != "" {
		h.Write([]byte(prevHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}
