# AIcap — Claude Code Context

## What this project is
**AIcap** — Continuous AI-BOM & Compliance Scanner for the EU AI Act.
- Go 1.23 backend + Supabase PostgreSQL + Stripe billing
- React/Vite frontend (single-page, no router)
- Deployed on Render (backend) + Vercel or Render (frontend)
- GitHub Action (`istrategeorge/AIcap@v1.0.0-beta`) runs the CLI scanner in CI pipelines

## Repo layout
```
main.go                        # entry point: HTTP server + --migrate subcommand
pkg/
  api/api.go                   # all HTTP handlers (RegisterRoutes)
  api/api_integration_test.go  # integration tests (build tag: integration)
  auth/auth.go                 # JWT + API key middleware, HashAPIKey
  httplog/httplog.go           # slog JSON handler + request-ID middleware
  migrate/                     # embedded SQL migration runner
  migrate/migrations/          # 00001..00009 SQL files
  scanner/                     # AI-BOM static analysis
  compliance/                  # EU AI Act compliance checks
  types/                       # shared types (AIBOM, ProofRecord, …)
frontend/src/App.jsx            # entire React frontend (single file)
docker-compose.yml              # local Postgres for integration tests
```

## Branching model
- `main` — stable / production
- `development` — active work branch (current: `d79d9fd`)
- All PRs target `development` first, then merge to `main` for release

## Tech stack versions
- Go module: `aicap` (`go.mod`)
- `lib/pq` — Postgres driver
- `stripe-go/v79` (v79.12.0)
- `golang-jwt/v5`
- React 18 + Vite + Tailwind + lucide-react

## Authentication model (Wave 3b — current)
Two distinct auth schemes, each for a different caller:

| Caller | Scheme | Routes |
|--------|--------|--------|
| Browser (dashboard) | Supabase session JWT (`RequireSupabaseJWT`) | `/api/history`, `/api/proof`, `/api/verify-chain`, `/api/create-checkout-session`, `/api/generate-key`, `/api/rotate-key`, `/api/verify-checkout`, `/api/me` |
| CI pipeline | API key hash (`RequireAPIKey`) | `/api/save-proof` |

**API keys are hashed at rest** (SHA-256, column `token_hash`). The plaintext is returned exactly once from `/api/generate-key` or `/api/rotate-key` and never stored. `HashAPIKey(raw)` in `pkg/auth` is the canonical hash function.

## Database schema (migrations 00001–00010)
```
api_keys:       id, user_id (UNIQUE), token_hash, stripe_customer_id,
                subscription_tier, scans_this_month, created_at
proof_drills:   id, project_id, commit_sha, ai_bom_json, risk_register_state,
                annex_iv_markdown, crypto_hash, prev_hash, user_id (NOT NULL),
                created_at
projects:       id, name (UNIQUE), repository_url, created_at
stripe_events:  event_id (PK), event_type, received_at   ← idempotency table
schema_migrations: filename, applied_at
```
Key constraints: `api_keys.user_id` is UNIQUE (one key per user).
`proof_drills.user_id` is NOT NULL (Wave 3b removed the NULL bridge).
`proof_drills.prev_hash` (Wave 4) chains each row to its predecessor's
`crypto_hash` per user, so a tampered or deleted historical row breaks
the chain at every later link. NULL on the genesis row of a user's chain.

## Running locally
```bash
# Unit tests (no Docker needed)
go test ./...

# Integration tests (requires Docker)
docker compose up -d db
TEST_DATABASE_URL='postgres://aicap:aicap@localhost:5432/aicap?sslmode=disable' \
  go test -tags=integration ./...
docker compose down

# Run server locally (no DB)
go run main.go

# Run server with DB + migrations
SUPABASE_DB_URL='...' RUN_MIGRATIONS=true go run main.go

# Frontend dev server
cd frontend && npm run dev
```

## Environment variables
```
SUPABASE_DB_URL         Postgres connection string (enables cloud/SaaS mode)
SUPABASE_JWT_SECRET     HS256 secret for verifying Supabase session tokens
STRIPE_SECRET_KEY       Stripe API key
STRIPE_WEBHOOK_SECRET   Stripe webhook signing secret
STRIPE_PRICE_ID         Stripe price ID (default: price_1Pdtg1E5iL2Zl43n5G4YhI9t)
VITE_FRONTEND_URL       Allowed CORS origin(s), comma-separated
RUN_MIGRATIONS          Set to "true" to auto-run migrations on startup
LOG_LEVEL               "debug" for verbose slog output (default: info)
PORT                    HTTP port (default: 8080)
```

## Completed hardening waves
### Wave 1 (merged to main)
- CORS preflight fix (OPTIONS passes through auth middleware)
- Tenant scoping on `/api/history` and `/api/proof` (user_id isolation)
- Rate limiting: rolling 30-day window via composite index (free tier: 10 scans)

### Wave 2 (merged to main — commit e9aeb44)
- Embedded SQL migration runner (`pkg/migrate`) with idempotency
- Docker multi-stage build + `docker-compose.yml` for local Postgres
- Integration test suite behind `//go:build integration`
- `scans_this_month` replaced by rolling-window COUNT query

### Wave 3a (on development — commit 81b872c)
- Stripe webhook replay protection: `stripe_events` table (PK idempotency)
- Structured logging: `pkg/httplog` with JSON slog + per-request `X-Request-ID`
- Graceful shutdown: `*http.Server` with SIGTERM → 25s drain
- Error hygiene: raw DB/Stripe error strings scrubbed from HTTP responses

### Wave 3b (on development — commit 4ee14a4)
- `/api/history` and `/api/proof` switched to `RequireSupabaseJWT`
- `OR user_id IS NULL` tenant bridge removed; `proof_drills.user_id` NOT NULL
- `api_keys.token` dropped; SHA-256 hash stored in `token_hash`
- `/api/generate-key`: one-time reveal (201 once, then 409)
- `/api/rotate-key`: revokes current hash, issues new plaintext once
- Stripe webhook: upserts Pro tier marker (NULL token_hash); frontend materialises key
- Frontend: session shape is `{user, accessToken, hasKey, tier}` — no raw key in state

### Wave 3c (on development — checkout flow hardening + RLS-independent reads)
Commits: `f59e339`, `a2adeac`, `dd5d41f`, `ca9ff46`, `d79d9fd` — all on `development`.

- **Checkout return race fixed**: `onAuthStateChange` was double-firing
  `INITIAL_SESSION` + `TOKEN_REFRESHED`, causing two concurrent `/api/generate-key`
  calls on the checkout-return URL (one 201, one 409). Fixed by removing the
  separate `supabase.auth.getSession()` call and guarding `fetchAndSetUserSession`
  with a `useRef(false)` latch.
- **Checkout processing UI**: `checkoutProcessing` state is initialised from the
  `session_id` URL param so the spinner shows immediately on page load, before
  auth state fires. Render order checks `checkoutProcessing` BEFORE `!session`
  so users don't flash the login screen between Stripe redirect and session mount.
- **Webhook-independent verification**: new `GET /api/verify-checkout?session_id=…`
  endpoint calls Stripe's API directly (`session.Get`), confirms
  `Status == complete` (NOT `PaymentStatus == paid` — for `mode=subscription`
  that can be `unpaid`/`no_payment_required` when the event fires), and upserts
  Pro tier. This is the fallback when the Stripe webhook is misconfigured,
  delayed, or simply not yet set up on a staging environment.
- **Checkout-return fallback chain** (in `fetchAndSetUserSession`):
  1. Call `/api/generate-key` to materialise the key (idempotent via 409).
  2. Poll `/api/me` 3 × 1.5 s for `tier == 'pro'` (normal webhook path).
  3. If still not Pro, call `/api/verify-checkout` (Stripe API fallback).
- **`/api/me` endpoint**: returns `{hasKey, tier}` via the direct DB connection,
  bypassing Supabase RLS. Frontend no longer reads `api_keys` through the
  Supabase JS client, so session correctness does not depend on RLS policies
  being configured in the Supabase dashboard. RLS stays enabled as
  defense-in-depth (if the anon key leaks, it still blocks cross-tenant reads).

### Wave 4 (in progress — on development)
- **CI integration-test job** — `.github/workflows/go-test.yml` runs `go build`,
  `go test ./...` (unit) and `go test -tags=integration ./...` (integration,
  against a Postgres 16 service container) on every push/PR to `main` and
  `development`. Uses `go-version-file: go.mod` so the toolchain stays in sync
  with the module declaration instead of pinning a version that drifts.
- **`/livez` vs `/readyz` split** — `/livez` always returns 200 if the process
  can serve (for liveness probes: a failing DB must not trigger a pod
  restart). `/readyz` returns 503 when the DB ping fails so the orchestrator
  pulls the pod out of the LB. `/healthz` is kept as an alias of `/readyz`
  so existing Render probes don't break during a rolling probe-URL update.
- **Hash-chain ledger anchoring** — migration 00010 adds `prev_hash` on
  `proof_drills`. Each save-proof opens a transaction, takes a per-user
  advisory lock (`pg_advisory_xact_lock(hashtextextended(user_id, 0))`),
  reads the user's chain head, and writes a new row whose `crypto_hash`
  is `sha256(commit_sha || ai_bom_json || prev_hash)`. The advisory lock
  serialises concurrent inserts for one user without blocking other
  users. `GET /api/verify-chain` walks the caller's chain and returns
  `{ok:false, brokenAt, reason}` on the first divergence (payload edit,
  prev_hash mismatch, or NULL prev_hash on a non-genesis row). The hash
  formula degrades to the pre-Wave-4 form when `prev_hash` is empty so
  legacy rows (written before 00010 ran) still verify against their
  stored hash — they form an unverified prefix that the chain extends from.

- **Frontend refresh-token handling** — `onAuthStateChange` now branches on
  the event type: `TOKEN_REFRESHED` patches only `session.accessToken` so a
  silent background refresh updates the in-memory JWT without re-running
  the checkout-return polling flow. All authenticated dashboard fetches
  (`/api/history`, `/api/proof`, `/api/generate-key`, `/api/rotate-key`,
  `/api/create-checkout-session`) now go through an `apiFetch` wrapper
  that reads the live access_token from supabase-js's cache (rather than
  React state) and, on a 401, calls `supabase.auth.refreshSession()` once
  and retries — covering the race where a request flies just after JWT
  expiry but before the auto-refresh tick. If the refresh itself fails,
  supabase-js fires `SIGNED_OUT` which routes back to the login screen.

## Wave 4 status
All items shipped. Wave 4 is feature-complete on `development` pending
final end-to-end verification against staging.

### Wave 5 (in progress — frontend hygiene)
Driven by the 2026-04-26 reassessment in `documentation/analysis_results.md`,
which flagged that `App.jsx` had grown to 1059 lines (worse than the
original 729-line analysis baseline). Wave 5 splits the monolith and
adds the first frontend tests.

- **Frontend componentization** — break `frontend/src/App.jsx` into:
  - `lib/supabase.js` — Supabase client + `apiFetch` wrapper (live-token
    read + 401 refresh-and-retry, moved out of `App.jsx`)
  - `lib/annexIV.js` — pure helper that builds the Annex IV markdown
    template from a scan + optional historical record
  - `components/Header.jsx` — branding bar + sign-out + dev rescan button
  - `components/LandingAuth.jsx` — marketing copy + login/signup form
  - `components/CheckoutProcessing.jsx` — Stripe-return spinner card
  - `components/Paywall.jsx` — Pro upgrade CTA
  - `components/KeyVault.jsx` — three-state API-key panel
    (revealed → has-key → no-key)
  - `components/HistoryTable.jsx` — proof-drill audit ledger
  - `components/AnnexIVPreview.jsx` — markdown preview + download button
  - `components/ProDashboard.jsx` — composes the cloud-SaaS Pro view
  - `components/LocalDashboard.jsx` — composes the local-dev view
    (db-config card, posture card, annex action, BOM table, FinOps table)
  After the split, `App.jsx` is the top-level state machine + view
  router only — auth state, session bootstrap, view selection.

- **Frontend tests (first-ever)** — Vitest + React Testing Library:
  - `apiFetch.test.js` — confirms 401 triggers `refreshSession` once
    and retries with the new token, and that a non-401 response is
    returned untouched
  - `KeyVault.test.jsx` — three-state UI rendering (no-key, has-key,
    revealed), button states during async ops
  Frontend tests run via `npm test`. CI (Wave 4 workflow) extended
  to invoke them on every push/PR.

## Pending work (Wave 5 remainder)
None — Wave 5 is scoped to the split + first tests only. Tier A and
Tier B items from the reassessment shipped in Wave 6.

### Wave 6 (shipped — backend correctness + Article 9 risk register)

#### Phase A: Correctness gaps from the 2026-04-26 reassessment
- **Idempotent `/api/save-proof` by `(user_id, commit_sha)`** — migration
  00011 adds a partial UNIQUE index (excluding NULL user_ids so local-dev
  still works without auth). The handler does a SELECT-first short-circuit
  inside the existing per-user advisory lock; a CI retry returns 200 OK
  with the existing `cryptoHash` and `{idempotent: true}`, no duplicate
  audit row, no chain pollution. Response body now always carries
  `{status, cryptoHash, idempotent}` instead of just `{status}`.
- **`customer.subscription.updated` reflects status into the tier** —
  `active`/`trialing` → `pro`, anything else (`past_due`, `canceled`,
  `incomplete_expired`, `unpaid`, `paused`) → `free`. The rolling-window
  rate-limiter (Wave 1) automatically applies once tier flips, so a user
  whose card declines loses Pro on the very next save-proof.
- **Soft revoke instead of hard delete** — `customer.subscription.deleted`
  and `invoice.payment_failed` (after 3 attempts) now `UPDATE … SET
  subscription_tier = 'free'` instead of `DELETE FROM api_keys`. The
  `token_hash` survives, so a re-subscribe (`subscription.updated → active`)
  flips the user back to Pro without forcing them to regenerate their
  CI key.

#### Phase B: Article 9 risk register population
- **Curated AI risk catalog** — `pkg/compliance/vulns.json` (embedded via
  `//go:embed`). Lower-cased keys for tensorflow, torch, pytorch,
  transformers, langchain, openai, anthropic, huggingface_hub,
  scikit-learn, diffusers. Each entry maps to OWASP ML Top 10 category,
  MITRE ATLAS technique IDs, EU AI Act articles, severity, recommended
  mitigation, and rationale. MVP scope per the original analysis ("even a
  static JSON to start"); live CVE / GHSA / MITRE feeds queued for a
  later wave.
- **`pkg/compliance/risk_register.go`** — `ComputeRiskRegister(bom)` is a
  pure function that walks `bom.Dependencies`, lower-cases each name,
  looks it up in the catalog, and emits a `types.RiskRegister` with
  per-finding rows + High/Medium/Low/Total summary counts.
  `RenderRiskRegisterMarkdown` emits the table block for Annex IV § 5.
- **Persistence** — `/api/save-proof` now JSON-marshals the register and
  writes it into `proof_drills.risk_register_state` (the JSONB column
  added in migration 00002 that had been empty for two years). The
  Annex IV markdown surfaces the same findings via § 3(a)
  "Cross-Referenced Risk Register (OWASP ML Top 10 / MITRE ATLAS)",
  replacing the previous minimal "Automated Risk Register" block.
- **Tests** — 5 unit tests in `pkg/compliance/risk_register_test.go`
  (catalog match, case-insensitive lookup, unknown deps skipped, mixed
  severities, markdown table shape) plus 2 new integration tests
  (`TestSaveProof_PersistsRiskRegister`,
  `TestSaveProof_AnnexIVContainsRiskRegister`).

## Pending work (Wave 6 remainder)
None for Phases A+B.

### Wave 7a (shipped — Annex IV § 4 auto-population from IaC)

The 2026-04-29 reassessment identified Annex IV's `[REQUIRES MANUAL INPUT]`
placeholders for HITL, training-data provenance, bias monitoring, and
prompt-injection defences as the largest remaining Phase 3 gap. Wave 7a
closes it by parsing IaC + source files we already walk, looking for
concrete signals.

- **`pkg/scanner/governance.go`** — six detector functions, all
  conservative (false negatives over false positives). HITL signals
  from k8s manifest names matching `(?i)\b(review|approval|human|hitl|
  moderation|feedback|judge|reviewer|escalation)\b` (word-bounded —
  "preview-server" doesn't match), Argo Workflow `suspend:` steps,
  and GitHub Actions `environment:` keys (only files under
  `.github/workflows/`). Training-data signals from any `*.dvc` /
  `dvc.yaml` / `dvc.lock`, Terraform `aws_s3_bucket` /
  `google_storage_bucket` resources whose declared name OR inline
  `bucket =` value matches the training-data pattern, and HuggingFace
  `from datasets import load_dataset` calls in Python. Bias-monitoring
  signals from Python imports of `fairlearn` / `aif360` /
  `responsibleai` / `equalized_odds` and from those names appearing
  in `requirements.txt` / `pyproject.toml`. Prompt-injection-defence
  signals from imports of `lakera` / `lakera_guard` / `rebuff` /
  `nemoguardrails` / `presidio_analyzer` / `garak` / `llm_guard` and
  from manifests.

- **`types.GovernanceTelemetry` + `types.GovernanceSignal`** — added
  to `pkg/types/types.go`. New `Governance` field on `AIBOM` with
  four buckets (HITL, TrainingData, BiasMonitoring,
  PromptInjectionDefenses). Each signal carries
  `{Source, Location, Evidence, Description}`.

- **`compliance.GenerateAnnexIVMarkdown`** — § 3(c) (prompt-injection)
  now branches: if any defence signals were detected, the section
  emits `[x] Prompt-injection defences detected: <evidence>` with
  per-signal descriptions; otherwise it keeps the original
  `[REQUIRES MANUAL INPUT: …]`. § 4 sub-sections (HITL, Training
  Data, Bias Monitoring) call a new `renderGovernanceSection`
  helper that does the same evidence-or-placeholder pattern. The
  contract: auditors see *evidence* or *prompt*, never silent
  omission, and never both at once for the same control.

- **Frontend `lib/annexIV.js`** — mirrored: `renderGovernance`
  helper renders `scanData.governance.{hitl,trainingData,
  biasMonitoring,promptInjectionDefenses}` if present, falls back
  to placeholders when not. Local-dev preview thus shows the same
  Annex IV shape as the persisted markdown.

- **Tests** — 13 unit tests in `pkg/scanner/governance_test.go`
  covering each detector + a `PerformScan` integration that drops
  realistic IaC into a tempdir and asserts all four buckets
  populate. 2 new unit tests in `pkg/scanner/scanner_test.go` cover
  the Annex IV rendering (placeholder when empty, evidence when
  populated, no double-render). 1 new integration test
  (`TestSaveProof_AnnexIVContainsGovernance`) confirms persistence
  end-to-end.

## Pending work (Wave 7a remainder)
None.

### Wave 7b (shipped — Phase 6 GPU cost estimation)

The 2026-04-29 reassessment kept Phase 6 at 40% because the scanner
could spot GPU-bearing infrastructure but couldn't tell the user what
it would cost. Wave 7b lifts the per-instance-family hourly-rate data
out of the inline maps in `pkg/scanner/scanner.go` into a structured
catalog and attaches concrete dollar figures to FinOps findings.

- **`pkg/finops/`** — new package, mirrors the
  `pkg/compliance/risk_register.go` pattern.
  - `gpu_costs.json` — curated catalog (AWS p3/p4d/p4de/p5/g4dn/g5/
    g5g/g6/inf1/inf2/trn1, Azure NC/ND/NV, GCP a2-highgpu/a2-megagpu/
    a3-highgpu/g2-standard) embedded via `//go:embed`. Each entry
    carries hourly USD low/high (for families that span multiple
    sizes), description, and the global assumed-hours-per-month
    constant + curated disclaimer.
  - `LookupGPUCost(content)` — first-match prefix lookup, returns a
    `types.FinOpsCost` with hourly + monthly USD ranges. Nil when
    nothing matches (typical for k8s nvidia.com/gpu requests with no
    instance-type hint).
  - `EstimateBOMCost(bom)` — aggregates per-finding costs into a
    BOM-level `FinOpsCostSummary` (TotalMonthlyUSDLow/High, Currency,
    AssumedHoursPerMonth, Disclaimer, CostedFindings,
    UncostedFindings).

- **`types.FinOpsFinding`** — new optional `EstimatedCost *FinOpsCost`
  field. **`types.AIBOM`** — new optional `FinOpsCostEstimate
  *FinOpsCostSummary` field. Both omitempty so legacy proof drills
  re-rendered through the new code don't carry phantom zero figures.

- **`pkg/scanner/scanner.go`** — `parseTerraformFile` now delegates
  cost lookup to `pkg/finops` and attaches `FinOpsCost` to the
  emitted finding. The big inline AWS/Azure/GCP instance maps are
  gone (DRY against the catalog). `PerformScan` calls
  `finops.EstimateBOMCost(bom)` after the walk so every BOM ships
  with a populated summary when there's at least one finding.

- **Annex IV § 2(c)** — renamed to "Hardware Requirements & Estimated
  Monthly Cost (FinOps Telemetry)". Per-finding bullets now include
  an "Estimated cost: $X.XX–$Y.YY /hr → $A–$B /month (Cloud family
  `prefix`)" line when available. A BOM-level total + assumptions
  block ("Estimated total monthly cost: $A–$B USD across N costed
  finding(s); M additional finding(s) had no catalog match") closes
  the section.

- **Frontend `LocalDashboard.jsx` FinOpsTable** — added "Est. $/mo"
  column with `Intl.NumberFormat` USD formatting; header right-side
  shows the BOM-level total when present; assumptions footer renders
  inside the table.

- **Frontend `lib/annexIV.js`** — mirrors backend rendering via a
  new `renderFinOpsBlock(finOps, est)` helper.

- **Tests** — 8 unit tests in `pkg/finops/cost_test.go` (catalog
  lookup positive/negative cases per cloud, range vs. point pricing,
  BOM aggregation with mixed costed/uncosted findings, all-uncosted
  edge case). 2 new unit tests in `pkg/scanner/scanner_test.go`
  (Annex IV cost line rendered when present, omitted when not). 1
  integration test (`TestSaveProof_AnnexIVContainsCostEstimate`)
  asserts the cost data round-trips through save-proof and the
  saved Annex IV markdown carries the dollar figure + disclaimer.

## Pending work (Wave 7b remainder)
None.

### Wave 7c (shipped — additional manifest parsers)

The original analysis flagged that AIcap only handled `requirements.txt`
and `package.json`. Wave 7c fills in the remaining lockfile / alternative-
manifest formats so projects using Poetry-locked, Pipenv-locked,
pnpm/yarn-locked, or Conda-managed deps still get a full AI-BOM:

- `poetry.lock` — TOML, `[[package]]` blocks (Poetry resolved tree)
- `Pipfile.lock` — JSON, `default` + `develop` sections (Pipenv)
- `pnpm-lock.yaml` — YAML, `packages:` map keyed by `/name@version`
- `yarn.lock` — custom format, `"name@range":` headers + `version "..."` rows
- `environment.yml` (and `environment.yaml`) — Conda dependencies + pip
  sub-block

All five live in `pkg/scanner/manifests.go` alongside a small
`emitIfAI` helper. Simple line/regex scanning rather than full
TOML/YAML parsers — zero new dependencies, lockfile shapes are stable.
The lockfiles are the authoritative version source: `pyproject.toml`
/ `Pipfile` / `package.json` carry version *ranges*, but the lockfile
tells us what actually got installed. 7 unit tests cover one
happy-path per parser plus a Conda section-toggle regression and a
PerformScan integration.

### Wave 7d (shipped — CHANGELOG.md)
`CHANGELOG.md` lands at the repo root with a Keep-a-Changelog
formatted entry covering every wave from 1 through 7c. Includes the
full maturity-table diff vs the original blueprint analysis and notes
that Phase 5 / 8 are deliberately deferred. The unreleased section
explains the development → main flow so a future merge can drop the
section header into a `v0.7.0` tag.

### Wave 7e (shipped — Stripe customer portal)

Pro users had to file a support ticket to update payment methods, view
invoices, or cancel — every billing change went through us. Wave 7e
adds a Stripe BillingPortal session endpoint and a frontend
"Manage subscription" button.

- `POST /api/customer-portal` — Supabase JWT-gated. Reads
  `stripe_customer_id` from `api_keys` for the authenticated user.
  Returns 400 when there's no Stripe customer (free-tier path) so the
  API guards the UI state. Otherwise creates a fresh BillingPortal
  session and returns `{url}` for the frontend to navigate to. Each
  call creates a new session — Stripe portal sessions are short-lived
  and single-use.
- `frontend/src/components/ManageSubscriptionButton.jsx` — POSTs the
  endpoint via `apiFetch` (so the 401 refresh-and-retry contract
  applies) and redirects same-tab on success.
- 3 new integration tests: requires-stripe-customer (400),
  unauthed-rejected (401), CORS-preflight (Wave 1 regression guard).

### Wave 7f (shipped — live OSV.dev CVE/GHSA enrichment)

The Wave 6 risk register fed exclusively from `pkg/compliance/vulns.json`
— accurate for OWASP / MITRE / Article mappings but lagging real-world
CVE / GHSA disclosures. Wave 7f cross-references each detected dep
against [OSV.dev](https://osv.dev) and attaches live vulnerability IDs
to the existing findings.

- `pkg/compliance/osv.go` — `OSVClient` (HTTP wrapper around
  `api.osv.dev/v1/query` with configurable timeout + base URL),
  `mapEcosystem` (translates per-parser labels to OSV identifiers
  PyPI / npm / Go), and `EnrichWithOSV` (5-worker concurrent fan-out,
  attaches `LiveVulnIDs` to matching findings).
- Env-var configuration: `AICAP_OSV_DISABLED=true` skips entirely,
  `AICAP_OSV_URL` overrides the base URL (used by tests to point at
  `httptest.NewServer`), `AICAP_OSV_TIMEOUT_MS` overrides the per-call
  timeout (default 1500ms).
- `types.RiskFinding.LiveVulnIDs []string` (omitempty so legacy proof
  drills don't carry phantom empty arrays).
- `compliance.GenerateAnnexIVMarkdownWithRegister(bom, register)` —
  pure formatter that takes a pre-computed register so the rendered
  markdown reflects OSV enrichment. The legacy
  `GenerateAnnexIVMarkdown(bom)` delegates to it.
- `/api/save-proof` flow: `ComputeRiskRegister(bom)` →
  `NewOSVClient()` (nil if disabled) → `EnrichWithOSV` (5s timeout)
  → `GenerateAnnexIVMarkdownWithRegister(bom, register)` → persist.
- Annex IV § 3(a) table grows a "Live CVE/GHSA" column rendering IDs
  as inline code spans (or "—" when absent).
- 10 new unit tests with `httptest.NewServer` covering happy path,
  timeout, disabled mode, non-200 response, ecosystem-label mapping,
  attach-to-matching-finding, no-match no-op, nil-client no-op, error
  fallback, markdown column rendering.

Failure mode (deliberate): if OSV is unreachable / slow / rate-limiting,
the catalog-derived finding still lands — we just lose the LiveVulnIDs
decoration. Compliance reporting stays deterministic in CI even when a
third-party API is having a bad day.

## Pending work (Wave 7c–7f remainder)
None. Phase 8 (GTM / landing page / SEO) and the remaining Phase 5
items (EU hosting migration off Render) stay as deliberately-deferred
Tier D work per the user's direction; they are quarter-scale projects,
not commit-scale. Wave 8a (below) closes the Helm-chart half of
Phase 5.

### Wave 8a (shipped — Helm chart for self-hosted Enterprise tier)

The original blueprint analysis flagged "Helm chart for the Enterprise
tier" as the gateway to Phase 5 (Sovereignty), and successive
reassessments left Phase 5 at 10% because no infrastructure-as-code
deliverable existed. Wave 8a adds a production-grade Helm chart at
`deploy/helm/aicap/` so an on-prem / sovereign-cloud customer can
`helm install aicap ./deploy/helm/aicap -f my-values.yaml` and run
the backend in their own cluster against their own Postgres.

- **Chart layout** — `Chart.yaml` (apiVersion v2, appVersion 0.7.0),
  `values.yaml`, `README.md`, `.helmignore`, plus templates:
  `_helpers.tpl`, `configmap.yaml`, `secret.yaml`, `deployment.yaml`,
  `service.yaml`, `ingress.yaml`, `serviceaccount.yaml`, `hpa.yaml`,
  `poddisruptionbudget.yaml`, `migration-job.yaml`, `NOTES.txt`.

- **Probes wired to Wave-4 split** — `livenessProbe` hits `/livez`
  (always 200 if the process can serve, so a failing DB does NOT
  trigger pod restart-loops); `readinessProbe` hits `/readyz` (503
  when the DB ping fails, so the orchestrator pulls the pod out
  of the LB).

- **Secrets handling** — two modes. Inline (`secrets.supabaseDbUrl`
  etc. set in values) for dev / quick-start; external
  (`secrets.existingSecret: my-secret`) for production with
  sealed-secrets / external-secrets / vault. The chart hashes the
  rendered ConfigMap + Secret content into pod annotations so a
  `helm upgrade` with changed values rolls the pods automatically.

- **Migration strategy** — two opt-in modes. Default
  (`config.runMigrations=true`) runs migrations on pod startup,
  matching the existing Render deployment shape. Opt-in
  (`migrationJob.enabled=true`) creates a pre-upgrade Helm hook
  Job running `aicap --migrate`, which gates the rollout on
  migration success. Pre-upgrade only (not pre-install) because
  chart-managed Secrets aren't rendered until the main install
  phase; first installs use startup-mode migration. Documented
  in chart README with the workaround (use `existingSecret` if
  you need migration-gated first installs).

- **Security defaults** — non-root uid 65532 (matches the
  distroless `nonroot` user in the Dockerfile),
  `readOnlyRootFilesystem: true` with an `emptyDir` mounted at
  `/tmp` for stdlib helpers, all caps dropped,
  `automountServiceAccountToken: false` (the binary doesn't talk
  to the Kubernetes API), `seccompProfile: RuntimeDefault`.

- **Optional resources** — `Ingress` (off by default — bring your
  own controller), `HorizontalPodAutoscaler` (off by default,
  configured for CPU + memory targets), `PodDisruptionBudget`
  (off by default; recommended for prod via `minAvailable: 1`).

- **What the chart does NOT deploy** — Postgres (bring your own:
  Supabase, RDS, Cloud SQL, in-cluster CloudNativePG; bundling
  storage choices conflicts with each operator's durability
  policy) and the React frontend (static site → Vercel /
  Cloudflare Pages / separate Deployment + Ingress). The chart's
  `viteFrontendUrl` value is the CORS allowlist for the frontend
  origin.

- **No tests yet** — Helm isn't part of the Go module's CI toolchain.
  A `helm lint` + `helm template` smoke job in
  `.github/workflows/` is queued for a follow-up wave.

## Pending work (Wave 8a remainder)
None for the Helm chart itself. CI smoke-test (helm lint + template
render against multiple value sets) is queued alongside the EU hosting
migration evaluation as part of the Phase-5 follow-up wave.

### Wave 8b (shipped — Phase 8 GTM surface, commit-scale)

Phase 8 (GTM) had stayed at 15% across every reassessment because no
public marketing surface, SEO infrastructure, or contributor docs
existed. Wave 8b lands the commit-scale half of Phase 8: a real
landing page on the unauthed path, SEO meta + structured data, modern
multi-platform CI templates, and a `CONTRIBUTING.md`.

- **`frontend/index.html`** — replaced the placeholder `<title>frontend</title>`
  with a real SEO-shaped `<head>`: title, meta description, keywords,
  robots, canonical, Open Graph, Twitter card, theme-color, and JSON-LD
  structured data (`SoftwareApplication` with two `Offer` blocks for
  Free + Pro pricing, `Organization` publisher). Crawlable on first
  paint without server-side rendering.

- **Public marketing surface under `LandingAuth`** — three new
  components mounted below the existing hero + auth form on the unauthed
  path:
  - `components/PricingSection.jsx` — three-tier card (Free CLI / Pro
    $49/mo / Enterprise self-host) with feature lists, CTAs, and
    `mailto:enterprise@aicap.dev` for sales. The `id="pricing"`
    target lets footer / external links scroll-link directly.
  - `components/FAQSection.jsx` — 8 FAQ entries answering the
    questions a prospect actually asks before signing up (CLI vs SaaS
    boundary, what Annex IV covers, ledger immutability, data
    residency, Stripe failure handling, telemetry, policy gating).
    Renders as native `<details>` for keyboard accessibility +
    crawler readability.
  - `components/MarketingFooter.jsx` — four-column footer (Product,
    Resources, Compliance, Contact) with the legal/nav links a
    marketing surface needs. Year auto-updates via `new Date()`.
  The form panel grew an `id="signup"` so the Pricing CTA can scroll
  to it. The "Trust/Social Proof" strip lost its `pb-10` so the new
  sections flow without a double border.

- **`templates/gitlab-ci.yml`** — rewrite. Old version cloned the
  repo and `go build`-ed on every pipeline (slow, wasteful, pinned
  Go 1.22). New version pulls the pre-built `aicap-linux-amd64`
  release binary from a configurable `AICAP_VERSION` (default
  `v1.0.0-beta` to match `action.yml`), uses `alpine:3.20` (no Go
  toolchain needed), exposes a reusable `.aicap-base` extends-anchor,
  and adds an optional `aicap_cyclonedx_sbom` job that emits the
  CycloneDX SBOM as a 30-day artifact.

- **`templates/bitbucket-pipelines.yml`** — same rewrite pattern.
  Anchored steps (`*aicap-scan`, `*aicap-cyclonedx`) for default /
  PR / branch flows; CycloneDX SBOM artifact on `main` and `master`.
  Drops the Go toolchain dependency.

- **`CONTRIBUTING.md`** — repo-root contributor guide. Covers branch
  model (PR `development`, never `main`), local backend + frontend
  + Helm-chart workflows, ranked list of high-impact contribution
  types (manifest parsers, risk-catalog entries, GPU cost catalog,
  governance detectors, CI templates), explicit "what we won't
  merge" list (large renames, speculative abstractions, third-party
  services without a fallback, hash-formula changes without a chain
  migration story), and security-disclosure email.

- **No new backend code** — Wave 8b is purely surface / docs / CI
  template work. Frontend tests still 9-passing, build still green
  (one fix: dropped the lucide `Github` icon that was removed
  upstream).

## Pending work (Wave 8b remainder)
The remaining Phase 8 ground is non-commit-scale: programmatic SEO
content (long-tail technical guides), screenshots in the README,
GitHub Marketplace listing curation, and a public docs site
(currently the README is the docs). Phase 5 still has the EU hosting
migration off Render queued. Both are next-wave Tier D.

### Wave 10 (shipped — daemonless container-image filesystem scanning)

Phase 2 had been stuck at ~92% because the scanner only walked the
filesystem of the repo it was invoked on. A CI pipeline that built a
container image then pushed it got zero scanning on the image
contents — exactly where the production-deployed model weights and
pip-installed AI deps actually live. Wave 10 closes that gap with a
daemonless image scanner.

- **`pkg/imagescan/`** — new package, ~340 LoC over `imagescan.go`
  (entry points) + `layer.go` (per-entry detection). Uses
  `github.com/google/go-containerregistry` v0.21.5, the same
  daemonless image-handling library Helm / ko / Skaffold use.
  - `ScanImage(ctx, ref)` — pulls a registry image via
    `remote.Image` with `authn.DefaultKeychain` (picks up
    `docker login` state, GitHub Actions `GITHUB_TOKEN`-derived
    ghcr.io creds, GCR / ACR / ECR helpers on PATH).
  - `ScanTarball(ctx, path)` — reads a `docker save` tarball via
    `tarball.ImageFromPath`, passing nil tag so the first image
    in the manifest is used (the typical single-tag save shape).
  - `ScanRefs(ctx, refs, tarballs)` — CLI-facing aggregator that
    returns flattened dependencies + per-image `ScannedImage`
    provenance entries + per-image error strings. Best-effort
    contract: one unreachable registry does not suppress
    findings from a sibling tarball.

- **Per-layer detection** in `scanLayer`. Walks each uncompressed
  layer tar (`v1.Layer.Uncompressed()`) and matches three kinds of
  entry:
  - **Model weight files** — same extension set as the directory
    scanner (`.safetensors`, `.onnx`, `.pt`, `.h5`, `.gguf`, `.bin`,
    `.tflite`, `.pb`, `.mlmodel`, `.ckpt`) plus the sentinel
    filenames `pytorch_model.bin` and `model.safetensors`. Header
    only, body never read (model files are huge; the path + size
    is what auditors care about).
  - **Python `dist-info/METADATA`** — PEP 566 RFC-822-style header
    block. Name + Version parsed from the first blank-line-delimited
    block (multi-line continuations don't apply to these fields).
    Cross-referenced against `scanner.LookupLibrary` (new exported
    helper) so `numpy` doesn't fire but `openai` / `torch` do.
  - **Node `node_modules/.../package.json`** — top-level Name +
    Version. Tolerant lookup (`extractStringField`) rather than
    `encoding/json` because some real-world package.json files
    have trailing-comma quirks from build tools. Root-level
    package.json is deliberately ignored — the directory scanner
    already catches it, and double-reporting would inflate counts.

- **Safety rails** for hostile layers:
  - `maxMetadataBytes = 256 KB` cap on any entry we choose to read
    into memory. Model files are never read; oversized "METADATA"
    or "package.json" entries are skipped.
  - Whiteout markers (`.wh.*`) are explicitly ignored — they're
    docker/OCI deletion sentinels, not content.
  - Per-layer error from `layer.Uncompressed()` returns ignored:
    one malformed layer doesn't crash the whole scan.

- **`types.AIBOM.ScannedImages []ScannedImage`** — new optional
  field carrying per-image provenance: `Reference`, `Digest` (sha256
  of the manifest), `Source` (`"registry"` or `"tarball"`), `Layers`,
  `FindingCount`. Per-finding `Location` strings carry
  `image#layerN:path` so an individual finding traces back to its
  layer.

- **CLI surface** — `main.go --cli` now accepts:
  - `--image <ref>` (repeatable) — registry reference
  - `--image-tar <path>` (repeatable) — local docker-save tarball
  - existing `--cyclonedx` still works
  - `parseCLIArgs` is extracted as a testable helper. Unknown flags
    AND their next-token value are silently consumed for forward
    compatibility — an older binary called by a newer `action.yml`
    that passes a new flag does not abort the pipeline.
  - Failures (unreachable registry, malformed tarball) surface as
    `[-] Warning: container-image scan: ...` and the directory-scan
    findings still ship.
  - Compliance posture is re-evaluated after image findings merge,
    so a high-risk model weight discovered in a layer flips the BOM
    to "Action Required" the same as one on disk would.

- **`pkg/scanner.LookupLibrary(name) (LibraryMeta, bool)`** — new
  exported helper so out-of-package scanners (today: `pkg/imagescan`;
  tomorrow: anything else that needs to cross-reference against the
  curated AI catalog) can look up names without duplicating the
  `libraries.json` data.

- **Annex IV § 2(d) "Container Images Inspected (Daemonless Layer
  Scan)"** — new sub-section in `compliance.GenerateAnnexIVMarkdownWithRegister`
  and the frontend mirror in `lib/annexIV.js`. Lists each scanned
  image with its source + layer count + finding count + digest.
  Omitted entirely when `bom.ScannedImages` is empty (no orphan
  header).

- **Tests** — 27 new tests:
  - **`pkg/imagescan/layer_test.go`** (16 tests): in-memory tar
    fixtures via `buildTar`; AI / non-AI Python `dist-info` lookup;
    model-weight detection per extension; sentinel filenames;
    whiteout markers skipped; oversized METADATA entries skipped;
    case-insensitive METADATA header keys; `parsePythonMetadata`
    stops at first blank line; `isPythonDistInfoMetadata` and
    `isNodePackageJSON` path predicates; `formatImageLocation`;
    `extractStringField` whitespace tolerance.
  - **`pkg/imagescan/imagescan_test.go`** (4 tests): end-to-end
    `ScanTarball` round-trip via `tarball.WriteToFile` of a two-layer
    synthetic image; non-existent path error; in-process
    `registry.New()` httptest server proving `ScanImage` walks
    registry-pulled layers; `ScanRefs` partial-failure contract.
  - **`main_test.go`** (5 tests): `parseCLIArgs` directory default,
    repeatable flags, forward-compat unknown-flag tolerance, missing
    trailing value tolerance.
  - **`pkg/scanner/scanner_test.go`** (2 tests): § 2(d) rendered when
    `ScannedImages` populated, omitted when empty.

- **No backwards-compatibility shims** — `bom.ScannedImages` is
  optional (`omitempty`), the directory-scan path is unchanged,
  and existing CI pipelines that don't pass `--image` see identical
  behavior to v1.1.0.

## Pending work (Wave 10 remainder)
None. Phase 2 reaches ~100% with this wave. The next quarter-scale
work is QA (EU hosting migration → Phase 5), QD (advanced FinOps:
spot pricing, rightsizing → Phase 6), or QB+QC (SEO content +
GitHub Marketplace listing → Phase 8). Per the user's direction,
all three are deferred Tier D.

## Wave 3b/3c deployment checklist (run before merging to main)
- [ ] RLS can stay as-is after Wave 3c — the frontend no longer reads `api_keys`
      directly, so `auth.uid() = user_id` row policies are sufficient as a
      defense-in-depth layer. A missing SELECT policy would no longer break the UI.
- [ ] Deploy with `RUN_MIGRATIONS=true` so 00008 + 00009 run against prod Supabase
- [ ] Confirm `ALTER TABLE api_keys DROP COLUMN token` succeeded (migration 00009)
- [ ] Test end-to-end: fresh signup → Stripe checkout → lands on Pro screen with
      key revealed → refresh page → still on Pro screen (not paywall)
- [ ] Test webhook fallback: with `STRIPE_WEBHOOK_SECRET` unset or the webhook
      disabled, complete checkout → `/api/verify-checkout` should still upgrade
      the user within ~7 s (Step 3 of the fallback chain)

## Key design decisions (do not re-litigate without good reason)
- **One key per user** enforced by `UNIQUE(user_id)` on `api_keys` — not application logic
- **No dual-auth bridge** on dashboard routes — there are no active users so no
  migration window was needed; API keys are simply rejected at `/api/history` and `/api/proof`
- **Stripe webhook does NOT materialise a raw key** — it upserts tier, frontend generates key
- **Frontend never reads `api_keys` directly via Supabase JS client** (post-Wave-3c) —
  all session state goes through `/api/me`. RLS remains as defense-in-depth, but
  application correctness does not depend on its configuration.
- **Checkout completion uses `Status == complete`, not `PaymentStatus == paid`** —
  for `mode=subscription`, Stripe fires `checkout.session.completed` before the
  first invoice payment settles, so `PaymentStatus` can be `unpaid` or
  `no_payment_required` even on a successful checkout.
- **`log/slog` for all structured logging**, not `log.Printf` — request-scoped logger
  via `httplog.From(r.Context())`, global logger via `slog.Default()`
- **`sha256.Sum256([]byte(key))` + `hex.EncodeToString`** is the canonical hash —
  matches Postgres `encode(sha256(convert_to(token, 'UTF8')), 'hex')`

## Notes on the test suite
- Unit tests: `go test ./...` — no DB, no Docker, runs everywhere
- Integration tests: `go test -tags=integration ./...` — requires `TEST_DATABASE_URL`
- `setup(t)` in `api_integration_test.go` applies all migrations + truncates tables
- `seedAPIKey` inserts a hashed key (post-Wave-3b); returns plaintext for headers
- `mintJWT` generates a test HS256 JWT using `jwtSecret = "integration-test-secret-do-not-use-in-prod"`
- Stripe webhook tests use `webhook.GenerateTestSignedPayload` with a local secret;
  event payloads must include `"api_version": "2024-06-20"` or `ConstructEvent` rejects them
