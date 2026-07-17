# AIcap — Claude Code Context

## What this project is
**AIcap** — Continuous AI-BOM & Compliance Scanner for the EU AI Act.
- Go 1.26 backend + Supabase PostgreSQL + Stripe billing
- React/Vite frontend (single-page, no router)
- **EU-hosted (Wave 13):** backend on Scaleway Serverless Containers (`fr-par`, Paris);
  database on Supabase (`eu-west-1`, Ireland); frontend on Vercel. All persisted
  data stays within the EU.
- GitHub Action (`istrategeorge/AIcap@v1.3.3`) runs the CLI scanner in CI pipelines

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
| Browser (dashboard) | Supabase session JWT (`RequireSupabaseJWT`) | `/api/history`, `/api/proof`, `/api/verify-chain`, `/api/share-report`, `/api/create-checkout-session`, `/api/generate-key`, `/api/rotate-key`, `/api/verify-checkout`, `/api/me` |
| CI pipeline | API key hash (`RequireAPIKey`) | `/api/save-proof` |
| Anyone with a share token | none — the 256-bit token is the credential | `/api/public/report` |

**API keys are hashed at rest** (SHA-256, column `token_hash`). The plaintext is returned exactly once from `/api/generate-key` or `/api/rotate-key` and never stored. `HashAPIKey(raw)` in `pkg/auth` is the canonical hash function.

## Database schema (migrations 00001–00013)
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

- **Checkout return race fixed**: `onAuthStateChange` double-firing `INITIAL_SESSION` + `TOKEN_REFRESHED` caused two concurrent `/api/generate-key` calls. Fixed with a `useRef(false)` latch on `fetchAndSetUserSession`.
- **Checkout processing UI**: `checkoutProcessing` initialised from `session_id` URL param so spinner shows before auth state fires. Render checks `checkoutProcessing` BEFORE `!session` to avoid login-screen flash.
- **Webhook-independent verification**: `GET /api/verify-checkout?session_id=…` calls Stripe directly, confirms `Status == complete` (not `PaymentStatus == paid` — for `mode=subscription` that field can be `unpaid` on a valid checkout), and upserts Pro tier.
- **Checkout-return fallback chain** (in `fetchAndSetUserSession`):
  1. Call `/api/generate-key` (idempotent via 409).
  2. Poll `/api/me` 3 × 1.5 s for `tier == 'pro'` (normal webhook path).
  3. If still not Pro, call `/api/verify-checkout` (Stripe API fallback).
- **`/api/me` endpoint**: returns `{hasKey, tier}` via direct DB connection, bypassing Supabase RLS. Frontend no longer reads `api_keys` through the Supabase JS client; RLS stays enabled as defense-in-depth.

### Wave 4 (shipped — on development)
- **CI integration-test job** — `.github/workflows/go-test.yml` runs `go build`, `go test ./...`, and `go test -tags=integration ./...` (Postgres 16 service container) on every push/PR. Uses `go-version-file: go.mod`.
- **`/livez` vs `/readyz` split** — `/livez` always 200 (liveness: failing DB must not restart pod); `/readyz` returns 503 on DB ping failure; `/healthz` is an alias of `/readyz`.
- **Hash-chain ledger anchoring** — migration 00010 adds `prev_hash`. Each save-proof takes a per-user advisory lock (`pg_advisory_xact_lock`), reads chain head, writes a new row with `crypto_hash = sha256(commit_sha || ai_bom_json || prev_hash)`. `GET /api/verify-chain` returns `{ok:false, brokenAt, reason}` on first divergence. Formula degrades gracefully for legacy rows (unverified prefix).
- **Frontend refresh-token handling** — `TOKEN_REFRESHED` patches only `session.accessToken`. All dashboard fetches use `apiFetch` wrapper that reads the live token from supabase-js cache and, on 401, calls `refreshSession()` once before retrying.

### Wave 5 (shipped — frontend hygiene)
- **Frontend componentization** — `App.jsx` split into `lib/supabase.js` (Supabase client + `apiFetch` wrapper), `lib/annexIV.js` (Annex IV builder), and components: `Header`, `LandingAuth`, `CheckoutProcessing`, `Paywall`, `KeyVault`, `HistoryTable`, `AnnexIVPreview`, `ProDashboard`, `LocalDashboard`. `App.jsx` becomes top-level state machine + view router only.
- **Frontend tests (first-ever)** — Vitest + React Testing Library: `apiFetch.test.js` (401 → refreshSession → retry), `KeyVault.test.jsx` (three-state rendering). Run via `npm test`; CI extended to invoke them.

### Wave 6 (shipped — backend correctness + Article 9 risk register)

#### Phase A: Correctness gaps
- **Idempotent `/api/save-proof` by `(user_id, commit_sha)`** — migration 00011 adds a partial UNIQUE index. Handler short-circuits inside the advisory lock; CI retry returns 200 with `{status, cryptoHash, idempotent: true}`, no duplicate row.
- **`customer.subscription.updated` reflects tier** — `active`/`trialing` → `pro`, anything else → `free`. Rate-limiter applies immediately on tier flip.
- **Soft revoke on cancellation** — `subscription.deleted` and `invoice.payment_failed` now `UPDATE … SET subscription_tier = 'free'` instead of DELETE, so `token_hash` survives and re-subscribe restores Pro without key regen.

#### Phase B: Article 9 risk register
- **`pkg/compliance/vulns.json`** (embedded) — curated catalog keyed by lowercase dep name (tensorflow, torch, pytorch, transformers, langchain, openai, anthropic, huggingface_hub, scikit-learn, diffusers). Maps to OWASP ML Top 10, MITRE ATLAS, EU AI Act articles, severity, mitigation.
- **`pkg/compliance/risk_register.go`** — `ComputeRiskRegister(bom)` walks deps, looks up catalog, emits `types.RiskRegister` with per-finding rows + summary counts. `RenderRiskRegisterMarkdown` emits the Annex IV § 5 table.
- **Persistence** — `/api/save-proof` writes the register into `proof_drills.risk_register_state` (JSONB). Annex IV § 3(a) surfaces findings via "Cross-Referenced Risk Register (OWASP ML Top 10 / MITRE ATLAS)".
- **Tests** — 5 unit tests in `risk_register_test.go`; 2 integration tests (`TestSaveProof_PersistsRiskRegister`, `TestSaveProof_AnnexIVContainsRiskRegister`).

### Wave 7a (shipped — Annex IV § 4 auto-population from IaC)

- **`pkg/scanner/governance.go`** — six conservative detectors (false negatives over false positives). HITL: k8s manifest names (`(?i)\b(review|approval|human|hitl|moderation|…)\b`), Argo `suspend:`, GitHub Actions `environment:`. Training data: DVC files, Terraform bucket resources, HuggingFace dataset imports. Bias monitoring: `fairlearn`/`aif360`/`responsibleai` imports. Prompt-injection: `lakera`/`rebuff`/`nemoguardrails`/`presidio_analyzer`/`garak`/`llm_guard`.
- **`types.GovernanceTelemetry` + `types.GovernanceSignal`** — new `Governance` field on `AIBOM` with four buckets. Each signal carries `{Source, Location, Evidence, Description}`.
- **`compliance.GenerateAnnexIVMarkdown`** — § 3(c) and § 4 sub-sections emit evidence when signals detected, placeholders when not. Auditors see one or the other, never silent omission.
- **Frontend `lib/annexIV.js`** — mirrored `renderGovernance` helper with same evidence-or-placeholder pattern.
- **Tests** — 13 unit tests in `governance_test.go` (per-detector + PerformScan integration), 2 in `scanner_test.go` (Annex IV rendering), 1 integration test (`TestSaveProof_AnnexIVContainsGovernance`).

### Wave 7b (shipped — Phase 6 GPU cost estimation)

- **`pkg/finops/`** — new package mirroring `pkg/compliance/risk_register.go`. `gpu_costs.json` (embedded) — catalog for AWS p3/p4d/p4de/p5/g4dn/g5/g5g/g6/inf1/inf2/trn1, Azure NC/ND/NV, GCP a2/a3/g2 families with hourly USD low/high. `LookupGPUCost(content)` — first-match prefix lookup, returns `types.FinOpsCost`. `EstimateBOMCost(bom)` — aggregates into `FinOpsCostSummary`.
- **`types.FinOpsFinding.EstimatedCost`** and **`types.AIBOM.FinOpsCostEstimate`** — new optional fields (omitempty).
- **`pkg/scanner/scanner.go`** — `parseTerraformFile` delegates cost lookup to `pkg/finops`; inline instance maps removed. `PerformScan` calls `finops.EstimateBOMCost(bom)` after the walk.
- **Annex IV § 2(c)** — renamed to "Hardware Requirements & Estimated Monthly Cost (FinOps Telemetry)". Per-finding bullets include cost line; BOM-level total + assumptions block closes the section.
- **Frontend** — `LocalDashboard.jsx` FinOpsTable gains "Est. $/mo" column; `lib/annexIV.js` gains `renderFinOpsBlock`.
- **Tests** — 8 unit tests in `cost_test.go`; 2 in `scanner_test.go`; 1 integration test (`TestSaveProof_AnnexIVContainsCostEstimate`).

### Wave 7c (shipped — additional manifest parsers)

`pkg/scanner/manifests.go` adds five lockfile parsers (zero new dependencies, line/regex scanning):
- `poetry.lock` — TOML `[[package]]` blocks
- `Pipfile.lock` — JSON `default` + `develop` sections
- `pnpm-lock.yaml` — `packages:` map keyed by `/name@version`
- `yarn.lock` — `"name@range":` headers + `version "..."` rows
- `environment.yml` / `environment.yaml` — Conda deps + pip sub-block

7 unit tests cover one happy-path per parser plus Conda section-toggle and PerformScan integration.

### Wave 7d (shipped — CHANGELOG.md)
`CHANGELOG.md` at repo root: Keep-a-Changelog format covering waves 1–7c, maturity-table diff vs original blueprint, Phase 5/8 deferral notes.

### Wave 7e (shipped — Stripe customer portal)
- `POST /api/customer-portal` — JWT-gated; reads `stripe_customer_id`, creates BillingPortal session, returns `{url}`. Returns 400 for free-tier users (no Stripe customer).
- `frontend/src/components/ManageSubscriptionButton.jsx` — POSTs via `apiFetch`, redirects same-tab on success.
- 3 integration tests: missing-customer (400), unauthed (401), CORS preflight.

### Wave 7f (shipped — live OSV.dev CVE/GHSA enrichment)

- **`pkg/compliance/osv.go`** — `OSVClient` (HTTP wrapper, `api.osv.dev/v1/query`), `mapEcosystem` (labels → PyPI/npm/Go), `EnrichWithOSV` (5-worker fan-out, attaches `LiveVulnIDs` to matching findings).
- **Env vars**: `AICAP_OSV_DISABLED=true` skips entirely; `AICAP_OSV_URL` overrides base URL (tests use `httptest.NewServer`); `AICAP_OSV_TIMEOUT_MS` overrides timeout (default 1500ms).
- **`types.RiskFinding.LiveVulnIDs []string`** (omitempty).
- **`/api/save-proof` flow**: `ComputeRiskRegister` → `EnrichWithOSV` (5s timeout) → `GenerateAnnexIVMarkdownWithRegister` → persist. OSV failure is non-fatal: catalog finding still lands without LiveVulnIDs.
- **Annex IV § 3(a)** grows a "Live CVE/GHSA" column.
- 10 unit tests via `httptest.NewServer` (happy path, timeout, disabled, non-200, ecosystem mapping, attach-finding, no-match, nil-client, error fallback, markdown column).

### Wave 8a (shipped — Helm chart for self-hosted Enterprise tier)

Production-grade Helm chart at `deploy/helm/aicap/` — `helm install aicap ./deploy/helm/aicap -f my-values.yaml`.

- **Chart layout** — standard Helm structure: `Chart.yaml` (apiVersion v2, appVersion 0.7.0), `values.yaml`, plus templates: `_helpers.tpl`, `configmap.yaml`, `secret.yaml`, `deployment.yaml`, `service.yaml`, `ingress.yaml`, `serviceaccount.yaml`, `hpa.yaml`, `poddisruptionbudget.yaml`, `migration-job.yaml`, `NOTES.txt`.
- **Probes** — `livenessProbe` → `/livez`; `readinessProbe` → `/readyz`.
- **Secrets handling** — inline (values) for dev; `secrets.existingSecret` for production (sealed-secrets / vault). Pod annotations hash ConfigMap + Secret content so `helm upgrade` rolls pods on value change.
- **Migration strategy** — default (`config.runMigrations=true`) runs on startup; opt-in (`migrationJob.enabled=true`) runs a pre-upgrade hook Job. Pre-upgrade only (not pre-install) because chart Secrets aren't rendered at install time.
- **Security defaults** — uid 65532, `readOnlyRootFilesystem: true`, `emptyDir` at `/tmp`, all caps dropped, `automountServiceAccountToken: false`, `seccompProfile: RuntimeDefault`.
- **Optional resources** — Ingress, HPA, PodDisruptionBudget (all off by default).
- **Not bundled** — Postgres (bring your own: Supabase, RDS, Cloud SQL, CloudNativePG) and the React frontend (static site). `viteFrontendUrl` is the CORS allowlist.

### Wave 8b (shipped — Phase 8 GTM surface, commit-scale)

- **`frontend/index.html`** — real SEO `<head>`: title, meta description, Open Graph, Twitter card, JSON-LD `SoftwareApplication` structured data. Crawlable without SSR.
- **Public marketing surface** — three components under `LandingAuth`: `PricingSection.jsx` (three-tier pricing, `id="pricing"` scroll target), `FAQSection.jsx` (8 `<details>` FAQ entries), `MarketingFooter.jsx` (four-column footer, auto-year).
- **`templates/gitlab-ci.yml` + `templates/bitbucket-pipelines.yml`** — rewritten to pull the pre-built `aicap-linux-amd64` binary via `AICAP_VERSION` (no Go toolchain in CI), with optional CycloneDX SBOM artifact jobs.
- **`CONTRIBUTING.md`** — branch model, local dev workflows, high-impact contribution types (manifest parsers, risk-catalog entries, GPU cost catalog, governance detectors), and "what we won't merge" list.
- No new backend code; frontend tests still 9-passing.

### Wave 10 (shipped — daemonless container-image filesystem scanning)

- **`pkg/imagescan/`** — new package using `github.com/google/go-containerregistry` v0.21.5.
  - `ScanImage(ctx, ref)` — pulls via `remote.Image` + `authn.DefaultKeychain`.
  - `ScanTarball(ctx, path)` — reads `docker save` tarball via `tarball.ImageFromPath`.
  - `ScanRefs(ctx, refs, tarballs)` — CLI-facing aggregator; best-effort (one failure doesn't suppress sibling findings).

- **Per-layer detection** in `scanLayer` — three entry types:
  - **Model weight files** — `.safetensors`, `.onnx`, `.pt`, `.h5`, `.gguf`, `.bin`, `.tflite`, `.pb`, `.mlmodel`, `.ckpt` + sentinels `pytorch_model.bin` / `model.safetensors`. Header-only reads (bodies never read).
  - **Python `dist-info/METADATA`** — RFC-822 Name + Version, cross-referenced via `scanner.LookupLibrary`.
  - **Node `node_modules/.../package.json`** — tolerant field extraction; root-level package.json skipped (directory scanner already covers it).

- **Safety rails** — `maxMetadataBytes = 256 KB` cap; whiteout markers (`.wh.*`) skipped; per-layer errors ignored (best-effort).

- **`types.AIBOM.ScannedImages []ScannedImage`** — per-image provenance: `Reference`, `Digest`, `Source`, `Layers`, `FindingCount`. Per-finding `Location` = `image#layerN:path`.

- **CLI surface** (`main.go --cli`) — `--image <ref>` (repeatable), `--image-tar <path>` (repeatable). `parseCLIArgs` extracted as testable helper; unknown flags + their value silently consumed for forward compatibility. Image-scan failures surface as warnings; directory findings still ship. Compliance posture re-evaluated after image findings merge.

- **`pkg/scanner.LookupLibrary(name)`** — exported so `pkg/imagescan` and future packages cross-reference the AI catalog without duplicating `libraries.json`.

- **Annex IV § 2(d)** "Container Images Inspected (Daemonless Layer Scan)" — lists each image with source + layers + finding count + digest. Omitted when `bom.ScannedImages` is empty.

- **Tests** — 27 new: 16 in `layer_test.go` (model-weight detection per extension, Python dist-info, whiteout skipping, oversized-entry cap, path predicates, field extraction); 4 in `imagescan_test.go` (tarball round-trip, registry httptest, partial-failure); 5 in `main_test.go` (`parseCLIArgs` scenarios including forward-compat); 2 in `scanner_test.go` (§ 2(d) render toggle).

- **No backwards-compatibility shims** — `bom.ScannedImages` is omitempty; pipelines without `--image` see identical behavior to v1.1.0.

### Wave 13 (shipped — EU data residency: Render → Scaleway)

- **Backend moved off Render (US) to Scaleway Serverless Containers (`fr-par`, Paris).**
  Database was already on Supabase `eu-west-1` (Ireland), so no DB migration was
  needed — only the compute layer moved. All persisted data now resides in the EU.
- **`deploy/terraform/scaleway/`** — Terraform module provisioning a private
  Container Registry namespace (`rg.fr-par.scw.cloud/aicap`), a Serverless
  Container namespace, and the backend container. Secrets via `terraform.tfvars`
  (gitignored); non-secret config via `environment_variables`.
- **Free-tier posture** — `min_scale = 0` (scale-to-zero) keeps the deployment
  inside Scaleway's free allowance (400k vCPU-s + 1.6M GB-s/month) while there
  are no clients. Bump `min_scale = 1` / `max_scale = 3` in tfvars when paying
  customers arrive (~€20–25/mo, no cold starts). CPU:memory must satisfy
  `mem ∈ [cpu, 4·cpu]`; we run 512 mvCPU / 512 MB.
- **Scaleway gotchas baked into the module** — `PORT` is a reserved env var
  (injected from the `port` field, must not be set manually); `memory_limit_bytes`
  replaced the deprecated `memory_limit`; registry namespace creation needs an
  org-scoped `ContainerRegistryFullAccess` IAM rule (project scope is insufficient).
- **Image build** — Dockerfile `GO_VERSION` bumped 1.23 → 1.26 to match `go.mod`
  (`go 1.26.0`). Build + push: see `deploy/terraform/scaleway/README.md`.
- **Backend URL** — `https://aicap9ceb68db-aicap-backend.functions.fnc.fr-par.scw.cloud`
  (the free `.scw.cloud` subdomain). Frontend `VITE_API_URL` on Vercel points here.
  A custom domain (`api.aicap.eu` recommended) is a deferred launch-time task.
- **Data-residency statement** — `documentation/data-residency.md` documents where
  each data class lives, for enterprise/DPA due diligence.
- **Known pre-launch risk** — Supabase free tier auto-pauses on inactivity; a
  paused DB fails the container's startup `db.Ping()` and the backend won't boot.
  Before go-live: move to a paid Supabase tier (no auto-pause) or add a keep-alive.

### Wave 15 (shipped — conversion & distribution features, July 2026)

Monetization-focused wave; Wave 14 (SEO content + Marketplace listing) remains open.

- **Annex IV PDF export** — `frontend/src/lib/annexIVPdf.js`: zero-dependency
  markdown→print-HTML renderer + hidden-iframe `exportAnnexIVPdf` ("Save as
  PDF"). Provenance footer carries the ledger hash + AIcap branding. All
  content HTML-escaped (dep names are attacker-controlled). Export buttons in
  `AnnexIVPreview` and the public report page.
- **Sample report landing section** — `SampleReportSection.jsx`: full Annex IV
  sample for a fictional high-risk hiring system on the public landing page.
- **Deadline countdown** — `lib/deadline.js` + badge in `LandingAuth`; counts
  down to 2 Aug 2026, flips to "in force" copy after.
- **CLI README badge** — `badgeMarkdown` in `main.go` prints a shields.io
  snippet after each scan (passing / action required / policy breach).
- **Shareable report links** — migration 00013 adds `proof_drills.share_token`
  (partial unique index). `POST /api/share-report {hash}` mints a 256-bit hex
  capability token (idempotent: 200 + same token on re-share); `DELETE ?hash=`
  revokes. Public `GET /api/public/report?token=` resolves it unauthenticated
  (malformed/unknown/revoked all 404). Frontend: `?report=<token>` URL param
  renders `PublicReport.jsx` (bypasses the entire auth state machine); Share
  button in `AnnexIVPreview` (Pro dashboard only) copies the link.
- **Tests** — 5 integration (`TestShareReport_*`, `TestPublicReport_*`),
  13 frontend unit (annexIVPdf, deadline, PublicReport), 3 Go unit
  (`TestBadgeMarkdown_*`).

## Wave 3b/3c deployment checklist (run before merging to main)
- [x] RLS can stay as-is after Wave 3c — the frontend no longer reads `api_keys`
      directly, so `auth.uid() = user_id` row policies are sufficient as a
      defense-in-depth layer. A missing SELECT policy would no longer break the UI.
- [x] Deploy with `RUN_MIGRATIONS=true` so 00008 + 00009 run against prod Supabase
- [x] Confirm `ALTER TABLE api_keys DROP COLUMN token` succeeded (migration 00009)
- [x] Test end-to-end: fresh signup → Stripe checkout → lands on Pro screen with
      key revealed → refresh page → still on Pro screen (not paywall)
- [x] Test webhook fallback: with `STRIPE_WEBHOOK_SECRET` unset or the webhook
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
