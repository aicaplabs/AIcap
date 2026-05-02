# Changelog

All notable changes to AIcap are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Trial of new features lands on `development` first. Once a stable
batch is ready, it is merged to `main` and tagged.

## [1.1.0] — 2026-05-02 — Self-host, GTM surface, billing self-serve & live CVE enrichment

### Added — Helm chart for self-hosted Enterprise tier (Wave 8a)
- **`deploy/helm/aicap/`** — production-grade Helm chart so Enterprise
  customers can `helm install aicap ./deploy/helm/aicap -f my-values.yaml`
  and run the backend in their own cluster against their own Postgres.
- Probes wired to the Wave 4 split: `livenessProbe → /livez` (never
  restarts pods on DB outage), `readinessProbe → /readyz` (pulls out
  of LB when DB ping fails).
- Dual secrets mode: inline values for dev/quick-start; `existingSecret`
  for production with sealed-secrets / external-secrets / Vault.
- Migration strategy: `config.runMigrations=true` (startup mode, default)
  or `migrationJob.enabled=true` (pre-upgrade Helm hook Job).
- Security defaults: non-root uid 65532, `readOnlyRootFilesystem: true`,
  all caps dropped, `automountServiceAccountToken: false`,
  `seccompProfile: RuntimeDefault`.
- Optional `Ingress`, `HorizontalPodAutoscaler`, and `PodDisruptionBudget`
  (all off by default; recommended values documented in chart README).

### Added — GTM surface & public marketing (Wave 8b)
- **SEO-shaped `<head>`** in `frontend/index.html`: title, meta
  description, Open Graph, Twitter card, JSON-LD `SoftwareApplication`
  structured data with `Offer` blocks for Free + Pro pricing.
- **`PricingSection.jsx`** — three-tier card (Free CLI / Pro $49/mo /
  Enterprise self-host) with feature lists and CTAs.
- **`FAQSection.jsx`** — 8 entries answering the questions a prospect
  asks before signing up; native `<details>` for keyboard accessibility
  and crawler readability.
- **`MarketingFooter.jsx`** — four-column footer (Product, Resources,
  Compliance, Contact).
- **`templates/gitlab-ci.yml`** rewrite — pulls the pre-built
  `aicap-linux-amd64` release binary instead of building from source;
  optional `aicap_cyclonedx_sbom` job as a 30-day artifact.
- **`templates/bitbucket-pipelines.yml`** rewrite — anchored steps for
  default / PR / branch flows; CycloneDX SBOM artifact on `main` and
  `master`.
- **`CONTRIBUTING.md`** — branch model, local workflows, ranked list of
  high-impact contribution types, "what we won't merge" list, and
  security-disclosure email.

### Added — Annex IV § 1 auto-fill + Helm CI smoke (Wave 9)
- **`.aicap.yml`** project config file: declare `system_name`,
  `version`, `provider`, `intended_purpose`, `deployment_context`,
  and `high_risk_category` in the repo; the scanner reads these and
  populates Annex IV § 1 (General Description) automatically instead
  of emitting `[REQUIRES MANUAL INPUT]` placeholders.
- **Helm lint + template CI** — `.github/workflows/helm-lint.yml` runs
  `helm lint` and five `helm template` variant renders (defaults,
  inline secrets, external secrets, migrationJob mode, HPA + Ingress +
  PDB) on every push/PR touching the chart.

### Added — Stripe billing self-serve (Wave 7e)
- `POST /api/customer-portal` — Supabase JWT-gated; creates a Stripe
  BillingPortal session and returns `{url}`. Returns 400 for free-tier
  users (no Stripe customer). Frontend "Manage subscription" button
  POSTs via `apiFetch` (401 refresh-and-retry applies) and redirects
  same-tab.

### Added — Live CVE/GHSA enrichment via OSV.dev (Wave 7f)
- `pkg/compliance/osv.go` — `OSVClient` wraps `api.osv.dev/v1/query`
  with configurable timeout + 5-worker concurrent fan-out.
  `EnrichWithOSV` attaches `LiveVulnIDs` to catalog-matched findings.
- Annex IV § 3(a) gains a "Live CVE/GHSA" column rendering live IDs
  as inline code spans; "—" when absent.
- Curated catalog stays primary; OSV failures fall back to
  catalog-only findings deterministically so compliance reports stay
  reproducible in CI.
- Configurable via `AICAP_OSV_DISABLED` / `AICAP_OSV_URL` /
  `AICAP_OSV_TIMEOUT_MS`.

### Fixed — CI reliability
- Security-scan steps in `staging-scan.yml` and `test-scan.yml` now
  use `continue-on-error: true` so a compliance finding (intended
  scanner output) shows as a warning rather than failing the job.
- Helm `NOTES.txt` type error: `config.runMigrations` changed from
  string `"true"` to boolean `true` in `values.yaml`; template
  condition updated to a truthiness check so `--set
  config.runMigrations=false` no longer triggers an incompatible-types
  comparison error.

### Maturity snapshot (vs v1.0.0-alpha baseline)
| Phase | v1.0.0-alpha | v1.1.0 | Δ |
|---|---|---|---|
| Phase 1 (Stack) | 70% | 95% | +25 |
| Phase 2 (Scanning) | 40% | 92% | +52 |
| Phase 3 (Compliance) | 20% | 95% | +75 |
| Phase 4 (CI/CD) | 60% | 98% | +38 |
| Phase 5 (Sovereignty) | 10% | 60% | +50 |
| Phase 6 (FinOps) | 15% | 75% | +60 |
| Phase 7 (Pricing) | 30% | 95% | +65 |
| Phase 8 (GTM) | 10% | 55% | +45 |
| **Overall MVP readiness** | **~32%** | **~83%** | **+51** |

## [0.7.0] — internal milestone, 2026-04-30 — Compliance intelligence + FinOps cost + multi-manifest

Internal development milestone. Not released as a GitHub tag; all
changes below shipped in v1.1.0.

### Added — scanning depth (Wave 7c)
- **Lockfile parsers** — `poetry.lock`, `Pipfile.lock`, `pnpm-lock.yaml`,
  `yarn.lock`, `environment.yml` (Conda). Lockfiles are the authoritative
  version source; previous waves only saw the looser-pinned manifests.
- **Multi-language SBOM coverage**: Python (pip / Poetry / Pipenv /
  Conda), Node.js (npm / pnpm / yarn), Go (`go.mod`), and container
  images (`Dockerfile` base images + `pip install` lines in `RUN`).

### Added — FinOps cost estimation (Wave 7b)
- **`pkg/finops/`** new package with embedded `gpu_costs.json` curated
  catalog covering AWS p3/p4d/p4de/p5/g4dn/g5/g5g/g6/inf1/inf2/trn1,
  Azure NC/ND/NV, and GCP a2-highgpu/a2-megagpu/a3-highgpu/g2-standard.
- `LookupGPUCost(content)` returns hourly + monthly USD ranges per
  detected instance family; nil when the catalog has no match.
- `EstimateBOMCost(bom)` aggregates per-finding costs into a BOM-level
  summary with costed/uncosted finding counters so auditors know when
  the headline figure is missing detections.
- Per-finding cost line + BOM-level total + assumptions disclaimer
  rendered into Annex IV § 2(c) and the dashboard FinOps table.

### Added — Annex IV § 3(c) + § 4 auto-population (Wave 7a)
- `pkg/scanner/governance.go` — six conservative IaC detectors:
  - **HITL** from k8s `metadata.name` patterns (word-bounded
    `review|approval|human|hitl|moderation|feedback|judge|reviewer|escalation`),
    Argo Workflow `suspend:` steps, GitHub Actions `environment:` keys.
  - **Training data** from `*.dvc` / `dvc.yaml` / `dvc.lock`, Terraform
    `aws_s3_bucket` / `google_storage_bucket` matching training-data
    name patterns, and HuggingFace `from datasets import load_dataset(...)`.
  - **Bias monitoring** from Python imports of `fairlearn` / `aif360` /
    `responsibleai` / `equalized_odds` plus their entries in
    `requirements.txt` / `pyproject.toml`.
  - **Prompt-injection defences** from imports of `lakera` /
    `lakera_guard` / `rebuff` / `nemoguardrails` / `presidio_analyzer`
    / `garak` / `llm_guard` plus same names in dependency manifests.
- Annex IV § 3(c) and § 4 sub-sections render evidence when found,
  keep `[REQUIRES MANUAL INPUT]` when not — never both at once.
  Frontend `lib/annexIV.js` mirrors backend rendering.

### Added — Article 9 risk register (Wave 6 Phase B)
- `pkg/compliance/vulns.json` — embedded curated AI risk catalog
  (tensorflow, torch, pytorch, transformers, langchain, openai,
  anthropic, huggingface_hub, scikit-learn, diffusers) mapping each
  to OWASP ML Top 10 / MITRE ATLAS / EU AI Act articles / mitigation.
- `ComputeRiskRegister(bom)` cross-references detected deps; result
  persists into `proof_drills.risk_register_state` (the JSONB column
  that had been empty since migration 00002).
- Annex IV § 3(a) "Cross-Referenced Risk Register (OWASP ML Top 10 /
  MITRE ATLAS)" replaces the previous minimal heuristic table.

### Changed — Stripe lifecycle correctness (Wave 6 Phase A)
- **Idempotent `/api/save-proof` by `(user_id, commit_sha)`**.
  Migration 00011 adds a partial UNIQUE index. The handler does a
  SELECT-first short-circuit inside the existing per-user advisory
  lock; CI retries return 200 OK with the existing `cryptoHash` and
  `{idempotent: true}`, no duplicate audit row.
- **`customer.subscription.updated`** now reflects Stripe status into
  `api_keys.subscription_tier`. `active`/`trialing` → `pro`,
  anything else (`past_due`, `canceled`, `incomplete_expired`,
  `unpaid`, `paused`) → `free`. Users whose card declines lose Pro
  on the next save-proof.
- **Soft revoke** — `subscription.deleted` and `payment_failed`
  (after 3 attempts) now `UPDATE … SET subscription_tier = 'free'`
  instead of `DELETE FROM api_keys`. The `token_hash` survives, so
  re-subscribers don't have to regenerate their CI key.

### Changed — frontend split + first tests (Wave 5)
- `frontend/src/App.jsx` reduced from **1059 → 316 lines** (−70%) by
  extracting `lib/supabase.js` (client + `apiFetch`), `lib/annexIV.js`
  (markdown builder + download), and 9 components under
  `components/`. App.jsx is now a top-level state machine + view
  router only.
- First-ever frontend tests via Vitest + React Testing Library:
  `apiFetch.test.js` covers the 401 refresh-and-retry contract;
  `KeyVault.test.jsx` covers the three-state UI machine.

### Added — Wave 4 platform hardening
- **Hash-chain ledger anchoring** — migration 00010 adds `prev_hash`
  on `proof_drills`. Each save-proof opens a transaction, takes a
  per-user `pg_advisory_xact_lock`, and writes a row whose
  `crypto_hash` is `sha256(commit_sha || ai_bom_json || prev_hash)`.
  `GET /api/verify-chain` walks the chain and reports the first
  divergence.
- **Refresh-token recovery** — `onAuthStateChange` branches on
  `TOKEN_REFRESHED` to update only `accessToken` without re-running
  the bootstrap flow. `apiFetch` reads the live token from
  supabase-js's cache and on a 401 calls `refreshSession()` once
  and retries.
- **`/livez` + `/readyz` split** — liveness stays 200 on DB outage;
  readiness pulls out of LB. `/healthz` kept as a `/readyz` alias.
- **CI integration tests** — GitHub Actions runs unit +
  `go test -tags=integration` against a Postgres 16 service container.

### Added — Wave 3 SaaS readiness (3a / 3b / 3c)
- Stripe webhook replay protection via `stripe_events` PK idempotency.
- `pkg/httplog` slog JSON handler with per-request `X-Request-ID`.
- Graceful shutdown with 25 s SIGTERM drain.
- API keys hashed at rest (SHA-256). Plaintext returned exactly once
  from `/api/generate-key` or `/api/rotate-key`. Migration 00009.
- `/api/me` (RLS-independent reads via the direct Postgres connection).
- `/api/verify-checkout` Stripe API fallback when the webhook is
  delayed or misconfigured.

### Added — Wave 2 ops baseline
- Embedded SQL migration runner (`pkg/migrate`) with idempotency.
- Docker multi-stage build + `docker-compose.yml` for local Postgres.
- Integration test suite behind `//go:build integration`.
- Rolling 30-day rate-limit query.

### Added — Wave 1 tenant + auth baseline
- Supabase JWT auth on dashboard routes; API key auth on CI route.
- Tenant scoping on `/api/history` and `/api/proof` (user_id isolation).
- CORS preflight fix (OPTIONS passes through auth middleware).
- Free tier: 10 scans / 30-day rolling window.

[Unreleased]: https://github.com/istrategeorge/AIcap/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/istrategeorge/AIcap/compare/v1.0.0-beta...v1.1.0
