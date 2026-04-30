# Changelog

All notable changes to AIcap are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Trial of new features lands on `development` first. Once a stable
batch is ready, it is merged to `main` and tagged.

## [0.7.0] — 2026-04-30 — Compliance intelligence + FinOps cost + multi-manifest

The 2026-Q2 hardening sequence converted AIcap from a working prototype
(MVP-readiness ~40% per the original blueprint analysis) to a compliance
platform with end-to-end Article 9 evidence (~85%+). Every value-prop
bullet on the marketing page now maps to a feature that demonstrably
works end-to-end.

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
  keep `[REQUIRES MANUAL INPUT]` when not — never both at once. Frontend
  `lib/annexIV.js` mirrors backend rendering.

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
  `KeyVault.test.jsx` covers the three-state UI machine. CI extended
  with a `frontend` job running lint + tests + build on every push/PR.

### Added — Wave 4 platform hardening
- **Hash-chain ledger anchoring** — migration 00010 adds `prev_hash`
  on `proof_drills`. Each save-proof opens a transaction, takes a
  per-user `pg_advisory_xact_lock`, and writes a row whose
  `crypto_hash` is `sha256(commit_sha || ai_bom_json || prev_hash)`.
  `GET /api/verify-chain` walks the chain and reports the first
  divergence. JSONB canonicalisation via `$1::jsonb::text` so insert
  bytes match SELECT bytes.
- **Refresh-token recovery** — `onAuthStateChange` branches on
  `TOKEN_REFRESHED` to update only `accessToken` without re-running
  the bootstrap flow. `apiFetch` reads the live token from
  supabase-js's cache (not React state), and on a 401 it calls
  `refreshSession()` once and retries.
- **`/livez` + `/readyz` split** — liveness stays 200 on DB outage so
  the orchestrator doesn't restart-loop healthy pods; readiness
  pulls out of LB. `/healthz` kept as a `/readyz` alias.
- **CI integration tests** — GitHub Actions matrix runs unit +
  `go test -tags=integration` against a Postgres 16 service container
  on every push/PR.

### Added — Wave 3 SaaS readiness (3a / 3b / 3c)
- Stripe webhook replay protection via `stripe_events` PK
  idempotency table.
- `pkg/httplog` slog JSON handler with per-request `X-Request-ID`.
- Graceful shutdown with 25 s SIGTERM drain.
- API keys hashed at rest (SHA-256). Plaintext returned exactly
  once from `/api/generate-key` or `/api/rotate-key`. Migration 00009.
- `/api/me` (RLS-independent reads via the direct Postgres
  connection) so session correctness doesn't depend on Supabase RLS
  configuration.
- `/api/verify-checkout` Stripe API fallback when the webhook is
  delayed or misconfigured.
- Frontend `INITIAL_SESSION` + `TOKEN_REFRESHED` race fix
  (`fetchSessionRef` latch).

### Added — Wave 2 ops baseline
- Embedded SQL migration runner (`pkg/migrate`) with idempotency.
- Docker multi-stage build + `docker-compose.yml` for local Postgres.
- Integration test suite behind `//go:build integration`.
- Rolling 30-day rate-limit query (replaces never-reset
  `scans_this_month` counter).

### Added — Wave 1 tenant + auth baseline
- Supabase JWT auth on dashboard routes; API key auth on CI route.
- Tenant scoping on `/api/history` and `/api/proof` (user_id isolation).
- CORS preflight fix (OPTIONS passes through auth middleware).
- Free tier: 10 scans / 30-day rolling window.

### Maturity (vs original blueprint analysis)
| Phase | Original | 0.7.0 | Δ |
|---|---|---|---|
| Phase 1 (Stack) | 80% | 95% | +15 |
| Phase 2 (Scanning) | 50% | 92% | +42 |
| Phase 3 (Compliance) | 35% | 88% | +53 |
| Phase 4 (CI/CD) | 70% | 95% | +25 |
| Phase 5 (Sovereignty) | 10% | 10% | +0 (deferred) |
| Phase 6 (FinOps) | 25% | 75% | +50 |
| Phase 7 (Pricing) | 35% | 90% | +55 |
| Phase 8 (GTM) | 15% | 15% | +0 (deferred) |
| **Overall MVP readiness** | **40%** | **~85%** | **+45** |

Phases 5 (sovereignty / EU hosting / Helm) and 8 (GTM / landing page
/ SEO) are quarter-scale projects intentionally deferred to a later
release.

[Unreleased]: https://github.com/istrategeorge/AIcap/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/istrategeorge/AIcap/releases/tag/v0.7.0
