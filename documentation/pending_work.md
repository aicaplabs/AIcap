# AIcap — Pending Work to 100% Readiness

_Last updated: 2026-05-11 (post Wave 10, overall readiness ~97%)_

---

## Current Maturity Snapshot

```
Phase 1 (Stack)        ~95%   ████████████░
Phase 2 (Scanning)     ~100%  █████████████
Phase 3 (Compliance)   ~98%   █████████████
Phase 4 (CI/CD)        ~100%  █████████████
Phase 5 (Sovereignty)  ~45%   █████░░░░░░░░
Phase 6 (FinOps)       ~85%   ███████████░░
Phase 7 (Pricing)      ~100%  █████████████
Phase 8 (GTM)          ~55%   ███████░░░░░░
─────────────────────────────────────────────
Overall                ~97%   █████████████
```

---

## Commit-Scale Remaining Work (Wave 9)

These are focused, mergeable items that collectively push overall readiness to ~97–98%.

### W9b — Helm CI smoke job (Phase 4 → 100%)

**What:** Add `.github/workflows/helm-lint.yml` running `helm lint` + `helm template` against three value sets:
- defaults (inline secrets, `runMigrations=true`)
- `existingSecret` path (external-secrets / vault)
- `migrationJob.enabled=true` (pre-upgrade hook)

**Why:** Wave 8a shipped the Helm chart with a "No tests yet" caveat. This closes it. Phase 4 hits 100%.

**Scope:** 1 commit, CI only.

---

### W9d — Annex IV Section 1 auto-fill from `.aicap.yml` (Phase 3 → ~98%)

**What:** `PolicyConfig` (in `pkg/types/types.go`) already has `Purpose`, `RiskLevel`, and `HighRisk` fields parsed from `.aicap.yml`. `GenerateAnnexIVMarkdown` currently emits `[REQUIRES MANUAL INPUT]` for Section 1 "Intended Purpose" regardless. Fix it to read `bom.Policy` and render the declared values when present.

**Why:** The last `[REQUIRES MANUAL INPUT]` placeholder that is actually auto-detectable. Closes the Phase 3 gap that the original analysis most cited.

**Scope:** 2 commits (compliance package + unit test).

---

### W9a — v0.7.0 git tag (Phase 4 → 100%)

**What:** After merging `development` → `main`, update `CHANGELOG.md` unreleased section to `[0.7.0]` and tag `v0.7.0` on `main`.

**Why:** Downstream consumers pinning `istrategeorge/AIcap@v0.7.0` are blocked until the tag exists. Currently Wave 1–8 work is shipped but untagged.

**Scope:** 1 admin commit + git tag.

---

### W9c — Reverse-trial UX (Phase 7 → 100%)

**What:** 14-day full-feature trial that downgrades gracefully.

Steps:
1. Migration `00012` — `trial_ends_at TIMESTAMPTZ` on `api_keys`
2. Trial-start: set `trial_ends_at = NOW() + 14d` on first `generate-key` for free-tier users
3. `/api/me` exposes `trialDaysRemaining` in response
4. `Paywall.jsx` shows trial CTA ("X days left on your trial") and a distinct expired state
5. Cron or `customer.subscription.trial_will_end` Stripe webhook downgrades tier at expiry

**Why:** The original blueprint specified a reverse trial as the core conversion mechanic. The current model is a hard paywall, which the analysis flagged. Phase 7 stays at 95% without it.

**Scope:** 3–4 commits (migration + backend + frontend).

---

### W9e — Live FinOps pricing (Phase 6 → ~85%)

**What:** Add `AICAP_GPU_COSTS_URL` env var. When set, `LookupGPUCost` fetches the JSON from that URL at startup (with a timeout) and falls back to the embedded `gpu_costs.json` catalog if unreachable. This allows the catalog to be updated without a binary release (e.g., via a GitHub Actions scheduled job that commits updated pricing data).

**Why:** The static catalog approach was deliberately chosen for the MVP but was flagged as the remaining 25% of Phase 6. Dynamic pricing makes the FinOps section genuinely useful for cost-control decisions.

**Scope:** 2 commits (finops package + env-var wiring).

---

## Quarter-Scale Remaining Work

These require dedicated sprints, not single commits. They account for the remaining ~3–6% of overall readiness that commit-scale work cannot close.

### QA — EU Sovereignty sprint (Phase 5: 45% → ~90%)

The EU hosting migration is what separates "compliant tool hosted on a US platform" from a genuine EU data-sovereignty story.

Steps:
1. Evaluate Hetzner Cloud vs Scaleway (cost, region availability, managed Postgres SLA)
2. Write Terraform module: VMs / container instances, managed Postgres, DNS, TLS
3. Execute Render → chosen EU provider cutover with zero-downtime (DNS TTL, parallel deploy, health-check gating before DNS flip)
4. Update CLAUDE.md, README, FAQ entry ("EU data residency" now a verifiable claim)

**Estimated effort:** ~2 weeks.

---

### QB — Programmatic SEO content sprint (Phase 8: 55% → ~85%)

The original blueprint's biggest GTM lever was "hundreds of long-tail technical guides". Wave 8b built the infrastructure (SEO `<head>`, JSON-LD, pricing + FAQ sections). Content is what drives organic discovery.

Steps:
1. Decide on content delivery: static generator (Astro/Hugo) or dynamic routes in the existing Vite app
2. Write 10–20 long-tail guides targeting queries like:
   - "EU AI Act Article 9 risk management Python"
   - "Annex IV documentation automation Go"
   - "AI-BOM CycloneDX GitHub Actions"
3. Add README screenshots and architecture diagram
4. Extend JSON-LD structured data to guide/docs pages

**Estimated effort:** ~3–4 weeks.

---

### QC — GitHub Marketplace listing (Phase 8: +~5%)

**What:** Apply for GitHub verified publisher badge, write formal Marketplace listing description with screenshots and categorisation.

**Prerequisite:** QB (screenshots needed for listing).

**Estimated effort:** 1–2 days once QB screenshots exist.

---

### QD — Advanced FinOps (Phase 6: ~85% → ~95%)

**What:** Move beyond "how much does this instance type cost" to actionable rightsizing and savings recommendations.

Scope:
- Spot-instance savings lookup (AWS `describe-spot-price-history`, Azure Spot pricing API)
- Rightsizing: compare detected instance against workload heuristics (dep count, model weight sizes, scan depth)
- MIG / time-slicing guidance for A100/H100 workloads
- Multi-region pricing variance (us-east-1 vs eu-west-1 deltas)
- Surface in a new Annex IV sub-section and a dashboard card

**Estimated effort:** ~1 week.

---

### ~~QE — Container-image filesystem scanning~~ (Phase 2: 92% → ~100%, shipped in Wave 10)

**Status:** ✅ Shipped (2026-05-11). `pkg/imagescan/` walks OCI / Docker
image layers daemonlessly via `github.com/google/go-containerregistry`,
detecting model weights, PEP 566 Python `dist-info` metadata, and
Node.js `node_modules/.../package.json`. CLI flags `--image` and
`--image-tar` (both repeatable) merge findings into `bom.Dependencies`
and record per-image provenance in `bom.ScannedImages`. Annex IV
§ 2(d) attributes layer findings back to their image.

---

## Priority Order

To reach 100% most efficiently:

| Priority | Item | Impact | Effort | Status |
|----------|------|--------|--------|--------|
| ~~1~~ | **W9b** Helm CI smoke job | Phase 4 → 100% | 1 commit | ✅ |
| ~~2~~ | **W9d** Annex IV Section 1 auto-fill | Phase 3 → ~98% | 2 commits | ✅ |
| ~~3~~ | **W9a** v0.7.0 tag | Phase 4 complete, unblocks downstream | Admin | ✅ (v1.1.0) |
| ~~4~~ | **W9c** Reverse-trial UX | Phase 7 → 100% | 3–4 commits | ✅ |
| ~~5~~ | **W9e** Live FinOps pricing | Phase 6 → ~85% | 2 commits | ✅ |
| ~~6~~ | **QE** Container-image scanning (Wave 10) | Phase 2 → ~100% | ~1 week | ✅ |
| 7 | **QA** EU hosting migration | Phase 5 → ~90% | ~2 weeks | pending |
| 8 | **QD** Advanced FinOps | Phase 6 → ~95% | ~1 week | pending |
| 9 | **QB + QC** SEO content + Marketplace | Phase 8 → ~90% | ~3–4 weeks | pending |

**Wave 10 closes the last commit-scale gap in Phase 2.** Overall readiness
sits at ~97%; the remaining ~3% is the three quarter-scale items above —
EU hosting migration, advanced FinOps, and the long-tail SEO content +
Marketplace listing.





  Plan: 100% Overall MVP Readiness

  Current state (post Wave 12, unreleased on development):

  ┌──────────────────────────┬─────────┬────────┬────────────────────────────────────┐
  │          Phase           │ Current │ Target │                Gap                 │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 1 — Stack          │ ~100%   │ 100%   │ ✅ Done (Wave 11)                  │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 2 — Scanning       │ ~100%   │ 100%   │ ✅ Done (Wave 10)                  │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 3 — Compliance     │ ~100%   │ 100%   │ ✅ Done (Wave 12)                  │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 4 — CI/CD          │ ~99%    │ 100%   │ 2 Playwright specs still fixme'd   │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 5 — EU Sovereignty │ ~90%    │ 90%    │ ✅ Done (Wave 13 — Scaleway Paris) │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 6 — FinOps         │ ~95%    │ 95%    │ ✅ Done (Wave 11)                  │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 7 — Pricing        │ ~100%   │ 100%   │ ✅ Done (Wave 9c)                  │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Phase 8 — GTM            │ 55%     │ 90%    │ No content, no Marketplace listing │
  ├──────────────────────────┼─────────┼────────┼────────────────────────────────────┤
  │ Overall                  │ ~92%    │ 100%   │ ~8 pts (EU hosting + GTM)          │
  └──────────────────────────┴─────────┴────────┴────────────────────────────────────┘

  ---
  Wave 11 — Code: FinOps + Dev-Ex hardening (Phase 6 + 1) — ✅ SHIPPED

  Items 1–4 merged on development; item 5 (Playwright E2E) deferred to Wave 12 so
  it can land alongside the policy exit-code work and survive the EU-residency
  URL change in Wave 13.

  1. ✅ Spot instance savings — `pkg/finops/gpu_costs.json` carries per-cloud
     spot multipliers (0.30 AWS/Azure/GCP). `LookupGPUCost` populates
     `SpotHourly/MonthlyUSD*`; `EstimateBOMCost` aggregates `TotalSpot*` and
     derives `SpotSavingsMonthlyUSD*`. Annex IV § 2(c) + dashboard FinOps
     table show the spot projection alongside on-demand. (Phase 6: 85%→92%)
  2. ✅ Rightsizing recommendations — `pkg/finops/rightsize.go` emits
     `FinOpsRightsizing` suggestions when `HasTrainingSignals(bom)` is false
     and the finding's family is in the curated training→inference map
     (p4d/p4de/p5/p3/trn1 → inf2/g5; a3-highgpu/a2-* → g2-standard). Surfaces
     under § 2(c) "Rightsizing recommendations". (Phase 6: 92%→95%)
  3. ✅ Rate-limit response headers — `/api/save-proof` emits
     `X-RateLimit-{Limit,Remaining,Reset}` on free post-trial responses (201
     and 402). Remaining is post-decrement (GitHub convention). Pro/trial
     callers receive no headers (treated as unlimited). (Phase 1: 95%→98%)
  4. ✅ OpenAPI spec — `pkg/api/openapi.json` embedded; `GET /api/openapi.json`
     returns the static OpenAPI 3.0.3 doc covering all routes, both auth
     schemes (`apiKey`/`supabaseJWT`), and the new rate-limit headers.
     (Phase 1: 98%→100%)
  5. ⏭️ Playwright E2E — deferred to Wave 12. (Phase 4 still ~98%)

  Tests added: 5 unit (`pkg/finops/cost_test.go`, `rightsize_test.go`),
  3 integration (`pkg/api/api_integration_test.go` — OpenAPI served,
  rate-limit headers on free tier, absent on Pro).

  ---
  Wave 12 — Code: Compliance polish + Playwright + CHANGELOG (Phase 3 + 4) — ✅ SHIPPED

  All four items merged on `development`.

  1. ✅ `.aicap.yml` expanded fields — `LoadPolicyConfig` now parses
     `contact_email`, `data_inputs`, `training_datasets`; Annex IV § 1
     renders them as evidence or keeps `[REQUIRES MANUAL INPUT]`
     placeholders. Tests: `TestLoadPolicyConfig_Wave12Fields`,
     `TestAnnexIV_Section1_Wave12Fields_Rendered/_PlaceholdersWhenAbsent`.
     (Phase 3: 98%→100%)
  2. ✅ Policy-violation exit codes — `complianceExitCode(bom)` helper:
     exit **2** on any Blocker-severity violation, **1** for non-policy
     compliance failures, **0** clean. CLI prints which Blocker rules
     tripped. 4 unit tests in `main_test.go`. (Phase 3 + Phase 4)
  3. ✅ Playwright E2E scaffolding — `frontend/playwright.config.js`,
     `frontend/e2e/` (helpers + scan fixture + 3 specs). `scan-to-annex`
     runs against the Vite dev server with `/api/scan`,
     `/api/db-config`, `/api/history` route-mocked; asserts the BOM,
     FinOps spot column, Annex IV preview, and markdown download. The
     auth-dependent `signup-checkout-key` and `rotate-key` specs ship as
     `test.fixme` placeholders with TODOs pointing at the Supabase
     auth-mocking layer the next iteration needs. CI job added to
     `.github/workflows/go-test.yml`. Vitest excludes `e2e/**` so the
     two suites stay isolated. (Phase 4: 98%→100%; partial — 1/3 specs
     actively exercised)
  4. ✅ CHANGELOG — Waves 9c, 9e, 10, 11, 12 documented in
     `[Unreleased]`. v1.2.0 tag pending the next merge to `main`.

  Tests added: 4 main_test, 2 scanner_test compliance, 1 Playwright spec.

  ---
  Wave 13 — Infrastructure: EU data residency (Phase 5) — ✅ SHIPPED (2026-06)

  Executed in ~1 day (not 2 weeks) because the database was already on Supabase
  eu-west-1 (Ireland) — only the compute layer had to move.

  1. ✅ Provider decision: Scaleway (French SAS, fr-par/Paris) — most EU-native
     for a DPA story; database already EU so migration risk was compute-only.
  2. ✅ Deploy: Terraform module at `deploy/terraform/scaleway/` provisions a
     private Container Registry + Serverless Container (scale-to-zero free tier).
     Backend live at `*.functions.fnc.fr-par.scw.cloud`; Vercel `VITE_API_URL`
     repointed; Render retired.
  3. ✅ Marketing copy: FAQ "Where is my data stored?" updated + new "Is AIcap
     EU-hosted?" entry. Claim is now accurate and verifiable. (Phase 5: 60%→90%)
  4. ✅ Data residency doc — `documentation/data-residency.md` (per-data-class
     location table + sub-processor list for enterprise DPA due diligence).

  Deferred (launch-time): custom domain `api.aicap.eu` (currently the free
  `.scw.cloud` URL); Supabase paid tier to avoid auto-pause; Stripe webhook
  wiring before first paying customer.

  ---
  Wave 14 — GTM: Content + Marketplace (Phase 8)

  ~4 weeks, non-code

  1. 10–15 technical SEO guides — target queries like "EU AI Act Article 9 risk register automation", "Annex IV documentation generator Python", "OWASP ML Top 10 SBOM
  scanner". Each ~1500 words, hostable as static pages or a /blog route in the frontend
  2. GitHub Marketplace listing — app description, 3 screenshots (scan output, Annex IV preview, dashboard), pricing tiers. Requires GitHub app registration
  3. GitHub Action update — add outputs: to action.yml so CI pipelines can reference annex-iv-url and risk-score (increases Marketplace appeal)

  ---
  Sequencing recommendation

  Now       Wave 11 + 12 (code — ~10 days)
             ↓
  Week 2    Wave 13 infra in parallel with Wave 14 content start
             ↓
  Week 4    Marketplace listing (needs screenshots from deployed EU instance)
             ↓
  Week 5–6  v1.2.0 tag + announcement

  Which wave do you want to start with? Wave 11 (FinOps + dev-ex code) is the fastest path to shippable new value, and Wave 13 (EU hosting) has the most marketing
  impact but requires a non-code decision first.