# Contributing to AIcap

Thanks for considering a contribution. AIcap is an EU AI Act compliance
scanner; the project's value is directly proportional to how many real
codebases it understands. New manifest parsers, source-language
detectors, and risk-catalog entries are especially welcome.

## TL;DR

- Branch off `development`, not `main`.
- Run `go test ./...` and `cd frontend && npm test && npm run lint`
  before pushing.
- One logical change per PR; keep diffs small.
- We do not require a CLA. Contributions are MIT-licensed.

## Repo layout

See [CLAUDE.md](CLAUDE.md) for the canonical, up-to-date map. In short:

```
main.go                # HTTP server + --migrate subcommand
pkg/api                # all HTTP handlers
pkg/auth               # JWT + API-key middleware, HashAPIKey
pkg/scanner            # AI-BOM static analysis (manifests, source, IaC)
pkg/compliance         # risk register, OSV enrichment, Annex IV markdown
pkg/finops             # GPU cost catalog + estimation
pkg/migrate            # embedded SQL migration runner
pkg/types              # shared types
frontend/src           # React/Vite SPA (auth + dashboard + landing)
deploy/helm/aicap      # self-hosted Helm chart (Wave 8a)
templates/             # GitHub Action / GitLab CI / Bitbucket templates
```

## Branching model

- `main` is stable / production. Tagged releases (`v0.X.Y`) come from
  here.
- `development` is the active integration branch. **Open every PR
  against `development`.**
- We squash-merge most PRs to keep `development` history readable; if
  your branch has a meaningful commit story, say so in the PR
  description and we may merge-commit instead.

## Local development

### Backend (Go)

Prereqs: Go 1.23+, optionally Docker for integration tests.

```bash
# Unit tests — no DB required
go test ./...

# Integration tests — requires Postgres via Docker Compose
docker compose up -d db
TEST_DATABASE_URL='postgres://aicap:aicap@localhost:5432/aicap?sslmode=disable' \
  go test -tags=integration ./...
docker compose down

# Run the server locally without a DB
go run main.go

# Run the server with a DB + auto-migrations
SUPABASE_DB_URL='postgres://...' RUN_MIGRATIONS=true go run main.go
```

### Frontend (React + Vite)

```bash
cd frontend
npm install
npm test           # Vitest + React Testing Library
npm run lint       # ESLint
npm run build      # production bundle (must succeed in CI)
npm run dev        # dev server with HMR
```

### Helm chart

`deploy/helm/aicap/` ships a production chart. Validate with:

```bash
helm lint deploy/helm/aicap/
helm template my-test deploy/helm/aicap/ \
  --set secrets.supabaseDbUrl='postgres://test' \
  --set secrets.supabaseJwtSecret='test' \
  --set secrets.stripeSecretKey='sk_test_x' \
  --set secrets.stripeWebhookSecret='whsec_test'
```

## How to land a change

1. **Open an issue first** for anything bigger than a typo or a
   one-file fix. We'd rather discuss approach than ask you to redo a
   landed branch.
2. **Branch from `development`** — `git checkout -b
   wave-9a/your-thing development`.
3. **Write tests.** Every parser PR needs at least one positive case +
   one false-positive guard. Every handler PR needs an integration test
   under `pkg/api/api_integration_test.go`. Every frontend component
   touching state needs a Vitest test.
4. **Run the full suite locally** before pushing:

   ```bash
   go test ./...
   go test -tags=integration ./...    # if you touched DB code
   cd frontend && npm test && npm run lint && npm run build
   ```
5. **Open the PR against `development`.** Title in conventional-commit
   style (`feat(scanner): add Pipfile.lock parser`,
   `fix(api): scrub raw error from save-proof response`, etc).
6. **CI must be green** before review. The pipeline runs unit tests,
   integration tests against a Postgres 16 service container, frontend
   tests + lint + build, and a `go build` of the binary.

## What kinds of contributions help most

Ranked roughly by impact:

1. **Manifest parsers** for ecosystems we don't cover yet (Cargo,
   Gemfile.lock, Gradle, Maven, Composer). See
   `pkg/scanner/manifests.go` for the existing pattern. Lockfile is
   the authoritative version source — prefer those over top-level
   manifests.
2. **Risk-catalog entries** in `pkg/compliance/vulns.json`. New AI
   library? Map it to OWASP ML Top 10 + MITRE ATLAS technique IDs +
   relevant EU AI Act articles + a recommended mitigation.
3. **GPU cost catalog updates** in `pkg/finops/gpu_costs.json` —
   especially as cloud providers add or rename instance families.
4. **Governance signal detectors** in `pkg/scanner/governance.go` for
   HITL, training-data provenance, bias monitoring, and
   prompt-injection defences. Conservative regex (false negatives
   over false positives) — auditors should never see a phantom check
   pass.
5. **CI integration templates** under `templates/` for systems we
   don't have yet (CircleCI, Jenkins, Azure DevOps, Drone).
6. **Documentation fixes.** [README.md](README.md) and
   [CHANGELOG.md](CHANGELOG.md) are user-facing; please keep them
   accurate.

## What we're unlikely to merge

- Renames / large reformat PRs — too much review surface for too
  little signal. If something's truly inconsistent, file an issue.
- New abstractions that aren't used yet ("might need this later").
- New external services without a fallback path. The OSV.dev
  enrichment is the model here: if OSV is down, the catalog-derived
  finding still lands.
- Anything that changes the proof-drill hash formula without a
  migration story for the existing chain.

## Reporting security issues

Do **not** open a public issue for a security finding. Email
`security@aicap.dev` with reproduction steps. We reply within 72h.

## Code of conduct

Be kind. Disagreements are fine — gatekeeping, condescension, and
personal attacks are not. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/) v2.1.

## License

By contributing, you agree your changes are licensed under the MIT
License (same as the project).
