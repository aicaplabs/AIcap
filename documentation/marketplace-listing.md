# GitHub Marketplace Listing — Draft & Publication Checklist

_Prepared 2026-07-06 (Wave 14). The listing itself is created through the
GitHub UI when publishing a release; this file holds the copy, category
choices, and the pre-flight checklist so publication is a 30-minute task,
not a research project._

---

## How Actions listings work (context)

A GitHub Action is listed by publishing a **release** with "Publish this
Action to the GitHub Marketplace" checked. The listing page is assembled
from:

- `action.yml` → **name**, **description**, **branding** (icon/color)
- The repository **README** → the entire listing body
- Release tag → the version users install
- Categories → chosen in the publish dialog (primary + secondary)

So "writing the listing" mostly means polishing `action.yml` + README and
choosing categories. There is no separate listing document to submit.

## Pre-flight checklist

- [x] `action.yml` at repository root with `name`, `description`,
      `branding` (shield / blue)
- [x] `action.yml` has typed `inputs` and an `outputs` block
      (`compliance-status`, added Wave 14)
- [x] Semver release tag exists (`v1.2.0`) with the linux-amd64 binary
      attached
- [ ] **Action name uniqueness** — "Continuous AI-BOM Scanner" must be
      unique across Marketplace. The README badge already links to
      `github.com/marketplace/actions/continuous-ai-bom-scanner`; verify
      whether a prior listing exists under this account and reuse or
      rename accordingly.
- [ ] Two-factor authentication enabled on the publishing account
      (required by GitHub)
- [ ] Accept the GitHub Marketplace Developer Agreement (first-time
      publish prompt)
- [ ] README screenshots added (see shot list below) — listings with
      images convert dramatically better
- [ ] Optional: verified publisher badge (Settings → Developer settings;
      needs a verified domain — do this after `aicap.eu` is live)

## Category selection

- **Primary: Security** — buyers searching for supply-chain/SBOM tooling
  live here; it is also the category with procurement-driven traffic.
- **Secondary: Continuous integration** — matches the "runs in your
  pipeline" positioning.

## action.yml metadata (current copy)

- **Name:** `Continuous AI-BOM Scanner`
- **Description:** `Automated EU AI Act compliance scanner. Detects AI
  models, dependencies, and FinOps risks.`
- Suggested sharper alternative (95 chars, deadline-aware — apply at next
  release): `EU AI Act compliance in CI: AI-BOM, risk register, and Annex
  IV documentation on every push.`

## Release notes copy (for the publishing release)

> **AIcap — EU AI Act compliance scanning for CI/CD**
>
> Scan your repository and container images for AI dependencies, model
> weights, and GPU infrastructure. Every run emits an AI-BOM, an
> OWASP ML Top 10 / MITRE ATLAS risk register with live CVE enrichment,
> and an Annex IV technical documentation draft — the artefacts the EU AI
> Act requires for high-risk systems from 2 August 2026.
>
> - Zero-config: `uses: istrategeorge/AIcap@v1.2.0` and you have a scan
> - Your source never leaves your runner; only the derived BOM syncs
>   (opt-in, with an API key)
> - Policy-as-code via `.aicap.yml` — exit codes gate merges (0/1/2)
> - `compliance-status` output for downstream steps
> - CycloneDX 1.5 SBOM export for Dependency-Track and friends
> - Pro: hash-chained tamper-evident audit ledger + hosted, shareable
>   Annex IV reports (EU-hosted: Scaleway Paris + Supabase Ireland)

## README shot list (take before publishing)

1. **PR check output** — the scan summary + compliance verdict + badge
   snippet in a GitHub Actions log (light theme, crop to the step).
2. **Annex IV preview** — dashboard preview pane showing the generated
   document with the Export PDF / Share buttons visible.
3. **Audit ledger** — history table with several proof drills and the
   chain-verified state.
4. **Public shared report** — the `/?report=<token>` page; it doubles as
   proof of the shareable-links feature.

Store originals under `documentation/screenshots/` and embed them near
the top of the README (Marketplace renders the README as the listing
body — the first screen matters most).

## Publication steps (when ready)

1. Confirm checklist items above are green.
2. Draft a new release from `main` (next tag, e.g. `v1.3.0`) — attach the
   `aicap-linux-amd64` binary as with previous releases.
3. Tick **"Publish this Action to the GitHub Marketplace"**, pick
   Security + Continuous integration, paste the release-notes copy.
4. Publish; verify the listing renders (README images, badges, inputs
   table) and that the marketplace URL matches the badge already in the
   README — fix the badge if the slug differs.
5. Announce: the listing URL becomes the canonical install link in the
   README quick-start, the GitLab/Bitbucket templates' comments, and the
   landing page.
