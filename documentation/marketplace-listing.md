# GitHub Marketplace Listing — Draft & Publication Checklist

_Prepared 2026-07-06 (Wave 14); status updated 2026-07-17. The listing
is **live** at
[github.com/marketplace/actions/continuous-ai-bom-scanner](https://github.com/marketplace/actions/continuous-ai-bom-scanner)
(published from an early version). The listing body renders from `main`'s
README, and each new release tag appears in the listing's version
dropdown automatically — no re-publish step needed._

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
- [x] Semver release tag exists (`v1.3.3`, 2026-07-17) with the
      linux-amd64 binary attached
- [x] **Action name uniqueness** — resolved: the listing already exists
      under this account at the slug the README badge points to
      (`continuous-ai-bom-scanner`).
- [x] Two-factor authentication enabled on the publishing account
      (implied — required for the existing publication)
- [x] Accept the GitHub Marketplace Developer Agreement (accepted at
      first publication)
- [x] README screenshots added (v1.3.3) — five shots under
      `documentation/screenshots/`, embedded in the README's
      "See it in action" section
- [ ] Optional: verified publisher badge (Settings → Developer settings;
      needs a verified domain — do this after `aicap.eu` is live)

## Category selection

- **Primary: Security** — buyers searching for supply-chain/SBOM tooling
  live here; it is also the category with procurement-driven traffic.
- **Secondary: Continuous integration** — matches the "runs in your
  pipeline" positioning.

## action.yml metadata (current copy)

- **Name:** `Continuous AI-BOM Scanner`
- **Description:** `EU AI Act compliance in CI: AI-BOM, risk register,
  and Annex IV documentation on every push.` (sharper deadline-aware
  copy applied 2026-07-09; ships with v1.3.3)

## Release notes copy (for the publishing release)

> **AIcap — EU AI Act compliance scanning for CI/CD**
>
> Scan your repository and container images for AI dependencies, model
> weights, and GPU infrastructure. Every run emits an AI-BOM, an
> OWASP ML Top 10 / MITRE ATLAS risk register with live CVE enrichment,
> and an Annex IV technical documentation draft — the artefacts the EU AI
> Act requires for high-risk systems from 2 August 2026.
>
> - Zero-config: `uses: istrategeorge/AIcap@v1.3.3` and you have a scan
> - Your source never leaves your runner; only the derived BOM syncs
>   (opt-in, with an API key)
> - Policy-as-code via `.aicap.yml` — exit codes gate merges (0/1/2)
> - `compliance-status` output for downstream steps
> - CycloneDX 1.5 SBOM export for Dependency-Track and friends
> - Pro: hash-chained tamper-evident audit ledger + hosted, shareable
>   Annex IV reports (EU-hosted: Scaleway Paris + Supabase Ireland)

## README shot list — ✅ all taken (v1.3.3)

1. [x] **PR check output** — `ci-passing.png` (verdict + badge snippet,
   light theme, cropped to the step). Bonus fifth shot:
   `ci-blocking.png` showing the enforcement path (red job, exit 1).
2. [x] **Annex IV preview** — `annex-iv-preview.png` (generated from
   the clean `istrategeorge/aicap-demo` scan; Export PDF / Share /
   Download visible).
3. [x] **Audit ledger** — `audit-ledger.png`.
4. [x] **Public shared report** — `public-shared-report.png`.

Originals live under `documentation/screenshots/`, embedded in the
README's "See it in action" section directly under the tagline —
Marketplace renders the README as the listing body, so they're the
first screen a visitor sees.

## Publication — ✅ done (early version); remaining polish

The listing is live and updates automatically: README/screenshots
render from `main`, new tags (v1.3.3) appear in the version dropdown,
and `action.yml`'s name/description come from the latest release.

Remaining items, all manual UI checks or blocked on other work:

1. [ ] **Eyeball the live listing** — confirm the five screenshots
   render, the description shows the new deadline-aware copy, and
   v1.3.3 is selectable in the version dropdown.
2. [ ] **Verify categories** — the early publication may predate the
   Security + Continuous integration choice above. Editable at
   repo → Releases → edit the marketplace listing. Security should be
   primary (procurement-driven traffic).
3. [ ] **Verified publisher badge** — blocked on the `aicap.eu` domain
   (Settings → Developer settings → verified domain).
4. [ ] **Announce** — once verified, make the Marketplace URL the
   canonical install link on the landing page and in launch posts
   (README quick-start + GitLab/Bitbucket templates already pin
   v1.3.3).
