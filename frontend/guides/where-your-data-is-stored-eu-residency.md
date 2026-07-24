---
title: Where your data is stored — AIcap EU data residency
description: A per-data-class statement of where AIcap stores and processes customer data, the sub-processor list, and what never leaves your own infrastructure. Written for GDPR Art. 28 assessments, DPAs, and security questionnaires.
date: 2026-07-24
---

# Where your data is stored

**All AIcap SaaS data is stored and processed within the European Union.**
Both the database and the backend compute run on EU-incorporated providers
in EU data centres. No customer data is persisted outside the EU.

This page exists so you can answer a security questionnaire without
emailing us first. If you need it as a signed document, or need a DPA
countersigned, contact us and we will send one.

## Where each data class lives

| Data class | Location | Provider | Legal entity |
|---|---|---|---|
| Database — AI-BOMs, proof-drill audit ledger, API key hashes, subscription state | Ireland (`eu-west-1`) | Supabase (on AWS) | Supabase Inc. / AWS EMEA SARL (Ireland) |
| Backend compute — HTTP API, request processing, migrations | Paris, France (`fr-par`) | Scaleway Serverless Containers | Scaleway SAS (France) |
| Container image registry | Paris, France (`fr-par`) | Scaleway Container Registry | Scaleway SAS (France) |
| Frontend static assets — no customer data | Global edge CDN | Vercel | Vercel Inc. (US) — static JS/HTML only, nothing persisted |
| Payment data — card details, billing | EU + US | Stripe | Stripe Payments Europe Ltd (Ireland) |

### Notes

- **Frontend (Vercel).** The dashboard is a static single-page app served
  from a global CDN. It holds no customer data at rest — everything is
  fetched at runtime from the EU backend over HTTPS. CDN distribution of
  static JavaScript is not storage or processing of personal data.
- **Payments (Stripe).** Card and billing data are handled by Stripe,
  contracted through Stripe Payments Europe Ltd (Ireland). AIcap never
  sees or stores raw card details. Stripe may process some data in the US
  under its own SCCs; that is limited to billing and is independent of
  AIcap's application data.
- **API keys** are stored only as SHA-256 hashes. The plaintext key is
  returned once, at creation, and never persisted — if you lose it, you
  rotate it, because we genuinely cannot recover it.

## What never leaves your environment

This is usually the more important half of the answer.

- **The CLI scanner runs entirely inside your own runner.** Your source
  code is never transmitted. The scanner sends data to the AIcap API only
  when `AICAP_API_KEY` is set, and only the derived AI-BOM — not the code
  it was derived from.
- **CVE enrichment** queries `api.osv.dev` with package names and
  versions. Disable it with `AICAP_OSV_DISABLED=true` and the scan still
  produces a full risk register from the local catalog.
- **Self-hosted deployments** (the Helm chart, for Enterprise) run
  entirely in your own infrastructure against your own Postgres. In that
  model no data reaches AIcap-operated systems at all.

## Sub-processors

| Sub-processor | Purpose | Region |
|---|---|---|
| Supabase / AWS | Managed PostgreSQL database | Ireland (`eu-west-1`) |
| Scaleway SAS | Backend compute + container registry | France (`fr-par`) |
| Stripe Payments Europe Ltd | Subscription billing | Ireland (+ US for some billing operations) |
| Vercel Inc. | Static frontend CDN (no customer data at rest) | Global edge |

## Change history

- **June 2026** — Backend compute migrated from Render (US) to Scaleway
  (Paris). The database was already on Supabase Ireland, so this moved the
  last non-EU component of the data path into the EU and made "EU-hosted"
  a fully accurate claim rather than a partial one.
