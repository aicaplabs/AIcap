# AIcap — Data Residency Statement

_Last updated: 2026-06-17_

This document describes where AIcap stores and processes customer data. It is
intended for prospective customers conducting data-protection due diligence
(GDPR Art. 28 processor assessments, DPAs, security questionnaires).

## Summary

**All AIcap SaaS data is stored and processed within the European Union.** Both
the database and the backend compute run on EU-incorporated providers in EU
data centres. No customer data is persisted outside the EU.

## Where each data class lives

| Data class | Location | Provider | Legal entity |
|---|---|---|---|
| Database (AI-BOMs, proof-drill audit ledger, API key hashes, subscription state) | Ireland (`eu-west-1`) | Supabase (on AWS) | Supabase Inc. / AWS EMEA SARL (Ireland) |
| Backend compute (Go HTTP API, request processing, migrations) | Paris, France (`fr-par`) | Scaleway Serverless Containers | Scaleway SAS (France) |
| Container image registry | Paris, France (`fr-par`) | Scaleway Container Registry | Scaleway SAS (France) |
| Frontend static assets (no customer data) | Global edge CDN | Vercel | Vercel Inc. (US) — static JS/HTML only, no persisted data |
| Payment data (card details, billing) | EU + US | Stripe | Stripe Payments Europe Ltd (Ireland) |

### Notes

- **Frontend (Vercel):** the dashboard is a static single-page app served from a
  global CDN. It contains no customer data at rest — all data is fetched at
  runtime from the EU backend over HTTPS. The CDN distribution of static
  JavaScript does not constitute storage or processing of personal data.
- **Payments (Stripe):** card and billing data are handled by Stripe, contracted
  through Stripe Payments Europe Ltd (Ireland). AIcap never sees or stores raw
  card details. Stripe may process certain data in the US under its own SCCs;
  this is limited to billing and is independent of AIcap's application data.
- **API keys** are stored only as SHA-256 hashes (`token_hash`); plaintext keys
  are never persisted.

## What does NOT leave the customer's environment

- The **CLI scanner** runs entirely locally. It transmits data to the AIcap API
  only when `AICAP_API_KEY` is set, and to `api.osv.dev` (CVE/GHSA enrichment)
  only when `AICAP_OSV_DISABLED` is unset. Both are opt-in and can be disabled.
- **Self-hosted / Enterprise** deployments (via the Helm chart) run entirely in
  the customer's own infrastructure with a customer-controlled Postgres. In that
  model, no data reaches AIcap-operated systems at all.

## Sub-processors

| Sub-processor | Purpose | Region |
|---|---|---|
| Supabase / AWS | Managed PostgreSQL database | Ireland (`eu-west-1`) |
| Scaleway SAS | Backend compute + container registry | France (`fr-par`) |
| Stripe Payments Europe Ltd | Subscription billing | Ireland (+ US for some billing ops) |
| Vercel Inc. | Static frontend CDN (no customer data at rest) | Global edge |

## Change history

- **2026-06 (Wave 13):** Backend compute migrated from Render (US) to Scaleway
  (Paris, FR). The database was already on Supabase Ireland. This migration moved
  the last non-EU component of the data path into the EU, making "EU-hosted" a
  fully accurate claim.

---

_For questions about this statement or to request a signed DPA, contact the
AIcap team._
