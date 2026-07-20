// Legal & trust page content, rendered through lib/annexIVPdf.js's
// markdownToHtml (same subset: headings, bullets, tables, bold/code).
// Kept as markdown constants rather than JSX so the copy is easy to
// review, diff, and eventually serve as static pages.
//
// Grounded in documentation/data-residency.md — when hosting or
// sub-processors change, update BOTH files in the same commit.

const LAST_UPDATED = '6 July 2026';

const TERMS = `# Terms of Service

_Last updated: ${LAST_UPDATED}_

## 1. Who we are

AIcap ("we", "us") provides a continuous AI Bill-of-Materials and EU AI Act
compliance scanner: an open-source CLI plus a hosted dashboard and audit
ledger (the "Service") at aicap.dev. By creating an account or using
the Service you accept these terms.

## 2. The two halves of AIcap

- **The CLI scanner** is open source under the MIT licence. Its use is
  governed by that licence, not these terms. It runs inside your own
  infrastructure and sends us nothing unless you configure an API key.
- **The hosted Service** (dashboard, proof-drill ledger, hosted Annex IV
  reports, API) is governed by these terms.

## 3. Accounts and API keys

- You must provide accurate account information and keep your credentials
  confidential. You are responsible for activity under your account.
- API keys are shown **once** at generation and stored by us only as a
  SHA-256 hash. Treat them as secrets; rotate immediately if exposed.
- One account per legal entity is expected for the Pro tier ("per
  workspace").

## 4. Subscriptions and billing

- Paid plans are billed through Stripe on a monthly subscription. Prices
  are shown on the pricing page at the time of purchase.
- New accounts receive a 14-day full-feature trial. When it lapses without
  a subscription, the account downgrades to the free tier — your data is
  retained, not deleted.
- You can cancel any time via the self-serve billing portal; access
  continues until the end of the paid period. Fees already paid are
  non-refundable except where required by law.

## 5. Acceptable use

You may not: (a) scan repositories or container images you have no right
to analyse; (b) attempt to access other tenants' data; (c) resell the
Service without an agreement; (d) use the Service to build a directly
competing hosted product by systematic extraction; (e) disrupt or probe
the Service except under a responsible-disclosure engagement (see the
Security page).

## 6. Your data and intellectual property

- **You own your data.** AI-BOMs, risk registers, and Annex IV reports
  generated from your repositories are yours. We take only the limited
  licence needed to store, process, and display them back to you and to
  anyone you explicitly share a report link with.
- The hash-chain audit ledger is tamper-evident by design; we do not edit
  or reorder your ledger entries.
- We may use aggregated, non-identifying usage statistics (e.g. count of
  scans) to operate and improve the Service.

## 7. Compliance disclaimer — read this one

AIcap **automates documentation drafting and risk surfacing. It is not
legal advice, and using it does not by itself make you compliant** with
the EU AI Act or any other regulation. Generated Annex IV documents are
drafts that require your review and completion (fields marked
\`[REQUIRES MANUAL INPUT]\` exist precisely because a scanner cannot know
your intended purpose or oversight procedures). Engage qualified counsel
for your conformity assessment.

## 8. Availability and support

The Service is provided on a best-effort basis without an uptime SLA on
the Free and Pro tiers. Enterprise agreements may include an SLA and
signed DPA — contact enterprise@aicap.dev.

## 9. Liability

To the maximum extent permitted by law, our aggregate liability arising
out of the Service is limited to the fees you paid us in the 12 months
before the claim. We are not liable for indirect or consequential damages,
including regulatory fines — see Section 7.

## 10. Termination

You may delete your account at any time. We may suspend or terminate
accounts that breach these terms, with notice where practicable. On
termination we delete your data within 30 days, except minimal billing
records we must retain by law.

## 11. Changes

We may update these terms; material changes will be announced on the
dashboard or by email at least 14 days in advance. Continued use after
the effective date is acceptance.

## 12. Governing law

These terms are governed by the laws of the EU member state in which the
AIcap operator is established, without prejudice to mandatory protections
you enjoy under the law of your country of residence. Disputes go to the
courts of that member state unless mandatory law provides otherwise.

Questions: hello@aicap.dev
`;

const PRIVACY = `# Privacy Policy

_Last updated: ${LAST_UPDATED}_

AIcap is designed to hold as little personal data as possible: the scanner
runs in **your** CI infrastructure, and what reaches us is dependency
metadata, not source code.

## 1. What we process, and why

| Data | Source | Purpose | Legal basis (GDPR Art. 6) |
|---|---|---|---|
| Account email + password hash | You, at signup (via Supabase Auth) | Authentication, service messages | Contract (1(b)) |
| Billing details, card data | Stripe checkout | Subscription billing | Contract (1(b)) — card data is held by Stripe, never by us |
| Scan payloads (AI-BOM, risk register, Annex IV markdown, commit SHAs) | Your CI pipeline, when you set an API key | The audit-ledger product itself | Contract (1(b)) |
| API key hashes (SHA-256) | Generated by us | Authenticating your CI | Contract (1(b)) |
| Request logs (IP, request ID, timestamps) | Automatic | Security, abuse prevention, debugging | Legitimate interest (1(f)) |

**A note on scan payloads:** AI-BOMs contain dependency names, file paths,
and commit SHAs from your repositories. Git commit metadata can embed
author names/emails — those stay in your repo; AIcap stores only the
commit SHA. Do not put personal data in project names.

## 2. Where your data lives

All application data is stored and processed **within the European
Union**: database in Ireland (Supabase, \`eu-west-1\`), backend compute in
Paris (Scaleway, \`fr-par\`). The full statement, including what never
leaves your environment, is in our Data Residency documentation (linked
from the DPA page).

## 3. Sub-processors

| Sub-processor | Purpose | Region |
|---|---|---|
| Supabase / AWS | Managed PostgreSQL + authentication | Ireland (eu-west-1) |
| Scaleway SAS | Backend compute + container registry | France (fr-par) |
| Stripe Payments Europe Ltd | Subscription billing | Ireland (+ US for some billing operations under Stripe's SCCs) |
| Vercel Inc. | Static frontend CDN — serves JavaScript only, holds no customer data at rest | Global edge |

We will announce sub-processor changes on this page before they take
effect.

## 4. Retention

- Account and ledger data: for the life of your account, then deleted
  within 30 days of account deletion.
- The immutable ledger is append-only while your account exists; deleting
  your account deletes your entire chain.
- Request logs: 30 days.
- Billing records: as required by tax law (typically 10 years), held by
  Stripe and in our accounting records.

## 5. Your rights

Under the GDPR you can request access, rectification, erasure,
restriction, portability, or object to processing based on legitimate
interest. Write to hello@aicap.dev — we respond within 30 days. You can
also lodge a complaint with your local supervisory authority.

## 6. Cookies and local storage

The dashboard uses browser local storage for your Supabase session token
(strictly functional — it is how you stay signed in). We set no
advertising or cross-site tracking cookies.

## 7. Contact

Data controller for account data: the AIcap operator. For scan payloads
synced from your CI, **you are the controller and AIcap is your
processor** — see the Data Processing Agreement page.

hello@aicap.dev
`;

const DPA = `# Data Processing Agreement (Summary)

_Last updated: ${LAST_UPDATED}_

When your CI pipeline syncs scan results to the hosted Service, **you are
the data controller and AIcap is your processor** under GDPR Art. 28.
This page summarises the processing terms; Enterprise customers can
request a signed copy at enterprise@aicap.dev.

## Subject matter and duration

Processing of scan payloads (AI-BOMs, risk registers, Annex IV markdown,
commit SHAs) for the purpose of providing the compliance audit-ledger
service, for as long as you maintain an account.

## Nature of the data

Dependency and infrastructure metadata from your repositories. The
scanner is designed so that **source code never leaves your CI runner** —
only the derived BOM is transmitted. Personal data content is expected to
be minimal (commit SHAs; whatever you place in project names).

## Our commitments as processor

- Process scan data only to provide the Service — never for advertising,
  model training, or resale.
- All application data stored and processed in the EU (Ireland + France).
  See the Data Residency statement in the repository:
  \`documentation/data-residency.md\`.
- Confidentiality: access to production data is restricted to the
  operator; API keys are stored only as SHA-256 hashes.
- Security measures as described on the Security page (TLS in transit,
  encrypted secrets at rest, tamper-evident ledger, tenant isolation by
  user id on every query).
- Sub-processors: only those listed in the Privacy Policy; changes
  announced in advance.
- Assistance: we support data-subject requests and provide the
  information reasonably needed for your Art. 28(3)(h) audits — starting
  with our public documentation and, for Enterprise, security
  questionnaires.
- Breach notification: without undue delay after becoming aware, to your
  account email.
- Deletion: full deletion of your data within 30 days of account
  termination, minus what tax law requires us to keep in billing records.

## International transfers

None for application data — it stays in the EU. Stripe may process
limited billing data in the US under its own Standard Contractual
Clauses; that flow is independent of your scan data.

## Self-hosted option

If a processor relationship is not acceptable at all, the Enterprise
Helm chart runs AIcap entirely inside your own infrastructure with your
own Postgres — in that model no data reaches AIcap-operated systems.

Request a signed DPA: enterprise@aicap.dev
`;

const SECURITY = `# Security at AIcap

_Last updated: ${LAST_UPDATED}_

A compliance product has to be honest about its own posture. This page
describes the concrete measures in the hosted Service — most of them are
verifiable in the open-source repository.

## Architecture

- **Your source code never leaves your CI.** The scanner runs in your
  pipeline and transmits only the derived AI-BOM, and only when you set
  an API key.
- **EU-only application data**: database in Ireland (Supabase,
  \`eu-west-1\`), compute in Paris (Scaleway, \`fr-par\`). Documented per
  data class in the Data Residency statement.
- **TLS everywhere**: browser → API and API → database connections are
  encrypted in transit.

## Credentials

- API keys are **hashed at rest** (SHA-256); the plaintext is shown once
  at generation and is unrecoverable afterwards. One key per user,
  enforced by a database constraint; self-serve rotation revokes the old
  hash atomically.
- Dashboard sessions use Supabase-issued JWTs verified server-side on
  every request; API keys are rejected on browser routes and vice versa.
- Production secrets are stored encrypted in Scaleway's secret manager,
  never in the repository.

## Tenant isolation

- Every ledger query is scoped by the authenticated \`user_id\` — there
  are no cross-tenant read paths, and this is covered by integration
  tests.
- Database row-level security remains enabled as defence-in-depth behind
  the API layer.

## Tamper-evident ledger

Each proof drill is chained to its predecessor
(\`crypto_hash = sha256(commit_sha || bom || prev_hash)\`). Editing,
deleting, or reordering a historical row breaks verification at every
later link — checkable any time via the dashboard's chain verification.

## Shared report links

Public report links use 256-bit random capability tokens generated
server-side. Nothing is public by default; links are revocable instantly
and revoked tokens are indistinguishable from ones that never existed.

## Operational hygiene

- Structured request logging with request IDs; logs exclude secrets and
  raw payloads, and are retained for 30 days.
- CI runs the full unit + integration test suite on every change;
  dependencies are minimal by policy (the scanner adds zero runtime
  dependencies for new parsers).
- Database schema changes ship as idempotent, reviewed migrations.

## Responsible disclosure

Found a vulnerability? Email hello@aicap.dev with details and we will
respond within 72 hours. We ask for reasonable time to remediate before
public disclosure, and we do not pursue good-faith researchers.
`;

export const LEGAL_PAGES = {
  terms: { title: 'Terms of Service', markdown: TERMS },
  privacy: { title: 'Privacy Policy', markdown: PRIVACY },
  dpa: { title: 'Data Processing Agreement', markdown: DPA },
  security: { title: 'Security', markdown: SECURITY },
};
