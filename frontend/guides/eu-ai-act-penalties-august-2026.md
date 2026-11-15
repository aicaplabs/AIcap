---
title: EU AI Act penalties — what applies now, and what moved to December 2027
description: The real enforcement picture after the Digital Omnibus — which obligations are already enforceable, which moved to 2027 and 2028, the penalty tiers up to €35M or 7% of turnover, and the engineering work that reduces exposure.
date: 2026-11-15
---

# EU AI Act penalties: what applies now, and what moved to December 2027

This guide originally described 2 August 2026 as the date the bulk of the
EU AI Act became applicable, including the high-risk regime. That is no
longer accurate. **Regulation (EU) 2026/1744** — the "Digital Omnibus on
AI", published in the Official Journal on 24 July 2026 — moved the
high-risk dates. The guide has been rewritten against the amended text.

## The dates, as amended

| Date | What applies |
|---|---|
| 2 February 2025 | Article 5 prohibited practices |
| 2 August 2025 | General-purpose model obligations (Chapter V) and the penalty regime (Chapter XII) |
| **2 August 2026** | **Article 50 transparency duties**, and the remainder of the Act not listed elsewhere |
| 2 December 2026 | Article 50(2) machine-readable marking for generative systems already on the market before 2 August 2026; additional Article 5 prohibitions added by the Omnibus |
| **2 December 2027** | **High-risk requirements (Chapter III, Sections 1–3) for Annex III systems** — previously 2 August 2026 |
| 2 August 2028 | The same requirements for Annex I systems (AI in regulated products) — previously 2 August 2027 |
| 2 August 2030 | High-risk systems intended for use by public authorities |

Two things follow. The high-risk documentation duty — Article 11 and
Annex IV — is not yet enforceable for most systems. And the Act is not
dormant either: the prohibitions, the general-purpose model duties, and the
Article 50 transparency duties are all applicable today.

## The three penalty tiers (Article 99)

| Violation | Maximum fine |
|---|---|
| Prohibited practices (Art. 5 — social scoring, manipulative systems, most real-time biometric ID) | **€35M or 7%** of global annual turnover |
| Non-compliance with operator obligations — the high-risk requirements (risk management, data governance, **technical documentation**, human oversight, accuracy) and the **Article 50 transparency duties** | **€15M or 3%** of global annual turnover |
| Supplying incorrect or misleading information to authorities | **€7.5M or 1%** of global annual turnover |

Whichever is *higher* applies — except for SMEs and startups, where
whichever is *lower* applies. The Omnibus extended that lower-of rule to
small mid-cap companies as well. These are statutory ceilings, not tariffs:
authorities must set fines proportionately. A percentage-of-turnover
ceiling is still not something to plan around hitting.

## What is enforceable today

- **Article 5.** If a component in your system infers emotion in a
  workplace or classroom, or performs biometric categorisation or
  identification, the question of whether a prohibition applies is a live
  one now, in the highest penalty tier.
- **Article 50.** Telling people they are interacting with an AI system,
  marking synthetic output machine-readably, informing people subject to
  emotion recognition or biometric categorisation, and disclosing deep
  fakes. If you put a generative system on the market on or after
  2 August 2026, the marking duty has applied to it from day one. If it was
  already on the market before that date, you have until 2 December 2026.
- **General-purpose model duties**, if you are a model provider rather than
  a deployer.

## Who actually enforces this

- **National market surveillance authorities** (one or more per member
  state) handle AI systems. They can demand documentation, order corrective
  action, and ultimately pull a system from the market.
- **The European AI Office** oversees general-purpose model providers
  directly.
- **Anyone can complain.** Article 85 gives any person the right to lodge an
  infringement complaint with a market surveillance authority — a
  disgruntled user, a competitor, an NGO.

The realistic first-contact scenario is not a dawn raid. It is a **request
for information**: the authority asks what the system does, what it is
built from, and what you did about the duty in question, typically with a
deadline in weeks. What happens next depends almost entirely on whether an
accurate, current answer already exists.

## The two failure modes that generate fines

**1. You have nothing to show.** For a high-risk system, Article 11 requires
technical documentation to exist *before* market placement and to be kept
up to date. From 2 December 2027, "we were going to write it" is a
violation on its face.

**2. What you show contradicts your system.** The component list says
scikit-learn; the container ships a fine-tuned Llama. Now you are in the
third tier too — incorrect information supplied to an authority — and you
have converted an administrative gap into a credibility problem.

The second failure mode is the insidious one, because it is the *default
outcome of hand-maintained documentation*. Every dependency bump, every new
model integration, every infra change silently invalidates the document
written last quarter.

## What reduces exposure, in order of effort

1. **Classify honestly, now.** Map your systems against Article 5,
   Article 50, and Annex III. The analysis costs a workshop; discovering
   you were in scope during an information request costs much more.
2. **Generate the mechanical evidence continuously.** Component inventory
   (AI-BOM), per-component risk register, hardware description — these can
   be produced from your repository on every commit. Article 9 requires
   high-risk risk management to be "continuous and iterative", so a
   process that has been running since before the application date is
   itself evidence.
3. **Make the record tamper-evident.** When an authority asks "what did you
   know and when", a hash-chained ledger of every scan — where editing or
   deleting a historical entry visibly breaks the chain — is a categorically
   better answer than a folder of Word documents with a `_final_v3` naming
   convention.
4. **Write the judgement sections once, properly.** Intended purpose, human
   oversight design, accuracy claims. No tool writes these; every tool
   should embed them.

## What the delay does and does not buy you

The stated reason for the delay is that harmonised standards and national
authorities were not ready. It is tempting to read sixteen extra months as
sixteen months in which nothing needs doing. Three reasons not to:

- A high-risk system already on the market is brought into scope by a
  significant design change after the application date. The inventory you
  will need in order to know whether a change is significant is the one
  you would be building now.
- The duties that did *not* move — Article 5 and Article 50 — attach to
  the same components. An inventory that tells you which of your services
  generate synthetic content or call a general-purpose model is the
  starting point for both.
- Your **enterprise customers are not waiting**. AI Act evidence appears in
  procurement questionnaires regardless of the regulator's calendar, which
  is a faster and more certain enforcement mechanism than any authority.

## Start with the part that costs one CI job

The mechanical half of the evidence (AI-BOM, risk register, Article 5 and
Article 50 indicators, Annex IV draft, hash-chained scan ledger) is a
single GitHub Actions job with AIcap — free CLI, EU-hosted ledger, and your
source code never leaves your pipeline. The judgement half is yours either
way; stop spending engineering time on the half that automates.

This guide is engineering guidance, not legal advice. Check the dates above
against the Official Journal text of Regulation (EU) 2024/1689 as amended
before relying on them.
