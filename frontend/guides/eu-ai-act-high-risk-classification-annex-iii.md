---
title: Is my AI system high-risk under the EU AI Act? An Annex III walkthrough
description: A practical classification walkthrough for engineering and product teams — the eight Annex III categories, the Article 6 filter, common edge cases, and what to do once you know.
date: 2026-07-06
---

# Is my AI system high-risk under the EU AI Act?

Everything expensive in the EU AI Act — Annex IV documentation, Article 9
risk management, conformity assessment, registration — hangs on one
question: **is your system high-risk?** This walkthrough is the engineering
team's version of that analysis. It is not legal advice; it is the homework
that makes the conversation with counsel ten times cheaper.

## The two routes into high-risk

**Route 1 — Annex I products (Art. 6(1)).** Your AI is a safety component
of a product already covered by EU product legislation (machinery, medical
devices, vehicles, toys…). If that is you, you likely have a notified body
relationship already; this guide is secondary.

**Route 2 — Annex III use cases (Art. 6(2)).** The list that catches
software companies. Eight categories, condensed:

| # | Category | Typical software examples |
|---|---|---|
| 1 | Biometrics | Face recognition, emotion inference, biometric categorisation |
| 2 | Critical infrastructure | AI controlling power, water, traffic safety |
| 3 | Education | Exam scoring, admission ranking, proctoring |
| 4 | **Employment** | CV screening, interview scoring, promotion/termination decisions, task allocation |
| 5 | Essential services | Credit scoring, insurance pricing, benefits eligibility, emergency dispatch |
| 6 | Law enforcement | Risk assessments, evidence evaluation, polygraph-adjacent tools |
| 7 | Migration & border | Visa/asylum application assessment, verification tools |
| 8 | Justice & democracy | Judicial decision support, election-influencing systems |

Categories 4 and 5 are where most SaaS teams discover themselves. An HR
tech product that ranks applicants is squarely in category 4. A fintech
that scores creditworthiness is category 5.

## The Article 6(3) escape hatch — use with care

A system in an Annex III category is *not* high-risk if it does not pose a
significant risk of harm — the Act gives four qualifying conditions, such
as performing a narrow procedural task or merely preparing an input for a
human assessment. Two warnings:

- **Profiling kills the exemption.** If the system profiles natural
  persons, it is high-risk regardless of the four conditions.
- **You must document the exemption analysis** and register the system as
  exempt. Claiming the escape hatch silently is itself a compliance gap.

Honest test: if your sales deck says "AI-powered decisioning" and your
exemption memo says "merely preparatory", an authority will notice the
tension.

## Common edge cases

- **"A human reviews every output."** Human review does not remove the
  classification — human oversight is an *obligation* of high-risk systems
  (Art. 14), not an exemption from being one.
- **"We only provide the model; our customer deploys it."** Providers and
  deployers both have obligations. If you place the system on the EU
  market, the Annex IV documentation duty is yours.
- **"It's just an LLM wrapper."** The classification follows the *use
  case*, not the architecture. A GPT-4 wrapper that screens résumés is a
  category-4 high-risk system.
- **"We're not in the EU."** The Act applies if the system's output is
  used in the EU. Selling to EU customers puts you in scope.

## What to do with the answer

**If you are high-risk:** the obligation stack is Annex IV technical
documentation (before market placement), Article 9 continuous risk
management, data governance, logging, human oversight, accuracy/robustness
measures, registration in the EU database, and conformity assessment. Start
with the documentation — it is the artefact every other obligation
references, and its mechanical half (component inventory, risk register,
infrastructure description) can be generated from your repository on every
commit.

**If you are not high-risk:** document *why* (the analysis has to exist
somewhere when a customer or authority asks), watch the transparency
obligations in Article 50 (chatbots must disclose they are AI; synthetic
media must be labelled), and expect enterprise procurement to ask for the
same evidence anyway.

**Either way:** the classification is per-system and per-use-case, and it
drifts. A feature launch can move you into Annex III without anyone
noticing — which is an argument for making the AI inventory continuous
rather than a one-off audit. That inventory is exactly what an AI-BOM
scanner produces from your CI pipeline, free, on every commit.
