---
title: EU AI Act penalties — what actually happens after 2 August 2026
description: The real enforcement picture — penalty tiers up to €35M or 7% of turnover, who enforces them, what triggers them, and the engineering work that reduces exposure.
date: 2026-07-06
---

# EU AI Act penalties: what actually happens after 2 August 2026

On **2 August 2026**, the bulk of the EU AI Act's obligations become
applicable — including the high-risk system requirements and their
enforcement regime. Here is what the penalty structure actually says, who
enforces it, and what engineering teams can do that measurably reduces
exposure.

## The three penalty tiers (Article 99)

| Violation | Maximum fine |
|---|---|
| Prohibited practices (Art. 5 — social scoring, manipulative systems, most real-time biometric ID) | **€35M or 7%** of global annual turnover |
| Non-compliance with high-risk obligations (Arts. 8–15: risk management, data governance, **technical documentation**, human oversight, accuracy) | **€15M or 3%** of global annual turnover |
| Supplying incorrect or misleading information to authorities | **€7.5M or 1%** of global annual turnover |

Whichever is *higher* applies — except for SMEs and startups, where
whichever is *lower* applies. That SME carve-out matters, but a
percentage-of-turnover fine is existential at any size.

## Who actually enforces this

- **National market surveillance authorities** (one or more per member
  state) handle high-risk systems. They can demand your technical
  documentation, order corrective action, and ultimately pull a system from
  the market.
- **The European AI Office** oversees general-purpose model providers
  directly.
- **Anyone can complain.** Article 85 gives any person the right to lodge an
  infringement complaint with a market surveillance authority — a
  disgruntled user, a competitor, an NGO.

The realistic first-contact scenario is not a dawn raid. It is a **document
request**: the authority asks for your Annex IV technical documentation and
your Article 9 risk management evidence, typically with a deadline in weeks.
What happens next depends almost entirely on whether that documentation
exists and is current.

## The two failure modes that generate fines

**1. You have no documentation.** Article 11 requires technical
documentation to exist *before* market placement and to be kept up to date.
"We were going to write it" is a tier-2 violation on its face.

**2. Your documentation contradicts your system.** The component list says
scikit-learn; the container ships a fine-tuned Llama. Now you are in tier-3
territory too — incorrect information supplied to an authority — and you
have converted an administrative gap into a credibility problem.

The second failure mode is the insidious one, because it is the *default
outcome of hand-maintained documentation*. Every dependency bump, every new
model integration, every infra change silently invalidates the document
written last quarter.

## What reduces exposure, in order of effort

1. **Classify honestly, now.** Map your systems against Annex III. The
   analysis costs a workshop; discovering you were high-risk during a
   document request costs much more.
2. **Generate the mechanical evidence continuously.** Component inventory
   (AI-BOM), per-component risk register, hardware description — these can
   be produced from your repository on every commit. Continuous generation
   is not just cheaper; Article 9 *requires* risk management to be
   "continuous and iterative", so the process itself is evidence.
3. **Make the record tamper-evident.** When an authority asks "what did you
   know and when", a hash-chained ledger of every scan — where editing or
   deleting a historical entry visibly breaks the chain — is a categorically
   better answer than a folder of Word documents with a `_final_v3` naming
   convention.
4. **Write the judgement sections once, properly.** Intended purpose, human
   oversight design, accuracy claims. No tool writes these; every tool
   should embed them.

## The uncomfortable part of the timeline

Enforcement authority appointments and procedures are still maturing across
member states, and early enforcement will likely be complaint-driven and
uneven. It is tempting to read that as "nothing will happen for a while".
Two problems with that bet: the *documentation* obligation is binary and
retrospective — a system placed on the market in August 2026 without
documentation is non-compliant from day one, whenever the question arrives —
and your **enterprise customers are not waiting**: AI Act evidence is
already appearing in procurement questionnaires, which is a faster and more
certain enforcement mechanism than any regulator.

## Start with the part that costs one CI job

The mechanical half of the evidence (AI-BOM, risk register, Annex IV draft,
immutable scan ledger) is a single GitHub Actions job with AIcap — free CLI,
EU-hosted ledger, and your source code never leaves your pipeline. The
judgement half is yours either way; stop spending engineering time on the
half that automates.
