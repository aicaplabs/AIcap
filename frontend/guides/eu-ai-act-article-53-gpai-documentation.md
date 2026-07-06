---
title: EU AI Act Article 53 — documentation duties for GPAI model providers
description: If you train, fine-tune, or substantially modify a general-purpose AI model, Article 53 documentation obligations have applied since August 2025. What they require and how to keep the technical half current.
date: 2026-07-06
---

# Article 53: documentation duties for GPAI model providers

Most EU AI Act coverage fixates on high-risk *systems* and the August 2026
date. But if you provide a **general-purpose AI model** — including a
fine-tune of someone else's — a separate obligation set in Article 53 has
already applied **since 2 August 2025**. If that describes you, this is not
a countdown; you are in the applicability window now.

## Are you a GPAI provider?

You likely are if any of these hold:

- You **train a foundation model** and make it available in the EU (API,
  weights release, embedded in your product)
- You **fine-tune or substantially modify** an existing GPAI model and
  place the result on the market — the fine-tuner takes on provider duties
  for the modification
- You **release open weights** — the open-source exemption relieves some
  Article 53 duties, but *not* the copyright policy and training-content
  summary, and it vanishes entirely if the model carries systemic risk

You are probably *not* a GPAI provider if you only call third-party model
APIs. Your obligations then live in the system-level rules (and your API
vendor's Article 53 documentation becomes something you should be
requesting — see below).

## The four Article 53 duties

| Duty | For whom |
|---|---|
| **(a)** Technical documentation of the model — training and testing process, evaluation results (Annex XI spells out the contents) | All providers (open-source partially exempt) |
| **(b)** Information and documentation for downstream providers who build on your model (Annex XII) | All providers (open-source partially exempt) |
| **(c)** A policy to comply with EU **copyright** law, including honouring text-and-data-mining opt-outs | Everyone, no exemption |
| **(d)** A **public summary of training content**, using the AI Office template | Everyone, no exemption |

Models classified as having **systemic risk** (the compute threshold is
10^25 FLOPs, or designation by the AI Office) add Article 55: adversarial
testing, incident reporting, cybersecurity measures.

## The Annex XI technical file, in engineering terms

Annex XI wants, among other things: the model's architecture and parameter
count, design specifications and training methodology, **data provenance
and curation methods**, compute used (training time, hardware), energy
consumption, and evaluation results. Two observations from doing this in
practice:

- **The dependency and infrastructure half is mechanical.** Training-stack
  inventory (frameworks, dataset tooling, orchestration), hardware
  descriptions, and the software supply chain around the model are
  extractable from the repositories that produced it — the same AI-BOM
  scan that feeds Annex IV for high-risk systems feeds Annex XI here. GPU
  infrastructure detection (Terraform/K8s) gives you the compute-resources
  section with cost figures attached.
- **The data-provenance half is procedural.** Dataset manifests (DVC
  files, HF dataset references) are detectable in-repo and give you
  anchors, but curation methodology and the copyright policy are documents
  a human must own.

## The downstream-documentation duty is a two-way street

Annex XII is what *your* customers get: capabilities, limitations,
integration requirements, evaluation results. Flip it around: **if you
build on a GPAI model, you are entitled to this documentation from your
provider.** Put it in your vendor checklist. When your own high-risk
system's Annex IV asks about the pre-trained model you used, the answer
should be your provider's Annex XII package plus your own integration
evidence — your AI-BOM showing exactly which model, version, and SDK sit
in the stack.

## Practical sequencing

1. **Classify yourself honestly** — provider, downstream deployer, or
   both (fine-tuning makes you both).
2. **Stand up the mechanical evidence now**: per-commit AI-BOM of the
   training and serving repos, infrastructure description, model-weight
   inventory with provenance. One CI job.
3. **Write the procedural documents once**: copyright/TDM policy,
   training-content summary on the AI Office template, curation
   methodology.
4. **Version everything together.** Article 53 documentation must be kept
   up to date; documentation that lives in the repo and regenerates its
   mechanical sections on merge is up to date by construction — and a
   hash-chained scan ledger proves *when* each version existed.

The pattern is the same one that works for Annex IV: automate the inventory
that rots, hand-write the judgement that doesn't.
