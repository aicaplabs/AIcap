---
title: EU AI Act Article 50(2) — the 2 December 2026 marking date for existing generative AI
description: If your product generates text, images, audio or video and was already on the market before 2 August 2026, the machine-readable marking duty applies from 2 December 2026. Who it covers, what "machine-readable" means, and how to find out which of your services are in scope.
date: 2026-11-16
---

# Article 50(2): the 2 December 2026 marking date for existing generative AI

Most attention on the EU AI Act went to the high-risk regime, and then to
its delay: Regulation (EU) 2026/1744 moved those obligations to
2 December 2027. Article 50 was not moved. The transparency duties have
applied since **2 August 2026**, with one transitional rule — and that rule
runs out on **2 December 2026**.

## The rule, in one paragraph

Article 50(2) requires providers of AI systems that generate synthetic
audio, image, video or text to make sure the output is **marked in a
machine-readable format and detectable as artificially generated or
manipulated**. For a system placed on the market on or after 2 August 2026,
that has applied from day one. For a generative system that was **already
on the market before 2 August 2026**, the amended Article 111 gives until
**2 December 2026** to comply.

So the question for this date is narrow: do you have a generative product
that was live before August, and is its output marked?

## Does it apply to you?

Work through it in order.

**1. Do you provide the system?** Article 50(2) is a provider duty. If you
put a product on the market under your own name and it generates content,
you are the provider of that AI system, even when the model behind it is
someone else's and you reach it through an API. Whether marking applied
upstream by the model provider is enough for your system is a question for
your counsel and for the Commission's guidelines on Article 50 — do not
assume it either way.

**2. Does it generate synthetic content?** Text counts, not only images,
audio and video. A support assistant that drafts replies generates
synthetic text.

**3. Does an exception fit?** The duty does not apply where the system
performs an assistive function for standard editing, or does not
substantially alter the input data or its semantics. A spell checker is
the easy case. Most things in between need an actual assessment.

**4. Was it on the market before 2 August 2026?** If yes, your date is
2 December 2026. If no, the duty already applies.

## What "machine-readable" rules out

A visible "made with AI" label does not satisfy Article 50(2). That kind of
audience-facing disclosure belongs to a different paragraph, Article 50(4),
which covers deep fakes and AI-generated text published on matters of
public interest, and falls on deployers.

Article 50(2) asks for a marking that software can read and detect. The
Act requires the technical solution to be effective, interoperable, robust
and reliable as far as technically feasible, and names no single
technology. In practice the options in use are:

- **Provenance metadata** — a signed manifest that travels with the file
  (C2PA content credentials).
- **Watermarking** — a signal embedded in the image, audio or text itself.
- **Both**, since metadata is easily stripped and watermarks vary in
  robustness.

The Commission has published a Code of Practice on the marking and
labelling of AI-generated content. It is voluntary; the obligation in
Article 50 is not.

## What it costs to get wrong

Article 50 sits in the middle penalty tier of Article 99: up to
**€15 million or 3% of worldwide annual turnover**, whichever is higher.
For SMEs and small mid-caps the lower of the two applies. These are
ceilings, and authorities must act proportionately.

## The step most teams skip: finding the systems

The assessment above is done per system. That presumes a list of systems.
In most organisations nobody holds one: a generative feature was added to
one service last spring, a text-to-speech call sits in another, and an
internal tool that drafts customer emails quietly became external.

A dependency scan cannot tell you whether a marking duty is met. It can
tell you **which repositories contain something that generates content**,
which is the list the assessment needs. That is the part worth automating,
because it changes every time someone adds a library.

## What a scan shows, and what it cannot

AIcap raises an Article 50(2) entry when it finds a component that
generates content — image and audio generation libraries, and the client
libraries for hosted language models. For each entry it reports:

- **What triggered it** — the components, and where they were found.
- **The question a person has to answer** — does this system emit
  generated content to anyone outside the team, and what machine-readable
  marking is applied?
- **Evidence of a marking control**, if one is present in the dependency
  graph: a watermarking library, a C2PA library, an audio watermarking
  library.

Two limits, stated in the report itself:

- Finding a marking library shows that one is installed. It does not show
  which output paths it wraps. The report says to verify coverage; it never
  says "compliant".
- Finding none is not proof the duty is unmet. Marking may be applied by an
  upstream service or a gateway the scan cannot see. The entry is a prompt
  to check, not a finding of breach.

The other Article 50 duties — telling people they are talking to an AI,
and informing people subject to emotion recognition or biometric
categorisation — are discharged by interface copy and consent flows. Those
leave no trace in a manifest, and the report says so instead of showing an
empty evidence list that could be read as a gap.

## Run it

```yaml
name: AI inventory

on:
  push:
    branches: [ "main" ]

jobs:
  aicap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aicaplabs/AIcap@v1.8.0
```

No account and no API key are needed. The scan runs inside your own
runner and your source code does not leave it. The Article 50 entries
appear in the job log and in the generated report, alongside the AI-BOM.

## After 2 December

The date closes the transitional window; it does not end the work. Every
new generative feature brings the duty with it from the day it ships, and
the inventory that tells you a feature was added is the same one you will
need for the high-risk assessment in 2027. Start it once and keep it
running.

This guide is engineering guidance, not legal advice. Check the dates and
the scope against the text of Regulation (EU) 2024/1689 as amended, and
the Commission's guidelines on Article 50, before relying on them.
