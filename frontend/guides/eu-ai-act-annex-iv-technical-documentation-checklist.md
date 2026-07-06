---
title: EU AI Act Annex IV — the complete technical documentation checklist (2026)
description: What Annex IV actually requires, section by section, which parts you can auto-generate from your repository, and which parts only a human can write.
date: 2026-07-06
---

# EU AI Act Annex IV: the complete technical documentation checklist

If you provide a **high-risk AI system** in the EU, Article 11 of the AI Act
requires technical documentation *before* the system goes on the market — and
Annex IV defines exactly what that documentation must contain. From
**2 August 2026**, this stops being a future obligation.

This checklist walks through every Annex IV section from an engineering
perspective: what evidence satisfies it, and whether it can be generated from
your repository or must be written by a human.

## First: does Annex IV even apply to you?

Annex IV applies to **high-risk** systems as classified by Article 6 and
Annex III. The common triggers for software teams:

- Employment and worker management (CV screening, promotion decisions)
- Access to essential services (credit scoring, insurance pricing)
- Education (exam scoring, admission decisions)
- Biometric identification and categorisation
- Law enforcement, migration, and justice use cases

If your system is high-risk, you need the full Annex IV package. If it is a
general-purpose model, Article 53 imposes a related-but-different
documentation duty. If it is neither, you still benefit from most of this
checklist — customers and enterprise procurement increasingly ask for it
regardless.

## The checklist, section by section

### Section 1 — General description

- [ ] Intended purpose, in concrete operational terms
- [ ] Provider name and system version
- [ ] How the system interacts with hardware or other software
- [ ] Versions of relevant software/firmware and update requirements
- [ ] Forms in which the system is placed on the market

**Automatable?** Partially. Version, commit SHA, and dependency interactions
can be extracted from the repository. The *intended purpose* cannot — a
scanner does not know whether your classifier screens résumés or sorts
cucumbers. Write it yourself, precisely: vague purposes widen your risk
surface in a conformity assessment.

### Section 2 — Detailed technical description

- [ ] Development process and methods, including third-party tools
- [ ] **Pre-trained systems and components used** — this is your AI-BOM
- [ ] Architecture, computational resources, and hardware requirements
- [ ] Data requirements (datasheets, provenance, labelling)
- [ ] Human oversight measures per Article 14
- [ ] Predetermined changes and continuous-learning boundaries

**Automatable?** Largely, and this is where most manual effort is wasted. A
dependency scan of your manifests (`requirements.txt`, `package.json`,
`go.mod`, lockfiles, Dockerfiles, Terraform) produces the component
inventory; container-image scanning catches model weights baked into layers;
infrastructure manifests reveal the compute footprint. Every hand-maintained
component list is out of date by the next merge — generate this from the
repository on every commit instead.

### Section 3 — Monitoring, functioning, and control

- [ ] Capabilities and limitations, expected accuracy
- [ ] Foreseeable unintended outcomes and risk sources
- [ ] Human oversight measures (again — the Act really cares)
- [ ] Input data specifications

**Automatable?** Evidence of oversight tooling is detectable (approval gates
in CI, human-in-the-loop steps in orchestration manifests, moderation
services in the dependency graph). Accuracy claims need your evaluation
results.

### Section 4 — Risk management system (with Article 9)

- [ ] A **continuous, iterative** risk management process — not a one-off PDF
- [ ] Known and foreseeable risks, per component
- [ ] Mitigation and control measures

**Automatable?** The component-level risk register is: your dependency graph
cross-referenced against known ML attack patterns (OWASP ML Top 10, MITRE
ATLAS) and live vulnerability feeds (CVE/GHSA). Article 9's "continuous"
requirement is the strongest argument for putting this in CI — a register
regenerated on every commit is continuous by construction.

### Sections 5–9 — The long tail

- [ ] Description of changes made through the lifecycle (Section 5)
- [ ] List of applied harmonised standards (Section 6)
- [ ] Copy of the EU declaration of conformity (Section 7)
- [ ] Post-market monitoring plan per Article 72 (Section 8)

**Automatable?** Section 5 is your git history, if your documentation is
versioned with your code. Sections 6–8 are legal artefacts — counsel
territory.

## The pattern to notice

Everything mechanical in Annex IV (component inventories, risk registers,
hardware descriptions, change logs) rots the moment it is written by hand.
Everything judgement-based (intended purpose, oversight design, accuracy
claims) *should* be written by hand — once — and versioned.

The workable division of labour: **generate the mechanical sections from the
repository on every commit; keep the judgement sections as reviewed prose
that the generator embeds.** That is precisely what AIcap's scanner does —
it emits an Annex IV draft with the mechanical sections filled and the
judgement sections explicitly marked `[REQUIRES MANUAL INPUT]`, so an
auditor sees "we looked and found nothing automated" rather than silence.

## Timeline reality check

The obligations for most high-risk systems apply from **2 August 2026**.
Documentation must exist *before* market placement, and Article 99 penalties
for non-compliance with high-risk obligations reach **€15 million or 3% of
global turnover**. Starting the mechanical half today costs one CI job.
