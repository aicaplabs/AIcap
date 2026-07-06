---
title: EU AI Act Article 9 — implementing continuous risk management in CI/CD
description: Article 9 requires a continuous, iterative risk management system for high-risk AI. Here is what that means in engineering terms, and how to build the evidence trail into your pipeline.
date: 2026-07-06
---

# Article 9: implementing continuous risk management in CI/CD

Article 9 is the EU AI Act obligation most likely to be misread as
paperwork. It is not asking for a risk assessment *document* — it explicitly
requires a risk management **system**: "a continuous iterative process
planned and run throughout the entire lifecycle" of a high-risk AI system.

A PDF written last quarter is, by definition, not a continuous iterative
process. Your CI pipeline is. This guide maps Article 9's requirements onto
engineering practice.

## What Article 9 actually requires

Condensed from the article text, the system must:

- **Identify** known and reasonably foreseeable risks to health, safety,
  and fundamental rights
- **Estimate and evaluate** risks that may emerge in use and foreseeable
  misuse
- **Evaluate** risks identified from post-market monitoring data
- **Adopt** targeted risk management measures
- Be **updated** throughout the lifecycle — this is the word that kills
  the one-off-assessment approach

## The component layer: risks you can enumerate automatically

A meaningful share of an ML system's risk surface is carried by its
components, and components are enumerable from the repository:

| Component class | Known risk pattern | Framework reference |
|---|---|---|
| Model-loading frameworks (transformers, torch) | Supply-chain compromise, unsafe deserialization | OWASP ML06, MITRE ATLAS AML.T0010 |
| LLM orchestration (langchain, llama-index) | Prompt injection, excessive agency | OWASP ML01 / LLM01 |
| Hosted model APIs (openai, anthropic) | Data leakage to third parties, availability | OWASP ML02 |
| Local model weights (.safetensors, .pt, .gguf) | Model theft, provenance gaps | OWASP ML05, AML.T0044 |
| Training pipelines (dvc, dataset imports) | Data poisoning | OWASP ML02, AML.T0020 |

A **risk register generated per commit** — dependency graph cross-referenced
against these catalogs plus live CVE/GHSA feeds — gives you the
"identification" and "update" limbs of Article 9 for the component layer,
with zero marginal effort after setup.

## The judgement layer: risks only you can describe

No scanner knows that your recommender could disadvantage a protected group,
or that your users will paste medical records into the prompt box. Article 9
still needs a human-authored analysis of:

- Use-case-specific harms (who is affected, how badly, how reversibly)
- Foreseeable misuse (the Act's language, not optional)
- Residual risk after mitigation, and why it is acceptable

Write this once, review it on a cadence, version it next to the code it
describes. When the register and the analysis live in the same repo, the
diff history *is* your lifecycle evidence.

## What "evidence of a continuous process" looks like

Imagine the market surveillance authority's document request. Compare two
answers:

1. *"Attached is our risk assessment (March 2026)."*
2. *"Our risk register is regenerated on every commit; here is the
   tamper-evident ledger of every scan since January, and here is the
   register as of the release you are asking about."*

The second answer is structurally better in three ways: it demonstrates the
process is continuous (Art. 9(2)), it is tied to specific system versions
(Art. 11's up-to-date requirement), and it is hard to fabricate
retroactively — each ledger entry chains to its predecessor's hash, so
backdating an entry breaks verification at every later link.

## A minimal implementation

1. Add an AI-BOM + risk-register scan to CI (one job — see our GitHub
   Actions guide).
2. Fail the pipeline on blocker-severity findings, so unmitigated risk
   cannot reach production silently — that is your Art. 9(4) "adoption of
   measures" evidence.
3. Anchor each scan to an immutable ledger (AIcap Pro does this per
   commit).
4. Keep the human-authored harm analysis in the repo; reference it from the
   generated Annex IV Section 3.

The whole setup is an afternoon. Being asked for it and not having it is a
tier-2 penalty conversation — up to €15M or 3% of turnover.
