---
title: Scanning container images for hidden model weights (no Docker daemon)
description: Model weights routinely ship inside container layers where no repo scan can see them. How daemonless OCI layer scanning finds them, and why your compliance inventory is incomplete without it.
date: 2026-07-06
---

# Scanning container images for hidden model weights

There is a reliable gap in every repository-level AI inventory: **the model
that isn't in the repository**. It was `curl`-ed in a Dockerfile `RUN`
step, `COPY`-ed from a build context that never got committed, or baked
into a base image by another team a year ago. The repo scan says
"scikit-learn, nothing exciting"; the image serving production traffic
contains a 7-GB fine-tuned checkpoint nobody inventoried.

If your Annex IV documentation or security review is built purely from
source scanning, this gap is where it is wrong.

## Why weights end up in layers

- **Build-time downloads**: `RUN wget https://.../model.safetensors` —
  fast to write, invisible to source scanning, and the URL may not even
  resolve anymore
- **Base images with batteries**: internal "ML base" images that
  pre-bundle weights for cold-start speed
- **Vendored checkpoints**: weights copied from artifact stores during CI
  builds, never touching git
- **Framework caches**: a `transformers` download cache committed into an
  image by accident — surprisingly common

Each is a component with provenance, licence, and tampering questions
attached, sitting outside the inventory.

## Daemonless layer scanning: how it works

You do not need a Docker daemon to inspect an image. An OCI image is a
manifest plus a stack of tar-archive layers; a scanner can pull those via
the registry API (or read a `docker save` tarball) and walk every file
entry directly. The AIcap implementation:

- Detects weight files by extension (`.safetensors`, `.onnx`, `.pt`,
  `.h5`, `.gguf`, `.tflite`, `.pb`, `.ckpt`, …) and by sentinel names
  (`pytorch_model.bin`, `model.safetensors`) — **headers only, bodies are
  never read**, so scanning a multi-gigabyte image stays fast
- Reads Python `dist-info/METADATA` and Node `node_modules` package
  manifests inside layers, so pip-installed-at-build-time AI libraries
  are captured even though no requirements file mentions them
- Respects whiteout markers, so files deleted in later layers do not
  create false findings
- Attributes every finding to its exact position:
  `image#layer3:/models/pytorch_model.bin` — evidence, not vibes

## Using it in CI

Both remote references and local tarballs work, both flags repeatable:

```bash
# Scan the repo AND the image it produces
./aicap --cli . --image ghcr.io/your-org/inference:latest

# Or scan the image built earlier in this pipeline, pre-push
docker save your-app:candidate -o candidate.tar
./aicap --cli . --image-tar candidate.tar
```

Findings merge into the same AI-BOM as the source scan, the compliance
posture is re-evaluated with them included, and the Annex IV draft gains a
"Container Images Inspected" section listing each image, its digest, layer
count, and finding count. Registry auth uses your ambient credentials (the
default keychain), so private registries work in CI without extra wiring.

## What this closes, concretely

- **Annex IV Section 2(a) completeness** — "pre-trained systems and
  components used" includes the checkpoint in layer 3, whether or not git
  knows about it. An auditor comparing your documentation against your
  running image is exactly the failure mode that converts a documentation
  gap into a credibility problem.
- **Licence exposure** — weights carry licences (OpenRAIL restrictions,
  research-only clauses) that were never reviewed because the file never
  hit a repo.
- **The incident-response question** — when the next model-supply-chain
  advisory lands, "do we ship this checkpoint anywhere?" is answerable
  from inventory instead of by grepping every Dockerfile in the org and
  hoping.

## The rule of thumb

Scan what you *ship*, not just what you *write*. Source scanning covers
intent; layer scanning covers reality. They take one flag to run together,
and the delta between them is precisely the part of your AI supply chain
nobody was accountable for.
