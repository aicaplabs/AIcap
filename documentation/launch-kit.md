# AIcap Launch Kit

_Prepared 2026-07-22. Copy is ready to fire — nothing here needs rewriting
before posting. Every claim below is verified against what actually ships;
do not add social proof (user counts, "trusted by", testimonials) until it
is real._

---

## Timing

The EU AI Act's high-risk obligations apply **2 August 2026**. The
"beat the deadline" framing is at peak strength now and weakens after —
though it does not vanish, since enforcement anxiety tends to rise once a
regime is live. Sequence accordingly.

| When | Action | Owner |
|---|---|---|
| Before anything | Supabase paid tier + monitoring live | You |
| Launch day −1 | Verify: signup → scan → ledger → share link works end to end | You |
| Launch day (Tue–Thu, ~14:00 CET) | Show HN, then LinkedIn post #1 | You |
| Launch day +1 | Product Hunt | You |
| Rolling, from day 1 | Consultancy outreach (5–10/day, personalised) | You |
| Day +3, +7 | LinkedIn posts #2, #3 | You |

**Why Tue–Thu ~14:00 CET:** that lands mid-morning US Eastern, catching
both European and American HN traffic. Avoid Friday and weekends.

**Do not launch before the Supabase paid tier is active.** The free tier
auto-pauses on inactivity and a paused database fails the backend's
startup ping. Driving launch traffic to an intermittently dead product is
the one unrecoverable mistake available here.

---

## 1. Show HN

HN is the highest-value and least forgiving channel. It rewards technical
substance and punishes marketing voice. Post it yourself, in first person,
and stay in the thread for the first 3–4 hours to answer questions.

**Title** (keep under 80 chars):

```
Show HN: AIcap – EU AI Act compliance scanning in your CI pipeline
```

**Body:**

> The EU AI Act's high-risk obligations apply from 2 August 2026. One of
> them (Article 11 / Annex IV) requires technical documentation to exist
> *before* you place a system on the market. Most of that document is
> mechanical — a component inventory, a per-component risk register, a
> hardware/compute description — and it goes stale the moment someone
> bumps a dependency.
>
> AIcap generates the mechanical half from your repo on every commit.
>
> What it actually does:
>
> - Walks your manifests (requirements.txt, pyproject, poetry.lock,
>   Pipfile.lock, package.json, pnpm/yarn lockfiles, go.mod, Conda
>   environment.yml) plus source imports and Dockerfiles, and builds an
>   AI-BOM.
> - Scans container image layers **daemonlessly** (via
>   go-containerregistry) for model weights that never touch git —
>   `.safetensors`, `.onnx`, `.gguf`, `.pt` and friends. Header reads
>   only, so a multi-gigabyte image doesn't cost you the layer bodies.
>   Findings are attributed back to `image#layerN:path`.
> - Cross-references each dependency against OWASP ML Top 10 and MITRE
>   ATLAS, then enriches with live CVE/GHSA data from OSV.dev.
> - Detects GPU instances in Terraform/Kubernetes/Helm and attaches cost
>   estimates — a `p4d.24xlarge` left on-demand is roughly $25k/month,
>   and it flags training-class hardware serving inference-only
>   workloads.
> - Emits an Annex IV markdown draft where the judgement sections are
>   explicitly marked `[REQUIRES MANUAL INPUT]` rather than silently
>   omitted, so an auditor sees "we looked and found nothing automated"
>   instead of a gap.
> - CycloneDX 1.5 export, so the AI components ride the same rails as
>   the rest of your SBOM tooling (Dependency-Track etc.).
> - Policy-as-code via `.aicap.yml`, with exit codes — 0 clean, 1
>   unmitigated high-risk dependency, 2 explicit policy breach — so it
>   can gate merges rather than just report.
>
> The CLI is MIT-licensed and runs entirely inside your own runner; your
> source never leaves it. Only the derived BOM is transmitted, and only
> if you set an API key.
>
> The paid tier is a hosted audit ledger: each scan is hash-chained to
> its predecessor, so editing, reordering, or deleting a historical
> entry breaks verification at every later link. Plus shareable report
> links you can hand an auditor without giving them a login.
>
> Honest limitations:
>
> - It drafts documentation. It is not legal advice, and using it does
>   not by itself make you compliant.
> - It cannot know your intended purpose, your human-oversight design,
>   or your accuracy claims. Those stay `[REQUIRES MANUAL INPUT]` by
>   design — I'd rather the gap be visible than papered over.
> - Model weight files have no CVE identifiers, so their SBOM entries
>   are inventory and provenance, not vulnerability coverage.
> - Whether you're high-risk at all is a classification question you
>   have to answer; the tool doesn't decide it for you.
>
> It's EU-hosted (compute in Paris, database in Ireland) because
> "compliance product running on US infrastructure" was the first
> objection I got.
>
> Repo: https://github.com/aicaplabs/AIcap
> Try it: `uses: aicaplabs/AIcap@v1.4.0`
>
> Happy to answer anything.

**Prepared answers for likely HN pushback:**

- *"This is a wrapper around grep."* — Fair challenge on the manifest
  parsing; the non-trivial parts are the daemonless OCI layer walk, the
  hash-chained ledger, and the risk-register cross-referencing. Say so
  plainly, don't oversell the parsing.
- *"Compliance theatre."* — Agree that a scanner can't make anyone
  compliant, and point at the `[REQUIRES MANUAL INPUT]` design as the
  deliberate anti-theatre choice. The pitch is "stop hand-maintaining
  the half that rots", not "compliance solved".
- *"Why not just use Syft/Trivy?"* — They're excellent at packages;
  they don't inventory model weights, hosted-model dependencies, model
  licences, or emit Annex IV structure. Link the AI-BOM vs SBOM guide.
- *"How do you make money?"* — Direct answer: free MIT CLI, $49/month
  hosted ledger, self-hosted Helm chart for enterprises. Don't be coy.

---

## 2. Product Hunt

**Tagline** (60 char limit):

```
EU AI Act compliance, generated from your CI pipeline
```

**Description:**

> Every AI system on the EU market faces the AI Act's high-risk
> obligations from 2 August 2026 — including Annex IV technical
> documentation that must exist before launch and stay current.
>
> AIcap turns that into a CI job. On every commit it builds your AI-BOM
> (dependencies, model weights, hosted model APIs, GPU infrastructure),
> cross-references it against OWASP ML Top 10 / MITRE ATLAS with live
> CVE data, and emits an Annex IV draft plus a CycloneDX SBOM.
>
> The scanner is open source and runs in your own pipeline — your code
> never leaves it. Pro adds a tamper-evident, hash-chained audit ledger
> and shareable reports you can send an auditor without giving them a
> login. EU-hosted throughout: compute in Paris, database in Ireland.

**First comment (post immediately as maker):**

> Maker here. I built this because the mechanical half of AI Act
> documentation — the component inventory, the risk register, the
> compute description — is exactly the kind of thing that's accurate on
> the day you write it and wrong a week later. Generating it per-commit
> is the only version that stays true.
>
> The design decision I'd most like feedback on: sections a scanner
> can't know (intended purpose, human oversight, accuracy claims) are
> emitted as explicit `[REQUIRES MANUAL INPUT]` placeholders rather than
> quietly dropped. It makes the output look less finished, but an
> auditor seeing a visible gap is better than one discovering a silent
> one.
>
> Free CLI is MIT. Happy to answer anything.

**Gallery:** reuse the five README screenshots in
`documentation/screenshots/` — lead with `annex-iv-preview.png` (the
artifact), then `ci-blocking.png` (enforcement), `audit-ledger.png`
(trust), `public-shared-report.png` (sharing), `ci-passing.png`.

---

## 3. LinkedIn

This is where compliance officers, DPOs, and AI-governance people
actually are. Post from your personal profile — founder posts
consistently outperform company pages. Keep paragraphs to 1–2 lines.

### Post #1 — the deadline (launch day)

> The EU AI Act's high-risk obligations apply in 11 days.
>
> If you provide a high-risk AI system in the EU, Article 11 requires
> technical documentation — Annex IV — to exist *before* the system goes
> to market. Not after the first audit. Before.
>
> Having read Annex IV more times than is healthy, here's what stands
> out: most of it is mechanical.
>
> → A component inventory (every model, framework, and dataset)
> → A per-component risk register, kept current
> → Compute and hardware description
> → A record of changes across the lifecycle
>
> All of that is derivable from the repository that builds the system.
> And all of it is wrong within a week if you maintain it by hand.
>
> The other half — intended purpose, human oversight design, accuracy
> claims — genuinely needs a human. That part should be written once,
> carefully, and versioned.
>
> So we built the boring half into CI. Every commit regenerates the
> inventory, the risk register, and the Annex IV draft.
>
> Free and open source: github.com/aicaplabs/AIcap
>
> #EUAIAct #AICompliance #AIGovernance

### Post #2 — the insight (day +3)

> Your SBOM probably doesn't know what models you're running.
>
> Software bills of materials inventory packages. They're very good at
> it. But an ML system's highest-risk components usually aren't
> packages:
>
> → Model weights downloaded in a Dockerfile RUN step
> → Checkpoints baked into a base image by another team, last year
> → A hosted model dependency that changes underneath you
> → Model licences with use restrictions no OSS licence has
>
> None of those appear in a standard SBOM. All of them appear in EU AI
> Act Annex IV Section 2.
>
> The gap between "what your SBOM says" and "what your container
> actually ships" is precisely the part nobody is accountable for.
>
> We wrote up the difference here: aicap.dev/guides/ai-bom-vs-sbom-difference.html
>
> #SBOM #AISecurity #SupplyChain #EUAIAct

### Post #3 — the artifact (day +7)

> "What does an EU AI Act Annex IV document actually look like?"
>
> It's the question I get most, and it's fair — the regulation describes
> required contents, not a format.
>
> So we published a complete worked example: a full Annex IV technical
> documentation draft for a high-risk hiring system. Component
> inventory, Article 9 risk register cross-referenced against OWASP ML
> Top 10, GPU cost telemetry, governance evidence.
>
> No signup. It's on the homepage: aicap.dev
>
> Two things worth noticing:
>
> 1. The sections a tool can generate, it generates — from the repo, on
> every commit.
> 2. The sections requiring human judgement are marked as such, visibly,
> rather than quietly left out.
>
> If you're preparing for 2 August, seeing the shape of the deliverable
> is usually worth more than another explainer about the deadline.
>
> #EUAIAct #Compliance #AnnexIV

---

## 4. Consultancy & law-firm outreach

The highest-leverage channel and the least crowded. AI Act readiness
consultancies and tech law firms are running client engagements right now
with no tooling to hand over. One good partner beats a month of SEO.

**Targets:** EU tech law firms with an AI/data practice, GRC
consultancies, fractional DPO services, notified bodies' advisory arms.
Find them via LinkedIn ("EU AI Act" + consultant/counsel), and via who is
publishing AI Act explainers.

**Subject:** `Annex IV tooling for your AI Act engagements`

**Body:**

> Hi {Name},
>
> I saw your {article/post/practice page} on EU AI Act readiness — {one
> specific, genuine sentence about it}.
>
> I build AIcap, an open-source scanner that generates the mechanical
> half of Annex IV technical documentation directly from a client's
> repository: the AI component inventory, an Article 9 risk register
> cross-referenced against OWASP ML Top 10 and live CVE data, and the
> compute/hardware description. It runs in their CI, so it regenerates
> on every commit rather than going stale between engagements.
>
> The reason I'm writing: in readiness engagements, the inventory work is
> usually the least valuable use of your time and the most annoying to
> keep current — while the judgement work (classification, intended
> purpose, oversight design, residual risk) is exactly what clients
> should be paying you for. This handles the former so you can charge for
> the latter.
>
> The CLI is free and MIT-licensed — no commitment, and nothing to sell
> your clients if you don't want to. If it's useful, I'm happy to
> discuss a referral arrangement or a co-branded report footer.
>
> Sample output (no signup): https://aicap.dev
> Source: https://github.com/aicaplabs/AIcap
>
> Worth a 20-minute call?
>
> {Your name}

**Rules:** personalise the first line genuinely or don't send it. 5–10
per day, manually. Never bulk-send — a compliance audience is the exact
audience that will notice and hold it against you.

---

## 5. Communities & directories

**Reddit — proceed carefully.** These subs are hostile to promotion and
will punish a launch post. Only participate where you're genuinely
answering, and disclose that you built it.
- r/devops, r/mlops — the GitHub Actions tutorial is a legitimate
  contribution; the SaaS pitch is not.
- r/gdpr, r/compliance — the penalties and classification guides land
  well as answers to existing questions.
- Avoid r/MachineLearning for this; wrong audience, high downvote risk.

**Directories & lists** (low effort, compounding):
- `awesome-mlops`, `awesome-ai-governance`, `awesome-compliance` — open
  a PR adding AIcap with a one-line description
- OWASP ML Security community channels
- Journalists and bloggers writing "tools for AI Act compliance"
  roundups — there will be a wave of these in the deadline window; a
  short, factual email with the sample report converts well

**Hacker News follow-up:** if the Show HN underperforms, don't repost.
Instead submit a *guide* later (the penalties or classification piece) as
a regular link — different post type, different reception.

---

## What not to do

- **No fabricated social proof.** No user counts, no "trusted by", no
  invented testimonials. You have zero customers today and the audience
  is professionally trained to check claims.
- **No "guaranteed compliance" language.** It's false, it's a legal
  exposure, and it contradicts your own Terms disclaimer.
- **No launching before the database is on a paid tier.**
- **No Product Hunt and Show HN on the same day** — you can't be present
  in two comment threads at once, and presence is most of the value.

---

## Measurement

Track which channel produced each of the first 20 signups — ask directly
in onboarding if needed. With a two-week trial, the meaningful conversion
signal arrives ~14 days after launch, so resist judging channels earlier
than that.

Goal for the window: **first 10 paying customers**, not scale. Ten
customers give you testimonials, feedback on what the compliance buyer
actually needs, and proof the $49 price point holds.
