# documentation/

Everything in this directory is **public**. It ships with the repository:
anyone who clones AIcap — customer, auditor, competitor — reads it.

Put a file here only if you would be comfortable with all three reading it.

## Public (tracked)

| Path | Audience | Purpose |
|---|---|---|
| `screenshots/` | Everyone | Product screenshots embedded in the root README and the GitHub Marketplace listing |

Customer-facing prose lives on the website, not here. The data-residency
statement, the compliance guides, and anything else a prospect needs to
read is authored in `frontend/guides/` and published to
`aicap.dev/guides/` by `npm run build:guides` — a document a customer is
expected to read should have a URL you can paste into a security
questionnaire, not a path inside a git repository.

## Private (never tracked)

`documentation/internal/` is gitignored **as a whole directory**. Launch
plans, funnel checklists, pricing working, outreach lists, revenue
targets, internal status notes — anything written for an audience of one.

The directory-level rule is deliberate. The previous approach was a
`.gitignore` line per private file, which only protects the files someone
remembered to write a rule for *before* committing. Ignoring the whole
directory makes privacy the default: drop a note in `internal/` and it is
already private.

**New private note?** `documentation/internal/whatever.md`. Nothing else
to do.

**Note in the wrong place?** `git mv` it into `internal/` and commit the
deletion. Be aware that untracking a file removes it from the working
tree going forward but **not from git history** — anything already pushed
to a public remote stays readable in the history until the history itself
is rewritten.
