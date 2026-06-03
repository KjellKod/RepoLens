# RepoLens

**Know exactly what open source you ship — and what it obligates you to.**

RepoLens is a **license-disclosure orchestrator**. It points best-in-class tools at every
repository under an owner, in any language, and turns the ambiguity they leave behind
into one clean, evidence-backed disclosure. It **doesn't reinvent scanners — it conducts
them**, and adds the workflow, policy, evidence, and reporting on top.

> All six pipeline stages are shipped and tested end-to-end. See
> **[docs/usage.md](docs/usage.md)** for how to run it, and
> **[docs/roadmap](docs/roadmap/rpl_README.md)** for the design, decisions, and security model.

## Quickstart

```bash
pip install -e .                                       # install the `repolens` command (editable)
repolens --help                                        # the stages, and the typical run
python -m repolens.security.name_hygiene --self-test   # prove the name-hygiene guard works
```

`repolens --help` shows the full pipeline (`discover → scan → resolve → flag → shortlist
→ report`), and each stage's own `--help` explains what to run before it, an example, its
output, and the next step. All six stages run real orchestration today.

## What you get

- **A deduplicated license disclosure** — `Name | License | …` as Markdown, CSV, and a
  ready-to-share **`.docx`**, plus per-category appendices. One row per library, nothing
  silently dropped.
- **Risk flagged, not buried** — copyleft, network-copyleft, non-commercial, and
  source-available licenses surfaced against a configurable policy.
- **Ambiguity resolved with evidence** — anything the tooling can't determine is flagged
  and settled against a *fetchable* source (LICENSE permalink, registry field, SPDX
  match), with a human approving before it lands.
- **A complete, categorized inventory** (`inventory.json`) behind the report — every
  component tagged by origin, scope, and distribution.
- **Repeatable & resumable** — runs read-only against your code; crash-safe; re-runnable.

## Why it's needed

OSS license obligations are triggered by what you **ship**, and they're easy to lose
track of across dozens of repositories, a dozen languages, and thousands of transitive
dependencies. A single missed copyleft or non-commercial license can become a liability
during a security review, a funding round, or an acquisition — and hand-maintained
spreadsheets drift the moment they're written.

## How it works — orchestration, not reinvention

RepoLens conducts mature, trusted tools and resolves their gaps intelligently:

| Job | Tool it conducts |
|-----|------------------|
| Multi-language dependency inventory (SBOM) | **Syft** |
| Deep license detection (only where needed) | **ScanCode** |
| No-clone license resolution | **public APIs** — deps.dev, package registries, GitHub |
| Mobile (Android / iOS) | **native tooling** — AboutLibraries, LicensePlist |

The "smart" part is the **ambiguity resolution**: a cheapest-source-first ladder fills
most licenses without cloning; whatever's left — or is risky — is flagged and resolved
with **anchored evidence under human approval**, never guessed.

## Usage

Each stage reads the previous stage's output from the same `--work-root`, so a normal run
is just the stages in order:

```
repolens discover --owner <OWNER> --work-root work   # find + categorize repos -> approval checklist
repolens scan      --work-root work                  # inventory the checked repos (hardened clone + Syft)
repolens resolve   --work-root work --repo-ref <REPO_REF>   # resolve licenses cheapest-source-first
repolens flag      --work-root work                  # apply policy, flag risk/unknowns -> shortlist queue
repolens shortlist --work-root work                  # settle flagged items with evidence + your approval
repolens report    --work-root work --out-dir reports # assemble the gated disclosure (md/csv/docx)
```

Concrete example — scan a few specific repos under an owner and build the report:

```
repolens discover --owner KjellKod --repos "g3log, sketch2md, repolens" --work-root work
#  edit work/repos.candidate.md — untick anything you don't want scanned
repolens scan    --work-root work
repolens resolve --work-root work --repo-ref repolens
repolens flag    --work-root work
repolens report  --work-root work --out-dir reports
```

### What the disclosure looks like

`report.main` (illustrative excerpt — same columns in Markdown, CSV, and `.docx`):

| name | spdx_id | version | source_url | origin | scope | distribution |
|------|---------|---------|------------|--------|-------|--------------|
| requests | Apache-2.0 | 2.32.3 | https://pypi.org/project/requests/ | third-party | runtime | server |
| PyYAML | MIT | 6.0.2 | https://pypi.org/project/PyYAML/ | third-party | runtime | server |

One row per library (deduplicated across repos), each carrying its resolved license,
version, a fetchable source, and `origin`/`scope`/`distribution` tags. Excluded categories
and first-party code land in `report.appendix.<category>.*` — nothing is dropped, only
routed. The full row also records evidence provenance and any coverage gaps.

You stay in control at three points: approving the repo list (`discover`), approving the
flagged shortlist (`shortlist`), and the final report is **gated** until that shortlist is
clear. The owner, repo categories, and report header are runtime inputs — never baked into
the tool. `repolens scan --work-root work --repos approved-repos.json` is an optional
override for callers that already have an approved list. **Full guide:
[docs/usage.md](docs/usage.md).**

## Local Name Hygiene

RepoLens is repo-agnostic, so no real owner, repository, or company name is ever
committed. Public CI proves the guard is wired two ways: an invented runtime sentinel
that needs no configuration, plus a tracked-tree scan whose denylist comes from the
`REPOLENS_FORBIDDEN_NAMES` GitHub Actions **variable** (never a committed literal). The
variable holds runtime-only forbidden names; it is read at scan time and never written
back into the repo. For local runs, real forbidden names stay in a private gitignored
file instead:

```json
{
  "forbidden_names": ["private-owner-or-company-name"]
}
```

Save that as `.name-hygiene.local.json` in the main checkout. The leading dot is
intentional: it keeps the private denylist out of normal directory listings, reducing
the chance that someone notices the file and force-adds it past `.gitignore`. The guard
matches case-insensitively and discovers the file from the scan root upward; when
running inside a linked git worktree, it also checks the main checkout that owns the
shared `.git` directory.

Run the check locally (after `pip install -e .` — see [Quickstart](#quickstart)). It
auto-discovers `.name-hygiene.local.json` and scans the tracked tree:

```bash
python -m repolens.security.name_hygiene                 # scan: exit 0 = clean, non-zero = a forbidden name is committed
python -m repolens.security.name_hygiene --require-denylist   # same, but fail if no denylist is configured (CI uses this)
python -m repolens.security.name_hygiene --self-test          # prove the guard fires, using an invented sentinel (no config needed)
```

Findings are reported as `sha256:` hashes, never the literal matched name, so the
denylist value never leaks into output. See
[docs/usage.md](docs/usage.md#configuration-all-untracked--local) for details.

## Contributing

Contributions are welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**. In short: keep the
orchestrate-don't-reinvent principle, honor the non-negotiable security guardrails, never
put a real owner/org/repo name in code or tests, and make sure CI (tests + security
canaries + name-hygiene) is green.

## Disclaimer

RepoLens is provided **“as is”, without warranty of any kind.** It is an aid, **not** a
substitute for legal review, and nothing it produces is legal advice. License detection
across ecosystems is inherently imperfect — results may be incomplete or wrong.

**You are solely responsible for validating its output.** The authors and contributors
accept **no liability** for any decision, disclosure, or representation made on the basis
of this tool's results. When accuracy matters, verify against the source and consult
qualified counsel.

## License

See [LICENSE](LICENSE).
