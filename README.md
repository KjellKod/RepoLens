# RepoLens

**Know exactly what open source you ship — and what it obligates you to.**

RepoLens is a **license-disclosure orchestrator**. It points best-in-class tools at every
repository under an owner, in any language, and turns the ambiguity they leave behind
into one clean, evidence-backed disclosure. It **doesn't reinvent scanners — it conducts
them**, and adds the workflow, policy, evidence, and reporting on top.

> All six pipeline stages are shipped and tested end-to-end. See
> **[docs/usage.md](docs/usage.md)** for how to run it, and
> **[docs/roadmap](docs/roadmap/rpl_README.md)** for the design, decisions, and security model.

## Install

```bash
pip install -e .                                       # install the `repolens` command (editable)
repolens --help                                        # the recommended run command and stages
python -m repolens.security.name_hygiene --self-test   # prove the name-hygiene guard works
```

`repolens --help` leads with `repolens run`, the one-command pipeline. Each stage's own
`--help` remains available for stepping through, debugging, or re-running one stage.

## Requirements

- `git` ≥ 2.45 and `python3` — the hardened clone primitive requires a current, patched git.
- `gh` (the GitHub CLI), authenticated via `gh auth login`, **or** a `GH_TOKEN` /
  `GITHUB_TOKEN` in the environment. RepoLens uses this read-only credential to discover
  repositories and to clone **private** ones; **public repositories need no credential**.
  The credential is used for the fetch only and never lands in any artifact or log — see
  [docs/usage.md](docs/usage.md#authentication--private-repos).
- `syft` is acquired and integrity-verified into a shared cache by `scan` on first use, or
  pre-seeded with `repolens bootstrap` for offline runs; RepoLens never trusts a tool
  already on the machine.
- `scancode-toolkit` is prepared only when needed for fallback license detection. Use
  `repolens bootstrap --work-root <WORK>` to create the work-root-local ScanCode wrapper
  before `resolve --retry-scancode`.

## What you get

- **A deduplicated license disclosure** — `Name | License | …` as Markdown, CSV, and a
  ready-to-share **`.docx`**, plus per-category appendices. One row per library, nothing
  silently dropped.
- **Risk flagged, not buried** — copyleft, network-copyleft, non-commercial, and
  source-available licenses surfaced against RepoLens's policy tiers.
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

For a normal run, use the single front-door command:

```
repolens run --work-root work --owner <OWNER>
```

`run` pauses inline after discovery so you can untick repos in `work/repos.candidate.md`,
then resumes after Enter. If the shortlist has open items, it pauses again until you mark
each item in `work/shortlist.md` with `[x]` approve or `[r]` reject. Rerun the same
command after an interruption; existing artifacts decide where to resume.
When `--out-dir` is omitted, reports are written under the work root at
`work/reports`. Use `--out-dir <DIR>` only when you want a different location.

For one-repo dogfood:

```
repolens run --work-root /tmp/repolens-dogfood --owner <OWNER> --repos "<REPO>"
```

For automation, pass `--yes`. It proceeds past the discover gate and tool-consent prompts,
but it **never** approves shortlist items: if any remain open, `run` exits non-zero before
writing reports.

```
repolens run --work-root work --owner <OWNER> --yes
```

For offline runs, `repolens bootstrap` pre-seeds the verified Syft cache before `run` or
`scan`. For ScanCode fallback retries, run `repolens bootstrap --work-root work` first.

To step through manually, or to re-run one stage while debugging, use the stage commands:

```
repolens discover --owner <OWNER> --repos "sentinel-alpha, sentinel-beta" --work-root work
#  edit work/repos.candidate.md — untick anything you don't want scanned
repolens bootstrap --work-root work
repolens scan    --work-root work
repolens resolve --work-root work
repolens flag    --work-root work
repolens shortlist --work-root work
repolens report  --work-root work
```

Local runtime config is JSON-only and untracked. Use `repolens config init` to create a
guided `.repolens.local.json`, `repolens config schema` to see supported keys, and
`repolens config validate ./.repolens.local.json` to check a hand-written file. Category
patterns only label repositories; use `discover.taxonomy.exclude_patterns` or exact
`dead` repos when a repository should be hard-excluded before scan. These rules apply
when `discover` writes the candidate file.

## Resolving flagged licenses — with AI help, under your approval

After `flag`, RepoLens tells you exactly what needs a human:

```
Flagged 823 components (deduped across 5 repos).
  ✓ 448 auto-cleared (policy: ALLOW — no action needed)
  ⚠ 375 need your decision  →  repolens shortlist
```

On a big estate that "375" can be thousands. RepoLens shrinks the pile in three passes:

1. **Code resolves what it can** — the resolution ladder auto-clears anything policy allows.
2. **An AI takes the first stab** — for what's left, an AI proposes a license + a
   cited source, and double-checks every BLOCK for false positives (dual-licensed,
   build-only, a license exception, not actually shipped...).
3. **You approve** — RepoLens **re-fetches and verifies every citation itself** (it never
   trusts the AI), then hands you a grouped checklist.

> The AI only *suggests*. RepoLens verifies the evidence, and nothing lands without your
> tick. A wrong AI guess simply fails verification and stays open.

### Review in bulk, override the exceptions

Items are grouped by what actually decides risk — **license × where it ships × how it's
used** — so one decision covers a whole equivalence class:

```
✓ ACCEPT-RECOMMENDED   (AI: allow, evidence verified — tick the group)
  [ ] MIT · runtime · not-distributed      42 items
  [ ] Apache-2.0 · runtime · server        71 items

⚠ NEEDS-JUDGMENT       (real copyleft in shipped code — your call)
  [ ] GPL-3.0 · client-or-mobile            6 items   → open to override any one
  [ ] AGPL-3.0 · server                     3 items

? LOW-CONFIDENCE        (AI unsure — reviewed one by one)
  [ ] UNKNOWN (unresolved)                 14 items
```

- **Accept a group** — one tick approves all its members.
- **Drill in and override** — flip the one exception inside a group of 40.
- Genuine copyleft in shipped code is **never** auto-accepted — it's always yours to decide.

## Two ways to run

**One command** — RepoLens drives the whole pipeline and pauses where you're needed:

```bash
repolens run --work-root work --owner <OWNER>
#  pauses to approve the repo list, then again at the grouped shortlist
```

**Stage by stage** — same artifacts, fully scriptable, resume anywhere:

```bash
repolens discover --owner <OWNER> --work-root work
repolens bootstrap --work-root work
repolens scan --work-root work
repolens resolve --work-root work
# after fixing ScanCode availability, retry only repos with
# unresolved:scancode_tool_unavailable:
# repolens bootstrap --work-root work
# repolens resolve --work-root work --retry-scancode
# or retry selected affected repos:
# repolens resolve --work-root work --retry-scancode --repo-ref <REPO_NAME_A> --repo-ref <REPO_NAME_B>
repolens flag --work-root work
repolens shortlist --work-root work --emit-contexts work/shortlist.contexts.json
#   ↳ run the bundled repolens skill to review every row, look up verifiable
#      evidence, and write work/shortlist.proposals.json + work/shortlist.review.md
repolens shortlist --work-root work --proposals work/shortlist.proposals.json
#   ↳ review grouped work/shortlist.md, mark remaining rows/groups [x] or [r],
#      then rerun repolens shortlist --work-root work until open_count is zero
repolens report --work-root work
```

If you retry resolution and rerun `flag`, RepoLens preserves approved/rejected decisions
for matching shortlist rows and keeps new or changed findings open.

The AI step is the same seam in both modes — and it's optional. RepoLens itself never
calls a model; it only emits the questions and verifies the answers. Drive it with the
bundled **`repolens` skill** (works in both Claude and Codex), for example:
`$repolens review every row in work/shortlist.contexts.json and write proposals plus review notes`.
The skill may look up public package metadata on RepoLens-verifiable hosts, but RepoLens
still re-fetches every cited URL and leaves final approval in `shortlist.md`.

## What the disclosure looks like

`report.main` (illustrative excerpt — same columns in Markdown, CSV, and `.docx`):

| name | spdx_id | version | source_url | origin | scope | distribution |
|------|---------|---------|------------|--------|-------|--------------|
| requests | Apache-2.0 | 2.32.3 | https://pypi.org/project/requests/ | third-party | runtime | server |
| PyYAML | MIT | 6.0.2 | https://pypi.org/project/PyYAML/ | third-party | runtime | server |

One row per library (deduplicated across repos), each carrying its resolved license,
version, a fetchable source, and `origin`/`scope`/`distribution` tags. Excluded categories
and first-party code land in `report.appendix.<category>.*` — nothing is dropped, only
routed. The full row also records evidence provenance and any coverage gaps. An empty
shortlist means there are no open shipped-license decisions; appendices can still contain
coverage gaps such as `UNKNOWN`, `missing_spdx_id`, `missing_source_url`, or
`missing_version`, and the final summary calls those out for review.

You stay in control at three points: approving the repo list (`discover`), approving the
flagged shortlist (`shortlist`), and the final report is **gated** until that shortlist is
clear. The owner and repo selection stay runtime CLI inputs; repo categories and report
header text live only in untracked JSON local config. `repolens scan --work-root work
--repos approved-repos.json` is an optional override for callers that already have an
approved list. **Full guide:
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

Run the check locally (after `pip install -e .` — see [Install](#install)). It
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
