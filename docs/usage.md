# RepoLens — usage

> `repolens run` drives all six shipped stages (`discover → scan → resolve → flag →
> shortlist → report`) with inline human pauses and resume. For a picture-first tour of how
> those stages fit together — with ASCII diagrams of the resolution ladder and the
> verify-first shortlist loop — see [docs/how-it-works.md](how-it-works.md). For the design
> behind them see [docs/roadmap](roadmap/rpl_README.md); the original build plan is archived
> under [docs/roadmap/archive](roadmap/archive/rpl_roadmap.md).

## Prerequisites

- `gh` (authenticated), `git`, `python3`.
- `pip install -e .` (or `pip install -e '.[test]'` for the test suite) — provides the
  `repolens` command and the importable package the `python -m repolens.*` commands use.
- `syft` — acquired by `scan` on first use into RepoLens's shared verified cache, or
  pre-seeded with `repolens bootstrap` for offline runs.
- `scancode-toolkit` — prepared with `repolens bootstrap --work-root <WORK>` when
  scoped fallback retries are needed.
- For mobile license enrichment (optional, auto-detected): a build toolchain
  (JDK + Gradle for Android, Xcode/SPM or a `GITHUB_TOKEN` for iOS).

## Authentication & private repos

`discover` already enumerates private repositories through authenticated `gh`. `scan`
clones them through the same hardened clone primitive, and resolves a **read-only**
GitHub credential at clone time so private repos succeed instead of failing with
`could not read Username … prompts disabled`.

**Credential resolution order** (first hit wins):

1. `gh auth token` (run `gh auth login` once),
2. the `GH_TOKEN` environment variable,
3. the `GITHUB_TOKEN` environment variable.

If none resolve, each **private** repo fails with a clear, per-repo message
(`private repo <name> needs auth: run `gh auth login` or set GH_TOKEN.`) and `scan`
exits 1 — never a bare count or `Internal error`. **Public repositories clone with no
credential** and never require auth.

**Fetch-only, then scrubbed.** When a credential is present it is injected into the
clone/fetch subprocess only, as a process-scoped `http.https://github.com/.extraheader`
git config (an `Authorization: Basic …` header). It is:

- **never in argv** (so it is not visible via `ps`),
- **never written to any git config file** (it lives only in the child process
  environment, and `GIT_CONFIG_GLOBAL=/dev/null` + `GIT_CONFIG_NOSYSTEM=1` still hold),
- **gone the moment the clone returns** — Syft and every post-clone step run with a
  clean, secret-free environment (`GH_TOKEN`/`GITHUB_TOKEN` are not copied into the tool
  env), and the token is redacted from every message, log, and artifact.

**Why this is safe.** The clone runs hooks-disabled and executes no repository code, so
the credential is only ever exposed to a fetch that cannot run anything from the
untrusted repo. RepoLens still pins and integrity-verifies its own Syft, and never injects
credentials into the clone URL (embedded `user:pass@` remotes are rejected).

**Rate limits & transients.** `gh auth token`, the discover `gh` calls, and the clone all
retry with bounded exponential backoff on HTTP 429, GitHub secondary-rate-limit, and
network-class errors. If still unrecoverable, the repo surfaces
`rate-limited after N retries - try again later` rather than hanging. Authentication and
access (403) failures are never retried — they surface their distinct, actionable message
immediately.

## Scan source snapshot for resolve

`scan` deletes its temporary checkout after Syft finishes, but it now keeps a bounded
per-repo source sidecar at:

```
<WORK>/work/<repo-ref>/source.snapshot/
```

This sidecar lets default `resolve` and `run` use ScanCode fallback without requiring
`resolve --source-root` for normal scan-produced work-roots. `resolve` chooses the source
root in this order:

1. an explicit `--source-root`, when provided;
2. the stored `source.snapshot/` sidecar from the scan stage;
3. no source root, which keeps the existing fail-closed unresolved behavior.

The sidecar is deliberately sparse. Even if Git had to materialize a full fallback
checkout, RepoLens copies only regular files whose repo-relative paths match the hardened
sparse-manifest policy used for scan cloning: package manifests, lockfiles, and nearby
license files. It does not copy `.git`, symlinks, clone credential config, token-shaped
files, arbitrary source files, or files above the per-file/per-repo snapshot caps. If no
file passes those checks, `scan` removes the sidecar for that fresh scan.

This is a retention tradeoff: the sidecar intentionally stores selected manifest and
license file contents so ScanCode can inspect package-local targets later. RepoLens does
not promise to redact arbitrary text inside retained manifests; the privacy boundary is
that retention is path-bounded, size-bounded, token-pattern guarded, and separate from any
clone URL or Git credential metadata. ScanCode still runs only through RepoLens's pinned
bootstrap proof and still scans only package-local targets derived from SBOM locations.

## Tool bootstrap

Before any scan runs, RepoLens pins and integrity-verifies its own toolchain; it never
trusts a tool already on the machine. The pins are the single source of truth in
`src/repolens/bootstrap/pins.toml`: exact versions plus sha256 digests for Syft,
ScanCode, cosign, `git`, `gh`, and the base image (by digest) — never `latest`.

Normally no manual bootstrap is needed: `repolens scan` auto-acquires RepoLens's
pinned Syft on first use, verifies it, and stores it in the shared cache:

```
${XDG_CACHE_HOME:-~/.cache}/repolens/tools/<version>-<sha256>/syft
```

The cache key is the RepoLens-owned Syft version plus the pinned release-artifact
sha256, so a pin bump naturally uses a new directory and stale versions are unused.
For offline runs, pre-seed the cache:

```
repolens bootstrap
repolens scan --work-root work --offline
```

`repolens bootstrap` by itself prepares the shared Syft cache. ScanCode fallback
is work-root-local because `resolve` validates `<WORK>/tools/scancode` against
`<WORK>/tool_versions.json` before it can retry package-local scans:

```bash
repolens bootstrap --work-root <WORK>
repolens resolve --work-root <WORK> --retry-scancode
```

Validate the manifest offline, no downloads:

```
python3 -m repolens.bootstrap --dry-run
```

`repolens bootstrap` and `scan` verify Syft **fail-closed**: they check the
release artifact's sha256, verify the cosign-signed checksums file, then cross-check that
the pinned digest matches the signed entry — all **before** the Syft executable is exposed
from the cache. `repolens bootstrap --work-root <WORK>` prepares an isolated
`<WORK>/tools/scancode-venv`, installs the exact pinned ScanCode version with binary-only
pip resolution, writes `<WORK>/tools/scancode`, and records the proof in
`<WORK>/tool_versions.json`. If Python, pip, network access, or wheel compatibility fails,
the command exits with the pip error and a fix hint instead of writing a trusted proof.

How the verification works (pins, the fail-closed gate order, ScanCode `--require-hashes`,
`tool_versions.json`) is described in
[architecture → Tool bootstrap & integrity](roadmap/rpl_architecture.md#tool-bootstrap--integrity).

### Name-hygiene gate

The offline CI workflow runs the single canonical guard,
`python -m repolens.security.name_hygiene`, which fails the build on any forbidden
owner/org/company literal. The forbidden names are **never committed**: the guard reads
them from the `REPOLENS_FORBIDDEN_NAMES` environment / GitHub Actions variable
(comma/newline-separated) or from a discovered `.name-hygiene.local.json` file.

With `--require-denylist` the guard is **fail-closed**: if no denylist is configured it
exits non-zero, so the gate can never pass vacuously. For live owner/org hygiene,
configure the one variable:

```
# GitHub -> Settings -> Secrets and variables -> Actions -> Variables
REPOLENS_FORBIDDEN_NAMES = name1,name2,...     # the real forbidden literals
```

Run it locally either way — via the env var, or with names kept in a gitignored
`.name-hygiene.local.json` that the guard auto-discovers from the repo root upward (no
env var needed):

```
# A) explicit names via env var
REPOLENS_FORBIDDEN_NAMES="name1,name2" python3 -m repolens.security.name_hygiene --require-denylist

# B) names from .name-hygiene.local.json (auto-discovered)
python3 -m repolens.security.name_hygiene                 # scan tracked tree; exit 0 = clean
python3 -m repolens.security.name_hygiene --self-test     # prove the guard fires (invented sentinel; no config)
```

Findings are emitted as non-reversible `sha256:` hashes, never the literal name, so a real
forbidden value never appears in output or CI logs.

## Configuration (all untracked / local)

RepoLens local runtime config is JSON-only. The recommended filename is the hidden
`.repolens.local.json`; an explicit `--config` path may point at another JSON filename
such as `repolens.local.json`.

Create a minimal config through guided prompts:

```bash
repolens config init
repolens config init --work-root work
repolens config init --out ./.repolens.local.json
```

Use `config init` when you want RepoLens to prompt for the common schema fields and
write the JSON for you. `--work-root` writes `<work-root>/.repolens.local.json`; `--out`
writes the exact file you name. You can then edit the generated JSON to add exclusions
such as `dead` repos or `exclude_patterns`.

Inspect and validate config before using it:

```bash
repolens config schema
repolens config schema --json
repolens config validate ./.repolens.local.json
```

Pass a local config file explicitly with the global `--config` option before the stage
name:

```bash
repolens --config ./.repolens.local.json discover --owner <OWNER> --work-root work
```

`run` also accepts `--config` after the subcommand:

```bash
repolens run --work-root work --owner <OWNER> --config ./.repolens.local.json
```

Discovery is deterministic and does not merge neighbors:

1. Explicit `--config <path>` wins and validates exactly that JSON file.
2. If the command has `--work-root`, RepoLens checks `<work-root>/.repolens.local.json`.
3. RepoLens then checks `<cwd>/.repolens.local.json`.
4. If no config exists, commands that can use defaults continue and print that no config
   was active.

TOML, YAML, and YML are not RepoLens local runtime config formats. Pipeline artifact JSON
schemas are separate from local runtime config; `shortlist.proposals.json` and
`shortlist.evidence.json` are product artifacts, not config files.

Owner and repo selection stay runtime inputs (`--owner`, `--repos`, and scan `--repos`);
do not store them in local config. Discover taxonomy, scan options, and report options
are loaded from untracked local JSON config. License policy is not runtime-configurable
through local config today. The private name-hygiene denylist is also local and
untracked, but it uses the dedicated `.name-hygiene.local.json` file shown below.

`discover.taxonomy` is the optional set of rules that assigns each discovered repository
to a category and can hard-exclude repositories that should never be scanned. Category
rules are labels for review/reporting only; they do not remove a repo from the workflow.
Use `exclude_patterns` for repo-name glob exclusions, or `dead` for exact retired/dead
repos.

Supported taxonomy keys:

| Key | Meaning |
|-----|---------|
| `default_category` | Category used when no other rule matches. If omitted, this is `uncategorized`. |
| `explicit` | Exact repo-name matches. Keys can be `owner/repo` or just `repo`; values are categories. |
| `patterns` | Repo-name glob rules, checked after `explicit`. Each rule has `glob` and `category`. These only assign categories; they do not exclude or skip scan. |
| `topics` | GitHub repository topic matches. Topics are the tags shown on a GitHub repo page and returned by `gh repo view --json repositoryTopics`. |
| `exclude_patterns` | Repo-name glob rules that hard-exclude matching repos with a visible `reason`. Use when a whole class of repos should not be scanned, such as generated or internal-only repos. These apply when `discover` writes the candidate file. |
| `dead` | Exact repo-name matches that should be hard-excluded with the configured reason. Use only for retired/dead repos. |

Matching order for categories is `explicit`, then `patterns`, then `topics`, then
`default_category`. Hard exclusions are then applied from GitHub archived status, exact
`dead` matches, and `exclude_patterns`. The authoritative parser is
[`src/repolens/discovery/taxonomy.py`](../src/repolens/discovery/taxonomy.py).

Short exclusion-focused `.repolens.local.json` example:

```json
{
  "discover": {
    "taxonomy": {
      "default_category": "PRODUCTION",
      "dead": {
        "KjellKod/legacy-cli": "retired",
        "KjellKod/old-mobile-sdk": "retired"
      },
      "exclude_patterns": [
        {
          "glob": "skipme-*",
          "reason": "out of scope for this review"
        },
        {
          "glob": "forked_to_research-*",
          "reason": "research fork; not shipped"
        }
      ]
    }
  },
  "report": {
    "selection": {
      "include": ["PRODUCTION"]
    },
    "header": {
      "org_name": "KjellKod",
      "legal_text": "Prepared for license review."
    }
  }
}
```

Example `.repolens.local.json`:

```json
{
  "discover": {
    "taxonomy": {
      "default_category": "uncategorized",
      "explicit": {
        "sentinel-owner/sentinel-alpha": "runtime-bucket"
      },
      "patterns": [
        {
          "glob": "tool-*",
          "category": "tooling-bucket"
        }
      ],
      "topics": {
        "mobile": "mobile-bucket"
      },
      "exclude_patterns": [
        {
          "glob": "internal-*",
          "reason": "internal-only repo"
        }
      ],
      "dead": {
        "sentinel-retired": "retired by local approval"
      }
    }
  },
  "scan": {
    "exclude_paths": ["generated-fixtures/"],
    "clone_timeout_seconds": 300,
    "syft": {
      "catalogers": ["python-package-cataloger"]
    }
  },
  "report": {
    "selection": {
      "include": ["runtime-bucket", "mobile-bucket"]
    },
    "header": {
      "org_name": "Runtime Organization Name",
      "legal_text": "Runtime legal review text."
    }
  }
}
```

The CI name-hygiene step uses only an invented sentinel token, proving the guard is
wired without publishing private names. For local or deployment-specific checks, put
private names in a gitignored `.name-hygiene.local.json` file:

```json
{
  "forbidden_names": ["private-owner-or-company-name"]
}
```

Matching is case-insensitive. The leading dot is intentional: it keeps the private
denylist out of normal directory listings and lowers the chance that someone force-adds
it past `.gitignore`. The file is discovered from the scan root upward, and when the
command runs from a linked git worktree it also checks the main checkout that owns the
shared `.git` directory. Prefer placing the file in the main checkout, e.g.
`~/ws/extra/RepoLens/.name-hygiene.local.json`, so every worktree uses the same private
denylist.

## Recommended: `repolens run`

Use `run` for the normal end-to-end workflow:

```bash
repolens run --work-root work --owner <OWNER>
```

When `--out-dir` is omitted, `run` writes reports to `<work-root>/reports`. Use
`--out-dir <DIR>` only when you want the reports somewhere else.

For one-repo dogfood:

```bash
repolens run --work-root /tmp/repolens-dogfood --owner <OWNER> --repos "<REPO>"
```

What happens:

1. `discover` writes `work/discovered.json` and `work/repos.candidate.md`.
2. `run` pauses: review `work/repos.candidate.md`, untick repos to exclude, then press Enter.
3. `scan` inventories checked repos with RepoLens's verified Syft.
4. `resolve` runs for every successfully scanned repo; you do not call `--repo-ref` manually.
5. `flag` writes `inventory.json`, `shortlist.json`, and `shortlist.md`.
6. If the shortlist has open items, `run` writes `work/shortlist.contexts.json`, tells you
   how to run deterministic `shortlist research` or an external assistant pass, ingests
   existing `work/shortlist.proposals.json` and `work/shortlist.evidence.json` if present,
   and renders grouped `work/shortlist.md`.
7. Mark available group checkboxes or item rows in `work/shortlist.md` with `[x]` approve
   or `[r]` reject, then press Enter. Item ticks override group ticks. `run` repeats until
   `open_count == 0`.
8. `report` writes `report.main.{md,csv,html}` and
   `report.presentation.{md,csv,html}` plus optional `.docx` files and appendices under
   `<work-root>/reports` unless `--out-dir` overrides it.

Resume is artifact-based. Rerun the same command after Ctrl-C, a closed terminal, or a crash:
existing SBOMs, `resolved.ndjson`, `inventory.json`, a clear shortlist, and report files decide
where the pipeline resumes. Once scan artifacts exist, `run` does not regenerate
`repos.candidate.md`, so human unticks are preserved.

For inspection after every stage, add `--step` in an interactive terminal:

```bash
repolens run --work-root work --owner <OWNER> --step
```

For automation, add `--yes`:

```bash
repolens run --work-root work --owner <OWNER> --yes
```

`--yes` never approves the shortlist and never runs an AI proposal pass. In
non-interactive mode, open shortlist items produce a deterministic non-zero exit, emit
`work/shortlist.contexts.json`, ingest existing `work/shortlist.proposals.json` and
`work/shortlist.evidence.json` if already present, print copy-pasteable artifact
instructions once, and write no report until a human clears `shortlist.md`.

The final `run` summary separates resume skips from real failures and names the exact
report directory. Review `report.main.html`, `report.main.md`, `report.main.csv`,
`report.presentation.html`, `report.presentation.md`, and `report.presentation.csv`
(and their `.docx` files when present), review every
`report.appendix.<label>.{md,csv}`, and double-check any reported coverage gaps. An empty
shortlist means there are no open shipped-license decisions; it does not mean appendix
rows have complete SPDX, source URL, or version coverage.

If you already have a complete work root with resolved artifacts and a clear shortlist,
you do not need to rerun the full pipeline just to create or refresh presentation
artifacts. Run only the final report stage:

```bash
repolens report --work-root <WORK> --out-dir <REPORTS>
```

Run the full `repolens run` pipeline again only when earlier stages are stale or
incomplete, or when the shortlist still has open items.

`run` continues past per-repo scan or resolve failures when other repos succeeded. It lists the
failed repos in the final summary, writes reports for successfully resolved repos, and exits
non-zero overall so automation can surface the partial failure.

## CLI stages

`repolens --help` is the primary health check for the shipped CLI entry point. `run` is the
recommended route. The stage subcommands remain available for stepping through, debugging,
or re-running one stage; `discover`, `scan`, `resolve`, `flag`, `shortlist`, `report`,
and standalone `release` all run real orchestration.

Exit codes are:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings remain open, or a sanitized unexpected internal error occurred |
| `2` | Usage, argument, or config input error |

## Supported ecosystem coverage

RepoLens inventories dependencies through Syft and resolves licenses through
unauthenticated public APIs where a supported package identity exists. SwiftPM and
CocoaPods also have default-safe metadata-only resolution: RepoLens reads stored
`Package.resolved` / `Podfile.lock` metadata and verifies exact public metadata evidence
without running Swift, Xcode, CocoaPods, dependency checkout, or native mobile tooling.

<!-- repolens-supported-ecosystems:start -->
| ecosystem | Syft cataloged | RepoLens API/license resolution | notes |
|-----------|----------------|----------------------------------|-------|
| cargo | yes | yes | Rust crates resolve through deps.dev/Crates. |
| cocoapods | yes | yes | Metadata-only from CocoaPods trunk exact specs; native tooling stays opt-in. |
| githubactions | yes | no | Build/CI inventory; excluded from shipped main. |
| go-module | yes | yes | Go modules resolve through deps.dev/proxy data. |
| maven | yes | yes | Maven purls include Gradle-originated dependencies. |
| npm | yes | yes | npm packages resolve through deps.dev/npm registry data. |
| nuget | yes | yes | NuGet packages resolve through deps.dev. |
| pypi | yes | yes | Python packages include Syft and pyproject facts. |
| rubygems | yes | yes | Ruby gems resolve through deps.dev. |
| swift | yes | yes | Metadata-only from Package.resolved GitHub pins; native tooling stays opt-in. |
<!-- repolens-supported-ecosystems:end -->

GitHub Actions package-url records are retained in inventory as `scope: build` and
`distribution: not-distributed`. They route to the `build-ci` appendix and do not create
shipped-license gaps in `report.main.{md,csv,html}` or optional `.docx`.

## Step-it-yourself pipeline

```
repolens discover  --owner <OWNER>   # enumerate + categorize repos -> approval checklist
repolens bootstrap --work-root work  # prepare work-root-local ScanCode fallback tools
repolens scan      --work-root work  # first use verifies Syft cache, then writes SBOMs
repolens resolve --work-root work    # license resolution for scanned repo SBOMs
repolens flag      --work-root work  # apply policy, flag risk/unknowns -> shortlist queue
repolens shortlist --work-root work   # settle checked decisions; decided_by defaults
                                      # to the logged-in OS user; --identity overrides it
repolens shortlist --work-root work --emit-contexts work/shortlist.contexts.json
                                      # emit model-free external proposal contexts
repolens shortlist research --work-root work \
  --contexts work/shortlist.contexts.json \
  --proposals work/shortlist.proposals.json \
  --evidence work/shortlist.evidence.json \
  --review work/shortlist.review.md
                                      # deterministic model-free research
repolens shortlist --work-root work \
  --proposals work/shortlist.proposals.json \
  --evidence work/shortlist.evidence.json
                                      # ingest verified proposals and browser evidence
repolens report --work-root <WORK>
                                      # assemble gated main, presentation, docx, and appendix reports
repolens release --work-root <WORK> \
  --artifact dist/worker.js --target js-bundle
                                      # evaluate release policy and write release artifacts
```

Discovery (you approve the repo list), the `shortlist` approval gate, and the final report
are the shipped human checkpoints. The shipped scanner and resolver are read-only against
your code and resumable after an interruption. The per-stage sections below follow this order.

## `discover` — enumerate + categorize repos → approval checklist

`discover` is the first shipped pipeline stage. It invokes `gh repo list` for the
runtime owner you provide, or `gh repo view` for an explicit comma-separated repo-name
list under that owner. It categorizes the returned repositories from local taxonomy
config and writes both the structured stage artifact and the human approval file:

```bash
repolens discover --owner <OWNER> --work-root work
repolens discover --owner <OWNER> --repos "sentinel-alpha, sentinel-beta" --work-root work
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `--owner <OWNER>` | Runtime owner/org passed to `gh`; never commit it. |
| `--repos "<NAME>, <NAME>"` | Optional comma-separated repo name list under `--owner`; spaces around commas are fine. This is a name list, not the JSON file used by `scan --repos`. Cross-owner slugs containing `/` are rejected because `discovered.json` records one owner. |
| `--work-root <DIR>` | Output directory for `discovered.json` and `repos.candidate.md`; default `work`. |
| `--limit <N>` | Maximum repositories requested from `gh repo list`; default `1000`, max `5000`. Ignored when `--repos` is supplied. |
| `--force` | Overwrite an existing `repos.candidate.md` approval file. |

Taxonomy is optional and lives only in untracked local config. Unmatched repositories use
`uncategorized` unless you set `default_category`. `explicit`, `patterns`, and `topics`
classify only; they never exclude a repository from later scanning. Use
`exclude_patterns` for repo-name glob hard exclusions such as `internal-*`, and use
`dead` for exact retired/dead repos. GitHub-archived repositories are also hard-excluded.
Every hard exclusion writes a visible reason.
These config rules apply when `discover` writes `discovered.json` and
`repos.candidate.md`; if that approval file already exists, rerun discover with `--force`
to regenerate it, or manually untick rows you do not want scanned.

Discovery artifacts use deterministic review order: candidates first, then hard
exclusions. Within each group, repositories are sorted by category, then repo name, then
full owner/name, case-insensitively. This applies to both `discovered.json` and
`repos.candidate.md`, including when `discover --repos` receives names in a different
order.

To inspect only the hard exclusions and their recorded reasons:

```bash
jq -r '.repositories[] | select(.hard_excluded) | [.name_with_owner, .exclusion_reason] | @tsv' <WORK_ROOT>/discovered.json
```

To inspect only the candidate repositories eligible for approval:

```bash
jq -r '.repositories[] | select(.hard_excluded == false) | [.name_with_owner, .category] | @tsv' <WORK_ROOT>/discovered.json
```

`repos.candidate.md` is a human-edited checkpoint. A second `discover` run refuses to
overwrite it unless you pass `--force`, so existing approval checkboxes are not silently
discarded. Candidate repositories default to checked, so every checked repo will be
scanned. Untick repos only when you deliberately want to exclude them, and consider
adding a note such as `— excluded: <reason>`. Use `--force` only when you intentionally
want a fresh approval file; it also warns on stderr that the prior checkbox edits are
being discarded. After a successful run, the CLI prints a concrete `repolens scan`
command using the same `--work-root`.

```json
{
  "discover": {
    "taxonomy": {
      "default_category": "default-bucket",
      "explicit": {
        "sentinel-owner/sentinel-alpha": "runtime-bucket"
      },
      "patterns": [
        {"glob": "tool-*", "category": "tooling-bucket"}
      ],
      "topics": {
        "mobile": "mobile-bucket"
      },
      "exclude_patterns": [
        {"glob": "internal-*", "reason": "internal-only repo"}
      ],
      "dead": {
        "sentinel-retired": "retired by local approval"
      }
    }
  }
}
```

## `scan` — hardened clone + Syft → per-repo SBOM

`repolens scan` consumes the checked repositories from discover's reviewed artifacts and
produces one SBOM per repo. It does **not** re-run discovery and is independently
rerunnable.

```
repolens scan --work-root work [--timeout SECONDS] [--clone-timeout SECONDS] [--offline] [--quiet]
repolens scan --work-root work --repos approved-repos.json [--timeout SECONDS] [--clone-timeout SECONDS] [--quiet]
```

- `--work-root` — the pipeline work root. Per-repo artifacts land under
  `work/work/<repo_ref>/` (`sbom.syft.json` + `scan.status.json`). By default, scan reads
  `<work-root>/discovered.json` and `<work-root>/repos.candidate.md`. The verified Syft
  binary comes from RepoLens's shared cache, not from the work root.
- `--repos` — optional override JSON for callers that already have approved repo specs. When
  supplied, it wins over discover artifacts. The owner/repo are **runtime inputs**, never
  committed:

  ```json
  { "repos": [ { "repo_ref": "<repo>", "clone_url": "https://<host>/<owner>/<repo>.git" } ] }
  ```
- `--timeout` — per-repo wall-clock budget for the Syft inventory scan.
- `--clone-timeout` — per-repo wall-clock budget for hardened Git clone. Defaults to 300
  seconds and can also be set in local config as `scan.clone_timeout_seconds`.
- `--offline` — require the verified shared cache. Scan never downloads or prompts; if the
  cache is absent or stale, it exits with a usage error and tells you to run
  `repolens bootstrap`.
- `--quiet` — suppress per-repo progress and the final scan summary. By default, scan writes
  progress to stderr so stdout stays clean for automation.

For the default bridge, checked rows in `repos.candidate.md` are joined back to
`discovered.json`. Unticked rows and hard exclusions are skipped. Each checked repo's
`repo_ref` is the discovered `name`, and the clone URL is derived as
`https://github.com/<name_with_owner>.git`, then validated through the same HTTPS,
no-credentials checks used by explicit `--repos` input.

For each repo, `scan` clones through the hardened clone primitive using partial clone
(`--filter=blob:none --no-checkout`) plus sparse checkout for supported dependency
manifests, lockfiles, `.gitmodules`, and license/copying files. If the initial remote
clearly does not support partial-clone filtering, RepoLens falls back to the same hardened
full shallow clone path; sparse-checkout, checkout, auth, access, rate-limit, timeout, and
security failures do not fall back. The clone remains depth-1, no tags, single branch, no
recursive submodules, hooks/symlinks/file-protocol disabled, prompts off, and system git
config off. RepoLens then runs the pinned Syft over the cloned path within the Syft
`--timeout`, maps Syft's output onto the frozen `sbom.schema.json`, and persists it through
the store (token-redacted, schema-validated). It also reads static root `pyproject.toml`
project and optional dependencies without executing repository code. A completed SBOM lets
a rerun **skip** that repo. Every successful SBOM is persisted even within a mixed run; if
any repo fails the process exits `1` after the rest finish. Token redaction is applied to
both the SBOM and `scan.status.json` before they are written.

Large monorepos often repeat the same registry dependency graph in multiple lockfiles.
`scan` keeps Syft's full extraction pass and source snapshot intact, then automatically
collapses exact duplicate registry dependency artifacts before persisting RepoLens's
`sbom.syft.json`. Collapse requires the same ecosystem/type, normalized package identity,
version, purl, and declared-license tuple, and all locations must be dependency graph
manifest or lockfile paths. The persisted artifact carries deterministic merged locations
and `repolens_occurrence_count` when more than one occurrence was collapsed. Package-local
or source-like locations stay separate so location-sensitive ScanCode fallback can still
inspect the right target later. When this optimization applies, non-quiet scan progress
shows the persisted dependency count and the raw Syft artifact count.

Default scan exclusions remove artifacts located only under clearly non-shipped paths:
`tests/fixtures/`, `test/fixtures/`, `tests/bootstrap/fixtures/`, and `.git/`.
Top-level `fixtures/` and `vendor/` are not excluded by default. A local config can replace
the default list when a repository has local non-shipped sample or generated paths.
Use `scan.exclude_paths` for generated, vendor, build, or fixture directories that should
not be scanned at all; it is not needed for repeated lockfile dependency graphs because
that dedupe happens automatically after Syft extraction:

```json
{
  "scan": {
    "exclude_paths": ["generated-fixtures/"],
    "clone_timeout_seconds": 300
  }
}
```

When local config restricts Syft catalogers, RepoLens preserves that restriction but also
adds Gradle, CocoaPods, and Swift Package Manager catalogers so mobile manifests remain
cataloged:

```json
{
  "scan": {
    "syft": {
      "catalogers": ["python-package-cataloger"]
    }
  }
}
```

During a multi-repo run, stderr shows one line when each approved repo starts, one outcome line
when it finishes or is skipped, and a final `Done:` count. Non-TTY stderr gets plain appended
lines; TTY stderr may rewrite the in-progress line. stdout remains empty.

`scan` orchestrates external tools only — it never reimplements SBOM generation or license
detection. On a cache miss it acquires only RepoLens's pinned Syft and verifies it through
the existing bootstrap gates (checksum → signature → provenance, all before the binary is
exposed); the scanner then consumes that already-verified binary.

`scan` runs clone + Syft **in-process** with a hardened git environment, an ephemeral
per-repo workdir, separate clone and Syft wall-clock timeouts, and no secrets in the child
environment; no untrusted repo code executes (clone hooks/symlinks/file-protocol disabled,
Syft is a static inventory). Full container/VM runner-layer isolation is a deliberate scope
boundary layered at the runner — see
[architecture → Scan execution model & sandbox scope](roadmap/rpl_architecture.md#scan-execution-model--sandbox-scope).

## `resolve` — license ladder → `resolved.ndjson`

For the resolution stage, scan must already have written SBOMs under
`<WORK>/work/<repo_ref>/sbom.syft.json`:

```bash
repolens resolve --work-root <WORK>
```

By default, when `discovered.json` and `repos.candidate.md` exist, `resolve`
uses the checked repo list and resolves the checked repos that already have scan
SBOMs. Checked repos without SBOMs are skipped with a warning so stale approval
files do not block available scan output. If discover artifacts are absent,
mismatched, or none of the checked repos have SBOMs, `resolve` falls back to
every available SBOM under `<WORK>/work/`. Use one or more `--repo-ref <REPO_REF>` flags
only when you intentionally want to resolve selected repo artifact directories.

That normal form preserves the API-layer behavior: Syft-declared licenses and
verified metadata API evidence are written to `resolved.ndjson`; unresolved records
remain schema-valid.

Within each run, `resolve` reuses declared-license normalization and verified API
resolution outcomes for duplicate package/version/purl/declared-license rows that remain
in older or non-deduped SBOMs. Each output row is still rebuilt from the current SBOM
artifact, so repo, purl, version, first-party tags, build/runtime tags, and declared-version
markers remain specific to that occurrence. ScanCode remains source-location-sensitive:
RepoLens does not broadly reuse ScanCode outcomes across different package locations or
source roots. When duplicate rows are reused, non-quiet `resolve` and `run` output reports
the cached resolution count.

P3b adds an optional source checkout boundary for mobile marker detection and scoped
ScanCode fallback:

```bash
repolens resolve \
  --work-root <WORK> \
  --repo-ref <REPO_REF> \
  --source-root fixtures/source/sentinel-mobile
```

`--source-root` is read-only input and currently requires `--repo-ref` when more
than one scanned repo exists, because one source checkout can only describe one
repository. It lets `resolve` detect mobile markers and derive package-local
ScanCode targets from SBOM `locations`. ScanCode is invoked only for dependencies
still unresolved by earlier layers, and target selection rejects broad repository-root
scans and paths outside the source root. If the bootstrap-produced ScanCode executable is
unavailable during normal resolve, affected packages stay unresolved instead of failing
the run.

Before retrying ScanCode, prepare the work-root-local fallback tool:

```bash
repolens bootstrap --work-root <WORK>
```

Then retry only the checked repos whose existing
`resolved.ndjson` contains `unresolved:scancode_tool_unavailable`:

```bash
repolens resolve --work-root <WORK> --retry-scancode
repolens flag --work-root <WORK>
```

This reuses the same repo list and existing SBOM/source snapshot artifacts, rewrites
`resolved.ndjson` only for affected repos, and leaves normal `run` resume behavior
unchanged. Add one or more `--repo-ref <REPO_REF>` flags to narrow the retry to selected
repos:

```bash
repolens resolve --work-root <WORK> --retry-scancode --repo-ref <REPO_NAME>
repolens resolve --work-root <WORK> --retry-scancode --repo-ref <REPO_NAME_A> --repo-ref <REPO_NAME_B>
```

Native mobile enrichment is opt-in and remains off by default even when mobile markers
are present:

```bash
repolens resolve \
  --work-root <WORK> \
  --repo-ref <REPO_REF> \
  --source-root fixtures/source/sentinel-mobile \
  --enable-mobile-native
```

The native mobile path is separate from default metadata-only mobile resolution and runs
only through the sandbox boundary. Missing mobile toolchains or a missing sandbox backend
lower affected packages to unresolved mobile evidence, such as
`unresolved:mobile_sandbox_unavailable`, without hard-failing the stage.

The command writes `<WORK>/work/<REPO_REF>/resolved.ndjson` with SPDX-normalized
license records or schema-valid unresolved records when evidence cannot be verified.

## `flag` — tag, apply policy, dedup → inventory + shortlist

`repolens flag --work-root work` reads every `work/<repo>/resolved.ndjson` from `resolve`,
tags each component (`origin` / `scope` / `distribution`), applies the license policy
tiers, deduplicates components across repositories, and writes the inventory plus the
review queue:

```
repolens flag --work-root work
```

- `flag` owns its own resolved-record collector. A missing or empty `work/` is treated as
  "no records → empty artifacts → exit `0`", so the stage is safe to run early.
- Each deduplicated component is assigned a `policy_tier`: `ALLOW`, `REVIEW`, `BLOCK`, or
  `UNKNOWN`. `ALLOW` components produce no review item; `REVIEW`, `BLOCK`, and `UNKNOWN`
  components become **open** items in the shortlist, each with a stated reason — e.g. a
  planted AGPL dependency lands in the `BLOCK` queue and a dependency with no detectable
  license lands in `UNKNOWN`.

Outputs land under `--work-root`:

- `inventory.json` — the complete, deduplicated, tagged component dataset.
- `shortlist.json` + `shortlist.md` — the review queue `shortlist` consumes; its
  `open_count` is what gates the final report.
- Non-quiet output includes presence counts and a not-scanned count so the operator can
  see delivered, installed-review, monitor, and unknown delivery buckets before report.

The default policy tiers live in [license-policy.md](roadmap/rpl_license-policy.md). They
are not runtime-configurable through local config today.

### Advanced: changing default policy tiers

The shipped policy table is
`src/repolens/policy/data/license-policy.default.json`. It maps normalized SPDX IDs and
known aliases into `ALLOW`, `REVIEW`, or `BLOCK`. `flag` is the stage that applies this
file: `ALLOW` rows go straight to `inventory.json` and do **not** receive a
`shortlist.md` checkbox, while `REVIEW`, `BLOCK`, and `UNKNOWN` rows become shortlist
items that can be approved or rejected by a human.

Use this when the organization makes a standing policy decision such as "treat
`Unlicense` as reject/block" or "surface a formerly allowed license for legal review":

1. Edit `src/repolens/policy/data/license-policy.default.json` by moving the SPDX ID from
   `ALLOW` to `REVIEW` or `BLOCK`, and update caveats/aliases only when the normalized
   license text should change too.
2. Run the policy/unit tests before using the policy on a work root:

   ```bash
   PYTHONPATH=src python3 -m pytest tests/policy tests/unit/test_schema_validation.py
   ```

3. Back up the current work-root decision artifacts if humans have already been reviewing
   them:

   ```bash
   mkdir -p <WORK>/.policy-backup
   cp <WORK>/shortlist.json <WORK>/shortlist.md <WORK>/shortlist.evidence.json \
      <WORK>/shortlist.proposals.json <WORK>/shortlist.review.md <WORK>/.policy-backup/ 2>/dev/null || true
   ```

4. Rebuild policy output:

   ```bash
   repolens flag --work-root <WORK>
   repolens shortlist --work-root <WORK>
   ```

Rerunning `flag` does not rerun scan or resolve, and it does not delete
`work/<repo>/resolved.ndjson`. It rebuilds `inventory.json`, `shortlist.json`, and
`shortlist.md` from the resolved records. Before rebuilding, `flag` ingests pending
checkboxes from the existing `shortlist.md` and carries forward matching
approved/rejected decisions by exact `component_ref`, so settled rows should not be
silently reopened. If a previously approved item moves from monitored, unknown, or
not-scanned delivery state to delivered, it reopens with a `reopened:` note. New or
materially changed rows stay open. Rich research metadata and proposal annotations are
separate artifacts; if you need them after a policy rebuild,
rerun or reingest the relevant `shortlist.evidence.json` and `shortlist.proposals.json`.

Paid/vendor software is a separate decision from SPDX policy. A commercial SDK can still
declare an open-source license for bundled notices, and `flag` will treat that license
according to the policy table. If the organization pays for a component and decides it
must not be submitted as OSS, the row must be rejected in the shortlist. If it is already
`ALLOW`, it will not have a checkbox until the policy or a supported override surfaces it
as a `REVIEW`/`BLOCK` row and `flag` is rerun.

## `shortlist` — artifact proposals + grouped human approval

`repolens shortlist --work-root work` reads the `shortlist.json`
and `shortlist.md` that `flag` produced, renders a grouped review surface, and settles only
the items a human approved or rejected:

`shortlist.md` is grouped first by dependency presence, then by the existing review tiers:

1. `DELIVERED / SHIPPED - ACTION REQUIRED`
2. `INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW`
3. `LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR`
4. `DELIVERY ARTIFACT NOT SCANNED - UNKNOWN`

Monitor and unknown rows are visible review rows, not suppressions. Their row copy shows
delivery state, install state, relation, dependency path when known, and platform match.

If you later retry resolution and rerun `flag`, RepoLens first ingests any pending
`shortlist.md` checkbox decisions and then preserves approved/rejected decisions for
matching `component_ref` rows. New or materially changed findings stay open, so a ScanCode
or resolver retry should not erase completed human review while still forcing review of
different evidence.

1. **Ingest human decisions.** Any item whose checkbox you ticked in `shortlist.md`
   (`[x]` approve, `[r]` reject) is recorded with `status`, `decided_by`, a UTC
   `decided_at`, and `decided_via`. By default, `decided_by` is the logged-in OS user
   (`getpass.getuser()`); pass `--identity <REVIEWER>` only to override that label. Group
   ticks apply to every covered member; item `rpl:ref` ticks override group `rpl:group`
   ticks.
2. **Pre-screen → route.** Each still-open item's untrusted text (LICENSE / README /
   description / evidence) is capped, NFC-normalized, and screened for injection markers
   (role-play, output-override, container-escape, imperative, directional Unicode). Use
   `--emit-contexts` to write these request-shaped contexts to a JSON artifact. RepoLens
   does not call a model.
3. **Research artifacts.** Run deterministic model-free research or create artifacts
   outside RepoLens, then pass them back with
   `--proposals work/shortlist.proposals.json --evidence work/shortlist.evidence.json`.
   A proposal has
   `component_ref`, `spdx_id`, `evidence_url`, `evidence_anchor`, `disposition`,
   `confidence`, `rationale`, and `sanity_check`; an abstention uses
   `component_ref`, `abstain: true`, and `reason`. RepoLens validates the artifact shape
   with `src/repolens/data/schemas/shortlist_proposals.schema.json` before parsing
   proposals fail-closed.
   Evidence rows are validated with
   `src/repolens/data/schemas/shortlist_evidence.schema.json`, keyed by stable context
   identity, and outcome-specific: pending verifier support requires direct HTTP(S)
   browser evidence with short labels, no-public-evidence requires lookup attempts,
   conflicts require all disagreeing URLs, and legal/vendor review requires a clear note.
   The bundled `$repolens` skill is the intended assistant workflow here: ask it to review
   every row in `work/shortlist.contexts.json`, look up public package metadata on
   RepoLens-verifiable hosts or browser evidence, and write `work/shortlist.proposals.json`,
   `work/shortlist.evidence.json`, and `work/shortlist.review.md`. The review notes
   include one row per context row, outcome counts, links or lookup trails, and conflict
   or legal/vendor wording.
4. **Verify, don't trust.** Supported proposal citations are re-fetched through the
   SSRF-guarded, allowlisted HTTP client and checked for an exact SPDX anchor. Bad,
   malicious, off-allowlist, mismatched, low-confidence, or abstained proposals leave the
   item open. Machine-verification failure does not erase researched browser evidence.
   `disposition`, `confidence`, `rationale`, and `sanity_check` are metadata only.

The grouped Markdown tiers are:

- `ACCEPT-RECOMMENDED`: all members have verified `allow` candidates and the class is
  low-risk (`not-distributed` or permissive family). A group checkbox is available.
- `NEEDS-JUDGMENT`: genuine block/review or mixed-risk cases. A group checkbox is
  available, with drill-in per-item rows for exceptions.
- `LOW-CONFIDENCE / CONFLICT`: abstentions, conflicts, verification failures, invalid
  proposals, or low-confidence items. Per-item decisions only.

`shortlist` exits `0` only when no item remains open and `1` (findings open) otherwise, so
it gates the downstream report.

When `shortlist` exits with open items, the console prints this same workflow:

```bash
repolens shortlist --work-root <WORK> --emit-contexts <WORK>/shortlist.contexts.json
repolens shortlist research --work-root <WORK> \
  --contexts <WORK>/shortlist.contexts.json \
  --proposals <WORK>/shortlist.proposals.json \
  --evidence <WORK>/shortlist.evidence.json \
  --review <WORK>/shortlist.review.md
repolens shortlist --work-root <WORK> \
  --proposals <WORK>/shortlist.proposals.json \
  --evidence <WORK>/shortlist.evidence.json
```

The same console output includes presence counts plus the not-scanned count. If any
not-scanned findings remain, the final run summary points to report review and calls out a
release policy review before publishing final artifacts; it does not prescribe disclosure
actions.

If any open rows came from `unresolved:scancode_tool_unavailable`, the console also prints
the deterministic retry path first:

```bash
repolens bootstrap --work-root <WORK>
repolens resolve --work-root <WORK> --retry-scancode
repolens resolve --work-root <WORK> --retry-scancode --repo-ref <REPO_NAME>
repolens resolve --work-root <WORK> --retry-scancode --repo-ref <REPO_NAME_A> --repo-ref <REPO_NAME_B>
repolens flag --work-root <WORK>
```

Use the all-repos form when you can afford it, or the repeated `--repo-ref` form to retry
only selected repos before rerunning `flag`. `flag` preserves matching approved/rejected
shortlist decisions when it rebuilds the shortlist, and keeps new or materially changed
findings open.

Other ScanCode-looking buckets have different meanings:
`unresolved:scancode_no_target` means RepoLens did not find a safe package-local source
target to scan, often because the SBOM points only at a lockfile, and
`unresolved:no_supported_catalog_license_api` means exact supported public metadata was
not found for that package identity/version. `--retry-scancode` does not change either
condition.

Use this when the open rows include `UNKNOWN`, abstained, low-confidence, or stale evidence
items that public package metadata might clarify. After proposal ingestion, review
`shortlist.md` and mark remaining groups or rows with `[x]` to accept or `[r]` to reject,
then rerun `repolens shortlist --work-root <WORK>`.

## `report` — gated main and presentation disclosure + appendices

`report` reads resolved occurrences, discovered repository categories when available, and
local runtime report config. If `<WORK>/shortlist.json` exists with `open_count > 0` or
any item whose `status` is `open`, the command exits with findings-open status and writes
no report artifacts. A missing shortlist does not block assembly.

When `--out-dir` is omitted, report writes to `<WORK>/reports`. The finish summary lists
the resolved report directory, main row count, appendix row counts by label, presence
counts, not-scanned count, and coverage gaps worth human review. Review
`report.main.html`/`.md`/`.csv`/`.docx` when present,
review `report.presentation.html`/`.md`/`.csv`/`.docx` when present, review appendices
especially when `build-ci` rows have `UNKNOWN`, `missing_spdx_id`, `missing_source_url`,
or `missing_version`, and generate the docx files later by adding `report.header` config
or rerunning report interactively if the summary says docx was skipped.

The `report.main.{md,csv,html}`, `report.presentation.{md,csv,html}`, and appendix data
always render — they need no header config and never hard-fail. The main and presentation
HTML reports are self-contained, wide on screen, and use letter-landscape print CSS. The
docx cover is **optional** and resolved as follows:

- **`report.header` config present** → the docx is generated from it (the polished,
  final docx). This is the path for a shareable artifact:

  ```json
  {
    "report": {
      "selection": {
        "include": ["runtime", "customer-facing"]
      },
      "header": {
        "org_name": "Runtime Organization Name",
        "legal_text": "Runtime legal review text."
      }
    }
  }
  ```

- **Absent + interactive (a TTY)** → you are prompted inline for the cover text; press
  Enter to accept each default, and the docx is rendered in the same run (no re-run):

  ```text
  No report header configured. Let's add one for the shareable .docx
  (press Enter to accept the default; this only affects the docx cover, not the data).
    Organization name [<owner>]:
    Legal / disclaimer line [Generated by RepoLens — not legal advice; verify before distribution.]:
  ```

  In `repolens run` the organization-name default is the `--owner` value; standalone
  `repolens report` has no owner, so it just asks. The legal line always defaults to the
  generic disclaimer above.

- **Absent + non-interactive (`--yes` or no TTY)** → the docx is skipped (no invented
  header), the md/csv/html data and appendices still render, and one notice is printed
  (exit `0`):

  ```text
  docx files skipped (no report.header); md/csv/html contain all the data — add report.header config or run interactively to generate it.
  ```

A `report.header` that is *present but malformed* (empty `org_name`/`legal_text`) still
errors — only the *absent* case is relaxed.

Rejected shortlist items are excluded from `report.main`; approved shortlist items are
included, even if they still carry coverage gaps such as `UNKNOWN` SPDX.

Before publishing final presentation artifacts, you can review complex disclosure
licenses without rerunning scan or resolve:

```bash
repolens report review --work-root <WORK>
```

This writes `<WORK>/report.review.md` and `<WORK>/report.review.json` for final main-report
rows whose detected SPDX expression is compound or otherwise review-worthy, including
policy-allowed `OR` expressions. Edit `report.review.md` by checking exactly one disclosure
choice per item, optionally add a short disclosure note, then rerun the same command to
ingest the decisions. Open shortlist items still block matching disclosure choices from
becoming authoritative.

The top of `report.review.md` also contains editable `Presentation Header:` and
`Presentation preamble text:` fields. On first generation, RepoLens seeds them from
`report.header.org_name` and `report.header.legal_text` when that config is present;
otherwise it uses the built-in presentation defaults. Edit those fields in
`report.review.md`, rerun `repolens report review`, and the values are stored in
`report.review.json` for the next report build.

After review, rerun only the report step:

```bash
repolens report --work-root <WORK>
```

Approved review choices flow into `report.presentation.{md,csv,html,docx}` as the
disclosure license and note while the detected SPDX expression stays visible. The main
report keeps its raw SPDX column unchanged.

`report.selection.include` is optional. When it is omitted, every observed third-party
category is selected into `report.main`. When present, third-party occurrences in included
categories go to `report.main.{md,csv,html}`, `report.presentation.{md,csv,html}`, and
optional `.docx`; excluded third-party categories go to `report.appendix.<category>.{md,csv}`. First-party occurrences always go to
`report.appendix.first-party.{md,csv}`. Build/CI-only occurrences tagged as
`scope: build` and `distribution: not-distributed` always go to
`report.appendix.build-ci.{md,csv}` instead of the shipped main report.

The main markdown, CSV, HTML, and DOCX include `delivery` and `install` columns. Explicit
lockfile-only, optional, or unscanned delivery rows route to
`report.appendix.not-currently-delivered.{md,csv}` after first-party and build/CI routing;
the appendix preamble explains that these rows are monitored because future platform,
feature, dependency, or deployment changes could install or include them later. The
presentation report includes a matching presence note column.

The presentation report is a
sibling view of the same gated main row set: Markdown, HTML, and DOCX group by exact SPDX
expression/value, while CSV stays flat and sorted by SPDX, name, then version. Presentation
rows include a brief `description` when the resolve stage captured one from Syft artifact
metadata or official package registry metadata; older work roots need `resolve` (or the full
`run`) to be rerun before report output can show newly supported descriptions. Category is
used only for routing, appendix filenames, and appendix headings. If a resolved repo cannot be joined to
`discovered.json` by exact trimmed `name` or `name_with_owner`, it uses
`discover.taxonomy.default_category` or `uncategorized` and the row records a
`missing_category` coverage gap.

## `release` — release disclosure gate and generated notices

`release` is a standalone stage after a clear shortlist/report gate. It reads the same
resolved records prepared for report output, optionally scans one JS bundle or Cloudflare
Worker artifact for positive npm delivery evidence, evaluates the versioned disclosure
policy, and writes release artifacts to `<WORK>/release` unless `--out-dir` is provided:

```bash
repolens release --work-root <WORK>
repolens release --work-root <WORK> \
  --artifact .open-next/worker.js --target cloudflare-worker
```

`--artifact` and `--target` are required together. `--target` is an arbitrary string:
unknown targets fail closed through `release.policy.json` and `release.review.md` instead
of being rejected by argparse, so policy data remains the source of truth.

On pass, release writes five files:

- `release.policy.json`
- `release.review.md`
- `release.licenses.json`
- `release.notices.md`
- `release.notices.txt`

On block, release writes only `release.policy.json` and `release.review.md`, and removes
any stale `release.licenses.json` or `release.notices.*` files from the output directory.
Unknown disclosure actions, unknown contexts, delivered GPL/non-commercial/source-available
blockers, and irreducible SPDX expressions exit 1. Missing artifact evidence does not
claim `not_delivered`; unscanned targets stay `not_scanned` and appear as scan-coverage
warnings unless policy data is tightened later.

For the runnable Sketch2md-style rehearsal, see
[`docs/pilots/sketch2md-release-pilot.md`](pilots/sketch2md-release-pilot.md).

## Offline fixture acceptance harness

The X1 synthetic fixtures can exercise the shipped M1 stage contracts without live
network or external tools. This harness injects fixture `gh`, clone, Syft, and API
boundaries, then writes the normal artifacts under the supplied work root:

```bash
python scripts/m1_fixture_e2e.py --work-root /tmp/repolens-m1-fixture
```

Expected output is a one-line JSON summary with discovered, SBOM, resolved, main report,
appendix, and docx counts. The work root contains `discovered.json`,
`repos.candidate.md`, per-fixture `sbom.syft.json` and
`resolved.ndjson`, a clear `shortlist.json`, `reports/report.main.{md,csv,html}`,
`reports/report.presentation.{md,csv,html}` plus optional `.docx` files, and
`reports/report.appendix.<category>.{md,csv}`. This is a fixture harness only; live owner
dogfood still uses the normal `repolens run --work-root /tmp/repolens-dogfood --owner
<OWNER> --repos "<REPO>"` shape, or the equivalent
`discover -> scan -> resolve -> flag -> shortlist -> report` stage flow.

## Outputs

- `discovered.json` — the structured repository list for later stages.
- `repos.candidate.md` — the sanitized human approval checklist with visible hard
  exclusion reasons.
- `<WORK>/work/<repo_ref>/sbom.syft.json` — the per-repo Syft SBOM from `scan`.
- `<WORK>/work/<repo_ref>/resolved.ndjson` — license records and evidence from `resolve`.
- `inventory.json`, `shortlist.json`, and `shortlist.md` — policy output from `flag`.
- `report.main.{md,csv,html}` — the gated main disclosure output; HTML is wide on
  screen and prints as letter landscape.
- `report.presentation.{md,csv,html}` — the sibling presentation view, grouped by exact
  SPDX in Markdown and HTML and flat in CSV.
- `report.main.docx` and `report.presentation.docx` — optional shareable Word outputs
  when report header text is configured or entered interactively.
- `report.appendix.<category>.{md,csv}` — excluded-category and first-party appendices.
- `release/release.policy.json` — release gate result and policy provenance.
- `release/release.review.md` — operator release review with blockers, monitored future
  risks, and scan coverage.
- `release/release.licenses.json` — delivered-only machine release manifest, written only
  when the release gate passes.
- `release/release.notices.{md,txt}` — generated bundled notices, written only when the
  release gate passes.

## Safety

Read-only against your code; never runs install/build scripts; external proposal contexts
carry no shell, secrets, filesystem paths, or callables, and RepoLens verifies every cited
URL itself. See the
[security model](roadmap/rpl_security.md) for the full guardrails.
