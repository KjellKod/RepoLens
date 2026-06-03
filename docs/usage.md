# RepoLens — usage

> All six pipeline stages (`discover → scan → resolve → flag → shortlist → report`) are
> shipped. For the design behind them see [docs/roadmap](roadmap/rpl_README.md); the
> original build plan is archived under [docs/roadmap/archive](roadmap/archive/rpl_roadmap.md).

## Prerequisites

- `gh` (authenticated), `git`, `python3`.
- `pip install -e .` (or `pip install -e '.[test]'` for the test suite) — provides the
  `repolens` command and the importable package the `python -m repolens.*` commands use.
- `syft` — acquired by `scan` on first use into RepoLens's shared verified cache, or
  pre-seeded with `repolens bootstrap` for offline runs.
- `scancode` — version-pinned by bootstrap requirements for scoped fallback use.
- For mobile license enrichment (optional, auto-detected): a build toolchain
  (JDK + Gradle for Android, Xcode/SPM or a `GITHUB_TOKEN` for iOS).

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
For automation, pass `--yes`; for offline runs, pre-seed the cache:

```
repolens bootstrap
repolens scan --work-root work --offline
```

Validate the manifest offline, no downloads:

```
python3 -m repolens.bootstrap --dry-run
```

`repolens bootstrap` and `scan --yes` verify Syft **fail-closed**: they check the
release artifact's sha256, verify the cosign-signed checksums file, then cross-check that
the pinned digest matches the signed entry — all **before** the Syft executable is exposed
from the cache. ScanCode installs via a hash-pinned `--require-hashes` requirements file
when the full injected-runner library flow (`repolens.bootstrap.run(...)`) is used.

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

Pass a local config file with the global `--config` option before the stage name:

```bash
repolens --config ./repolens.local.toml discover --owner <OWNER>
```

Owner is supplied at runtime (`--owner` / env) and never committed. Discover taxonomy
config is loaded from untracked local config files. The private name-hygiene denylist is
also local and untracked, but it uses the dedicated `.name-hygiene.local.json` file shown
below.

The runtime config loader supports three formats: JSON, TOML, and YAML. YAML has two
file extensions, so there are four filename patterns, not four different config models:

- `*.local.json`
- `*.local.toml`
- `*.local.yaml`
- `*.local.yml`

Prefer one local config file unless you intentionally need layered overrides. When
multiple local config files exist, precedence is:

1. `--config <path>`
2. `*.local.toml`
3. `*.local.yaml`
4. `*.local.yml`
5. `*.local.json`

On key collisions, the higher-precedence source replaces the lower-precedence value at
that key path; non-colliding keys are preserved.

`discover.taxonomy` is the optional set of rules that assigns each discovered repository
to a category. Categories are labels for review/reporting; they do not remove a repo from
the workflow.

Supported taxonomy keys:

| Key | Meaning |
|-----|---------|
| `default_category` | Category used when no other rule matches. If omitted, this is `uncategorized`. |
| `explicit` | Exact repo-name matches. Keys can be `owner/repo` or just `repo`; values are categories. |
| `patterns` | Repo-name glob rules, checked after `explicit`. Each rule has `glob` and `category`. |
| `topics` | GitHub repository topic matches. Topics are the tags shown on a GitHub repo page and returned by `gh repo view --json repositoryTopics`. |
| `dead` | Exact repo-name matches that should be hard-excluded with the configured reason. Use only for retired/dead repos. |

Matching order for categories is `explicit`, then `patterns`, then `topics`, then
`default_category`. The authoritative parser is
[`src/repolens/discovery/taxonomy.py`](../src/repolens/discovery/taxonomy.py).

Example taxonomy in `repolens.local.toml`:

```toml
[discover.taxonomy]
default_category = "uncategorized"

[discover.taxonomy.explicit]
"sentinel-owner/sentinel-alpha" = "runtime-bucket"

[[discover.taxonomy.patterns]]
glob = "tool-*"
category = "tooling-bucket"

[discover.taxonomy.topics]
mobile = "mobile-bucket"

[discover.taxonomy.dead]
sentinel-retired = "retired by local approval"
```

The same taxonomy in `repolens.local.json`:

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
      "dead": {
        "sentinel-retired": "retired by local approval"
      }
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

## CLI stages

`repolens --help` is the primary health check for the shipped CLI entry point. The
pipeline subcommands are registered as stage routes; `discover`, `scan`, `resolve`,
`flag`, `shortlist`, and `report` all run real orchestration.

Exit codes are:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings remain open, or a sanitized unexpected internal error occurred |
| `2` | Usage, argument, or config input error |

## The pipeline at a glance

```
repolens discover  --owner <OWNER>   # enumerate + categorize repos -> approval checklist
repolens scan      --work-root work  # first use verifies Syft cache, then writes SBOMs
repolens resolve --work-root <WORK> --repo-ref <REPO_REF>
                                      # API-only license resolution for an existing SBOM
repolens flag      --work-root work  # apply policy, flag risk/unknowns -> shortlist queue
repolens shortlist --work-root work [--identity <REVIEWER>]
                                      # settle flagged items + human approval
repolens report --work-root <WORK> --out-dir reports
                                      # assemble gated main, docx, and appendix reports
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
`uncategorized` unless you set `default_category`. Categories classify only; they never
exclude a repository from later scanning. Only GitHub-archived repositories or entries in
the local `dead` map are hard-excluded, and the reason is written visibly.

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
repolens scan --work-root work [--timeout SECONDS] [--yes] [--offline] [--quiet]
repolens scan --work-root work --repos approved-repos.json [--timeout SECONDS] [--yes] [--quiet]
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
- `--yes` / `-y` — pre-consent for automation. If the verified cache is empty, scan
  downloads RepoLens's pinned Syft, verifies it, caches it, and continues.
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

For each repo, `scan` clones through the hardened clone primitive (depth-1, no tags, single
branch, no recursive submodules, hooks/symlinks/file-protocol disabled, prompts off, system
git config off), runs the pinned Syft over the cloned path within a per-repo wall-clock
budget, maps Syft's output onto the frozen `sbom.schema.json`, and persists it through the
store (token-redacted, schema-validated). A completed SBOM lets a rerun **skip** that repo.
Every successful SBOM is persisted even within a mixed run; if any repo fails the process
exits `1` after the rest finish. Token redaction is applied to both the SBOM and
`scan.status.json` before they are written.

During a multi-repo run, stderr shows one line when each approved repo starts, one outcome line
when it finishes or is skipped, and a final `Done:` count. Non-TTY stderr gets plain appended
lines; TTY stderr may rewrite the in-progress line. stdout remains empty.

`scan` orchestrates external tools only — it never reimplements SBOM generation or license
detection. On a cache miss it acquires only RepoLens's pinned Syft and verifies it through
the existing bootstrap gates (checksum → signature → provenance, all before the binary is
exposed); the scanner then consumes that already-verified binary.

`scan` runs clone + Syft **in-process** with a hardened git environment, an ephemeral
per-repo workdir, a per-repo wall-clock timeout, and no secrets in the child environment;
no untrusted repo code executes (clone hooks/symlinks/file-protocol disabled, Syft is a
static inventory). Full container/VM runner-layer isolation is a deliberate scope boundary
layered at the runner — see
[architecture → Scan execution model & sandbox scope](roadmap/rpl_architecture.md#scan-execution-model--sandbox-scope).

## `resolve` — license ladder → `resolved.ndjson`

For the resolution stage, `<WORK>/work/<REPO_REF>/sbom.syft.json` must already exist:

```bash
repolens resolve --work-root <WORK> --repo-ref <REPO_REF>
```

That no-flag form preserves the API-layer behavior: Syft-declared licenses and
verified metadata API evidence are written to `resolved.ndjson`; unresolved records
remain schema-valid.

P3b adds an optional source checkout boundary for mobile marker detection and scoped
ScanCode fallback:

```bash
repolens resolve \
  --work-root <WORK> \
  --repo-ref <REPO_REF> \
  --source-root fixtures/source/sentinel-mobile
```

`--source-root` is read-only input. It lets `resolve` detect mobile markers and derive
package-local ScanCode targets from SBOM `locations`. ScanCode is invoked only for
dependencies still unresolved by earlier layers, and target selection rejects broad
repository-root scans and paths outside the source root. If the canonical
hash-pinned/bootstrap-produced ScanCode executable is unavailable, affected packages
stay unresolved instead of failing the run.

Native mobile enrichment is opt-in and remains off by default even when mobile markers
are present:

```bash
repolens resolve \
  --work-root <WORK> \
  --repo-ref <REPO_REF> \
  --source-root fixtures/source/sentinel-mobile \
  --enable-mobile-native
```

The native mobile path runs only through the sandbox boundary. Missing mobile
toolchains or a missing sandbox backend lower affected packages to unresolved mobile
evidence, such as `unresolved:mobile_sandbox_unavailable`, without hard-failing the
stage.

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

The default policy tiers live in [license-policy.md](roadmap/rpl_license-policy.md) and are
overridable through untracked local config.

## `shortlist` — capability-minimized agent + human approval

`repolens shortlist --work-root work [--identity <REVIEWER>]` reads the `shortlist.json` and
`shortlist.md` that `flag` produced and settles each `open` item:

1. **Ingest human decisions.** Any item whose checkbox you ticked in `shortlist.md`
   (`[x]` approve, `[r]` reject) is recorded with `status`, `decided_by` (from `--identity`,
   a runtime input — never an owner/repo literal), and a UTC `decided_at`. Do not edit the
   `rpl:ref` markers; they key each decision back to its component.
2. **Pre-screen → route.** Each still-open item's untrusted text (LICENSE / README /
   description / evidence) is capped, NFC-normalized, and screened for injection markers
   (role-play, output-override, container-escape, imperative, directional Unicode). A
   flagged item routes to the human queue and the resolution agent is **never invoked** for
   it.
3. **Capability-minimized agent.** Clean content is wrapped in `<untrusted_content>` (output
   instruction appended after the block) and handed to the agent, which may only propose a
   schema-validated `{spdx_id, evidence_url, evidence_anchor}` or abstain. The agent has no
   shell, no file-write, no token, and no arbitrary network.
4. **Verify, don't trust.** Any proposal is confirmed by re-fetching the cited evidence URL
   through the SSRF-guarded, allowlisted HTTP client and checking it exactly anchors the
   claimed SPDX id. A verified proposal records the candidate and `evidence.source_layer =
   "agent"` but the item **stays open until you tick it** — the agent proposes, you dispose.

`shortlist` exits `0` only when no item remains open and `1` (findings open) otherwise, so
it gates the downstream report.

## `report` — gated main disclosure + appendices

`report` reads resolved occurrences, discovered repository categories when available, and
local runtime report config. If `<WORK>/shortlist.json` exists with `open_count > 0` or
any item whose `status` is `open`, the command exits with findings-open status and writes
no report artifacts. A missing shortlist does not block assembly.

The docx header is required and must come from untracked runtime config:

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

`report.selection.include` is optional. When it is omitted, every observed third-party
category is selected into `report.main`. When present, third-party occurrences in included
categories go to `report.main.{md,csv,docx}`; excluded third-party categories go to
`report.appendix.<category>.{md,csv}`. First-party occurrences always go to
`report.appendix.first-party.{md,csv}`.

The main markdown and CSV keep the frozen P6a columns. Category is used only for routing,
appendix filenames, and appendix headings. If a resolved repo cannot be joined to
`discovered.json` by exact trimmed `name` or `name_with_owner`, it uses
`discover.taxonomy.default_category` or `uncategorized` and the row records a
`missing_category` coverage gap.

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
`resolved.ndjson`, a clear `shortlist.json`, `reports/report.main.{md,csv,docx}`, and
`reports/report.appendix.<category>.{md,csv}`. This is a fixture harness only; live owner
dogfood still uses the normal `repolens discover -> scan -> resolve -> flag -> report`
commands above.

## Outputs

- `discovered.json` — the structured repository list for later stages.
- `repos.candidate.md` — the sanitized human approval checklist with visible hard
  exclusion reasons.
- `<WORK>/work/<repo_ref>/sbom.syft.json` — the per-repo Syft SBOM from `scan`.
- `<WORK>/work/<repo_ref>/resolved.ndjson` — license records and evidence from `resolve`.
- `inventory.json`, `shortlist.json`, and `shortlist.md` — policy output from `flag`.
- `report.main.{md,csv,docx}` — the gated main disclosure output.
- `report.appendix.<category>.{md,csv}` — excluded-category and first-party appendices.

## Safety

Read-only against your code; never runs install/build scripts; the resolution agent has
no shell, secrets, or arbitrary network. See the
[security model](roadmap/rpl_security.md) for the full guardrails.
