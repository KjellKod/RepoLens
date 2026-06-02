# RepoLens — usage

> In active development. This guide describes the intended workflow and **grows as each
> command ships** (tracked on the [roadmap](roadmap/rpl_roadmap.md)). For the full design,
> see [docs/roadmap](roadmap/rpl_README.md).

## Prerequisites

- `gh` (authenticated), `git`, `python3`.
- `pip install -e .` (or `pip install -e '.[test]'` for the test suite) — provides the
  `repolens` command and the importable package the `python -m repolens.*` commands use.
- `syft` + `scancode` — installed and version-pinned by a future bootstrap step
  (checksum/signature-verified).
- For mobile license enrichment (optional, auto-detected): a build toolchain
  (JDK + Gradle for Android, Xcode/SPM or a `GITHUB_TOKEN` for iOS).

## Tool bootstrap

Before any scan runs, RepoLens pins and integrity-verifies its own toolchain.
The pins are the single source of truth in `src/repolens/bootstrap/pins.toml`: exact
versions plus sha256 digests for Syft, ScanCode, cosign, `git`, `gh`, and the
base image (by digest) — never `latest`.

Validate the manifest offline (no downloads):

```
python3 -m repolens.bootstrap --dry-run
```

Live bootstrap is available as an injected-runner library call:
`repolens.bootstrap.run(...)`. The `python3 -m repolens.bootstrap` command is currently
validate-only; without injected fetch/cosign/pip runners it exits with a usage error for
live acquisition. The library flow verifies Syft **fail-closed**: it checks the binary's
sha256, then verifies the cosign-signed checksums file, then cross-checks that the pinned
digest matches the signed entry — all **before** the binary is ever made executable or
run. ScanCode installs via a hash-pinned `--require-hashes` requirements file. Resolved
versions/digests are written to `tool_versions.json` (default under `work/`, which is
gitignored).

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

Findings are emitted as `sha256:` hashes, never the literal name, so a real forbidden
value never appears in output or logs.

Findings are reported only by a non-reversible `sha256:` token id, so a real name never
lands in CI logs.

## Configuration (all untracked / local)

- **Owner** — supplied at runtime (`--owner` / env); never committed.
- **Category taxonomy** — how repos are bucketed (e.g. `product`, `internal`).
- **License policy** — the ALLOW / REVIEW / BLOCK / UNKNOWN tiers.
- **Report selection + header** — which categories land in the main report, and the
  org/legal boilerplate (injected at render time).
- **Name-hygiene denylist** — private owner/repo/company names used only by the
  local hygiene guard; never committed and never stored as a public GitHub variable.

F1 local config is loaded only from untracked local files. Precedence is:

1. `--config <path>`
2. `*.local.toml`
3. `*.local.yaml`
4. `*.local.yml`
5. `*.local.json`

On key collisions, the higher-precedence source replaces the lower-precedence value at
that key path; non-colliding keys are preserved.

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
pipeline subcommands are registered as stage routes; `discover`, `scan`, `resolve`, and
`report` run real orchestration. `flag` and `shortlist` are registered placeholders until
those stages land.

Exit codes are:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings remain open, or a sanitized unexpected internal error occurred |
| `2` | Usage, argument, or config input error |

## `scan` — hardened clone + Syft → per-repo SBOM

`repolens scan` consumes an already-approved repo list and produces one SBOM per repo. It
does **not** re-run discovery and is independently rerunnable.

```
repolens scan --work-root work --repos approved-repos.json [--timeout SECONDS]
```

- `--work-root` — the pipeline work root. Per-repo artifacts land under
  `work/work/<repo_ref>/` (`sbom.syft.json` + `scan.status.json`). The verified Syft binary
  is read from `<work-root>/tools/syft`.
- `--repos` — a JSON file of the approved repos. The owner/repo are **runtime inputs**, never
  committed:

  ```json
  { "repos": [ { "repo_ref": "<repo>", "clone_url": "https://<host>/<owner>/<repo>.git" } ] }
  ```

For each repo, `scan` clones through the hardened clone primitive (depth-1, no tags, single
branch, no recursive submodules, hooks/symlinks/file-protocol disabled, prompts off, system
git config off), runs the pinned Syft over the cloned path within a per-repo wall-clock
budget, maps Syft's output onto the frozen `sbom.schema.json`, and persists it through the
store (token-redacted, schema-validated). A completed SBOM lets a rerun **skip** that repo.
Every successful SBOM is persisted even within a mixed run; if any repo fails the process
exits `1` after the rest finish. Token redaction is applied to both the SBOM and
`scan.status.json` before they are written.

`scan` orchestrates external tools only — it never reimplements SBOM generation or license
detection. Syft is acquired and integrity-verified by the bootstrap step (checksum →
signature → provenance, all before the binary is made executable); `scan` consumes that
already-verified binary and performs no acquisition itself.

### `scan` sandbox — M1 scope and deferred non-goals

M1 runs clone + Syft **in-process** with: the hardened git environment, an ephemeral
per-repo workdir, a per-repo wall-clock timeout, guaranteed `finally` cleanup of that
workdir, and no secrets (no GitHub token) in the child environment. No untrusted code from a
scanned repository is executed (hooks are disabled at clone; Syft is a static inventory).

The full container/VM **runner-layer** isolation controls are an explicit M1 **non-goal**:
a read-only root filesystem, dropped Linux capabilities, a non-root UID, CPU/memory/disk
quotas, and a network egress allowlist. Mobile/native license enrichment is also outside P2
scan scope and remains deferred to P3b/R2. No P2 canary asserts filesystem/capability/egress
isolation or mobile/native behavior; the roadmap tick for P2 reflects only the in-process
hardening actually delivered above, not full sandboxing.

## The pipeline

```
repolens discover  --owner <OWNER>   # enumerate + categorize repos -> approval checklist
repolens scan      --work-root work --repos approved-repos.json   # hardened clone + Syft → per-repo SBOM (resumable)
repolens resolve --work-root <WORK> --repo-ref <REPO_REF>
                                      # API-only license resolution for an existing SBOM
repolens flag                        # planned: policy + shortlist
repolens shortlist                   # planned: evidence + human approval
repolens report --work-root <WORK> --out-dir reports
                                      # assemble report.main.md + report.main.csv
```

Discovery (you approve the repo list) and the final report are the shipped human
checkpoints. The planned `flag` and `shortlist` stages will add the policy and approval
gate once they land. The shipped scanner and resolver are read-only against your code and
resumable after an interruption.

### Offline fixture acceptance harness

The X1 synthetic fixtures can exercise the shipped M1 stage contracts without live
network or external tools. This harness injects fixture `gh`, clone, Syft, and API
boundaries, then writes the normal artifacts under the supplied work root:

```bash
python scripts/m1_fixture_e2e.py --work-root /tmp/repolens-m1-fixture
```

Expected output is a one-line JSON summary with discovered, SBOM, resolved, and report
counts. The work root contains `discovered.json`, `repos.candidate.md`,
`approved-repos.json`, per-fixture `sbom.syft.json` and `resolved.ndjson`, and
`reports/report.main.{md,csv}`. This is a fixture harness only; live owner dogfood still
uses the normal `repolens discover -> scan -> resolve -> report` commands above.

### Discover

`discover` is the first shipped pipeline stage. It invokes `gh repo list` for the
runtime owner you provide, categorizes the returned repositories from local taxonomy
config, and writes both the structured stage artifact and the human approval file:

```bash
repolens discover --owner <OWNER> --work-root work
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `--owner <OWNER>` | Runtime owner/org passed to `gh repo list`; never commit it. |
| `--work-root <DIR>` | Output directory for `discovered.json` and `repos.candidate.md`; default `work`. |
| `--limit <N>` | Maximum repositories requested from `gh`; default `1000`, max `5000`. |
| `--force` | Overwrite an existing `repos.candidate.md` approval file. |

Taxonomy is optional and lives only in untracked local config. Unmatched repositories use
`uncategorized` unless you set `default_category`. Categories classify only; they never
exclude a repository from later scanning. Only GitHub-archived repositories or entries in
the local `dead` map are hard-excluded, and the reason is written visibly.

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
discarded. Use `--force` only when you intentionally want a fresh approval file.

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

### Resolve

For the API-only resolution stage, `<WORK>/work/<REPO_REF>/sbom.syft.json` must already
exist:

```bash
repolens resolve --work-root <WORK> --repo-ref <REPO_REF>
```

The command writes `<WORK>/work/<REPO_REF>/resolved.ndjson` with SPDX-normalized
license records or schema-valid unresolved records when evidence cannot be verified.

## Outputs

- `discovered.json` — the structured repository list for later stages.
- `repos.candidate.md` — the sanitized human approval checklist with visible hard
  exclusion reasons.
- `<WORK>/work/<repo_ref>/sbom.syft.json` — the per-repo Syft SBOM from `scan`.
- `<WORK>/work/<repo_ref>/resolved.ndjson` — license records and evidence from `resolve`.
- `report.main.{md,csv}` — the shipped main disclosure output.
- `inventory.json`, `shortlist.md`, `report.main.docx`, and
  `report.appendix.<category>.*` — planned downstream artifacts, not emitted at HEAD.

## Safety

Read-only against your code; never runs install/build scripts; the resolution agent has
no shell, secrets, or arbitrary network. See the
[security model](roadmap/rpl_security.md) for the full guardrails.
