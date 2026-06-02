# RepoLens — usage

> In active development. This guide describes the intended workflow and **grows as each
> command ships** (tracked on the [roadmap](roadmap/rpl_roadmap.md)). For the full design,
> see [docs/roadmap](roadmap/rpl_README.md).

## Prerequisites

- `gh` (authenticated), `git`, `python3`.
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

A live bootstrap (called by the pipeline, or via `repolens.bootstrap.run(...)`
with injected fetch/cosign/pip runners) verifies Syft **fail-closed**: it checks
the binary's sha256, then verifies the cosign-signed checksums file, then
cross-checks that the pinned digest matches the signed entry — all **before** the
binary is ever made executable or run. ScanCode installs via a hash-pinned
`--require-hashes` requirements file. Resolved versions/digests are written to
`tool_versions.json` (default under `work/`, which is gitignored).

### Name-hygiene gate

The offline CI workflow runs `tools/name_hygiene.py`, which fails the build on any
forbidden owner/org/company literal. The forbidden names are **never committed**:
the guard reads them from the `RPL_HYGIENE_DENYLIST` environment variable
(comma/newline-separated) or from a file named in `RPL_HYGIENE_DENYLIST_FILE`.

The guard is **fail-closed**: if no denylist is configured it exits non-zero (a
config error), so the gate can never pass vacuously. CI supplies a generated
denylist file for offline smoke coverage. For live owner/org hygiene, configure
the denylist:

```
# GitHub -> Settings -> Secrets and variables -> Actions -> Variables
RPL_HYGIENE_DENYLIST = name1,name2,...        # the real forbidden literals
```

Run it locally the same way (substitute your own forbidden names):

```
RPL_HYGIENE_DENYLIST="name1,name2" python3 tools/name_hygiene.py
```

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

## F1 CLI Skeleton

`repolens --help` is the primary health check for the shipped CLI entry point. The
pipeline subcommands are registered as skeleton routes while later roadmap components add
their real orchestration behavior.

Exit codes are:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Findings remain open, or a sanitized unexpected internal error occurred |
| `2` | Usage, argument, or config input error |

## The pipeline

```
repolens discover  --owner <OWNER>   # enumerate + categorize repos → approval checklist
repolens scan                        # hardened clone + Syft → per-repo SBOM (resumable)
repolens resolve                     # license ladder: APIs → mobile → ScanCode on unknowns
repolens flag                        # tag + apply policy + dedup → inventory + shortlist
repolens shortlist                   # evidence-anchored agent + human checkbox approval
repolens report                      # gated: assemble main report + appendices
```

Discovery (you approve the repo list) and the final report (gated until the shortlist is
clear) are the two human checkpoints. Everything else is automatic, read-only against
your code, and resumable after an interruption.

## Outputs

- `inventory.json` — the complete, tagged dataset.
- `report.main.{md,csv,docx}` — the disclosure for the included categories.
- `report.appendix.<category>.{md,csv}` — one per excluded category + first-party.
- `shortlist.md` — the human approval / audit artifact, plus a per-item evidence log.

## Safety

Read-only against your code; never runs install/build scripts; the resolution agent has
no shell, secrets, or arbitrary network. See the
[security model](roadmap/rpl_security.md) for the full guardrails.
