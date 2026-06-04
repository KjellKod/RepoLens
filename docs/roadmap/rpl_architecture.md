# Architecture

A thin Python CLI that **orchestrates** mature tools and owns the workflow, policy,
evidence, categorization, report, and security. Each stage is a subcommand that reads
and writes on-disk artifacts, so stages are independently runnable, resumable, and —
critically — independently *buildable in parallel* against fixed schemas.

## Pipeline

```
repolens discover  --owner <OWNER>     # gh → categorize → repos.candidate.md (human approves)
repolens scan      --repos <approved>  # hardened clone + Syft → work/<repo>/sbom.syft.json
repolens resolve                       # resolution ladder → work/<repo>/resolved.ndjson
repolens flag                          # tag + policy + dedup → inventory.json + shortlist.md
repolens shortlist                     # capability-minimized agent + human checkboxes
repolens report                        # gate → report.main + report.appendix.* + docx
```

## Resolution ladder (cheapest source first)

Each dependency gets its license from the first layer that succeeds; each records its
source as evidence. This shrinks the unknown set before anything slow or AI-driven runs.

| # | Layer | Cost | Notes |
|---|-------|------|-------|
| 0 | Syft declared metadata | cheap | from the SBOM already produced |
| 1 | Free license APIs (no clone) | cheap | deps.dev → registry APIs → GitHub license API → ClearlyDefined/ecosyste.ms fallback |
| 2 | Mobile native enrichment | medium | auto-detected mobile repos only; **sandboxed**; metadata/API default |
| 3 | ScanCode on the remaining unknowns | expensive | scoped to a single package dir / `LICENSE*` files |
| 4 | Evidence-anchored agent + human | human | the flagged shortlist only |

A **string→SPDX normalization** pass runs before policy lookup. Default API precedence follows
the adapter ladder: deps.dev → native registry field → ClearlyDefined curated →
ecosyste.ms. `resolve --detect-conflicts` opts into cross-checking every API adapter and
lowers verified API disagreement to `CONFLICT` → human; the default stops at the first
verified API source before falling through to mobile or ScanCode.

## Tagging & dedup

- Tag each component `origin` / `scope` / `distribution` (see [decisions](rpl_decisions.md)).
- Collapse to one row per `(name, normalized-SPDX)` with `found_in: [...]` provenance,
  versions seen, `source_url`, and `modified?`.

## Report views

The report is a **set**, driven by category selection (untracked config):
- `report.main` — included categories/items (default view `distributed`, `third-party-oss`).
- `report.appendix.<category>` — one per excluded category + first-party/internal.
- `inventory.json` — the full tagged dataset behind both.

Re-scoping is config + re-render, never a re-scan. The `.docx` renders from a generic
placeholder template; org/legal text is injected at runtime from untracked config.

## Storage (gitignored work dirs)

```
work/<repo>/sbom.syft.json     # canonical Syft output
work/<repo>/resolved.ndjson    # one line per dep: license + evidence + tags
inventory.json                 # deduped, tagged, full dataset
shortlist.md                   # human approval + audit trail
out/report.*                   # main + appendices + docx
```

Resume = skip any repo whose `sbom.syft.json` already exists.

## Sanity canary ("watermark")

Every run asserts against a known fixture with a hand-listed dependency set; the run
**fails loudly** if any expected dependency is missing — so "0 findings" means clean,
not broken.

## What we build vs. orchestrate

| We build | We orchestrate |
|----------|----------------|
| CLI, config, subcommand pipeline | `gh`, `git` |
| Resolution ladder + source precedence | Syft, ScanCode |
| Policy engine (SPDX normalize, compound expr, tiers) | deps.dev / registry / GitHub / ClearlyDefined APIs |
| Tagging, dedup, categorization | AboutLibraries, LicensePlist (sandboxed) |
| Evidence model + capability-minimized agent | — |
| Report views + docx render | — |
| **Security primitives** (clone, fetch, parse, sanitize, redact) | — |

## Tool bootstrap & integrity

RepoLens acquires and verifies its own pinned toolchain rather than trusting whatever is on
the machine. `src/repolens/bootstrap/pins.toml` is the single source of truth: exact
versions plus sha256 digests for Syft, ScanCode, cosign, `git`, `gh`, and the base image
(by digest) — never `latest`.

Syft acquisition is **fail-closed**, in order, all **before** the binary is ever made
executable or run:

1. **sha256** of the downloaded artifact must equal the pinned digest;
2. **cosign** verifies the signed checksums file against the pinned signer identity / OIDC
   issuer;
3. a **manifest-hash-signed cross-check** ties the pin in `pins.toml` to the cosign-verified
   checksums entry, so a maintainer cannot quietly edit the pin to a value the signature does
   not vouch for.

ScanCode installs via a hash-pinned `--require-hashes` requirements file. Resolved
versions/digests are recorded in `tool_versions.json` (under the gitignored work root). The
manifest can be validated offline with `python3 -m repolens.bootstrap --dry-run`.

## Scan execution model & sandbox scope

`scan` runs clone + Syft **in-process** with a hardened git environment, an ephemeral
per-repo workdir (guaranteed `finally` cleanup), a per-repo wall-clock timeout, and no
secrets (no GitHub token) in the child environment. No untrusted code from a scanned
repository executes — clone hooks/symlinks/file-protocol are disabled and Syft is a static
inventory.

Full container/VM **runner-layer** isolation — read-only root FS, dropped Linux
capabilities, non-root UID, CPU/memory/disk quotas, network egress allowlist — is a
deliberate scope boundary, layered at the runner rather than inside the process. The
mobile/native enrichment path (P3b) is the one execution-bearing step and runs only through
the sandbox boundary; see [security.md](rpl_security.md) for the mandatory guardrails and
canaries.
