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

A **string→SPDX normalization** pass runs before policy lookup. Precedence when sources
disagree: native registry field → ClearlyDefined curated → deps.dev → GitHub Licensee →
ScanCode detection; unresolved disagreement = `CONFLICT` → human.

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
