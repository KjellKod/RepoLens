# Roadmap — fast, parallel, sequenced

Strategy: build **foundation in parallel**, freeze the on-disk schemas early so **every
pipeline stage can be built concurrently** against fixtures, ship a **thin end-to-end
slice** first, then deepen. Security primitives and their canaries are part of the
foundation — not a later phase — and **gate every milestone**.

## Workstreams

### F — Foundation (build first; internally parallel)
| ID | Deliverable | Depends |
|----|-------------|---------|
| **F1** | CLI skeleton, config loading (untracked `*.local.*`), subcommand routing, exit codes `0/1/2` | — |
| **F2** | **Security primitives** library: hardened-clone wrapper, allowlisted + SSRF-guarded HTTP client, safe parsers (YAML/XML/JSON/archive caps), CSV/Markdown sanitizers, token redaction | — |
| **F3** | Data model + on-disk store: schemas for `sbom`, `resolved`, `inventory`, `shortlist`; resume logic. **Freezing F3 unlocks all P-stages.** | — |
| **F4** | Tool bootstrap: pinned Syft/ScanCode install with **checksum + signature verification**; pin `git`/`gh`; record versions | — |
| **F5** | Policy engine: string→SPDX normalize, compound-expression eval, tier mapping (pure, fully unit-tested) | — |

### P — Pipeline stages (parallel against F3 schemas; integrate along the data flow)
| ID | Deliverable | Depends |
|----|-------------|---------|
| **P1** | `discover`: `gh` enumerate → categorize (config taxonomy) → `repos.candidate.md` approval file | F1, F3 |
| **P2** | `scan`: hardened clone (F2) + Syft → per-repo SBOM; resumable; sandboxed | F2, F3, F4 |
| **P3** | `resolve`: ladder — API adapters (parallel sub-tasks: deps.dev, registry, GitHub, ClearlyDefined) → mobile native (sandboxed) → ScanCode on unknowns → normalize | F2, F3, F5 |
| **P4** | `flag`: tag `origin`/`scope`/`distribution`, apply policy tiers, dedup → `inventory.json` + `shortlist.md` | F3, F5 |
| **P5** | `shortlist`: capability-minimized agent (F2 fetch/sanitize) + two-queue + human checkboxes + evidence re-verify | F2, F3, F5 |
| **P6** | `report`: category selection → `report.main` + `report.appendix.*` + docx (generic template); gate | F3 |

### X — Cross-cutting (continuous; parallel throughout)
| ID | Deliverable | Depends |
|----|-------------|---------|
| **X1** | Test harness + multi-language fixtures (invented names) + the **watermark canary** | F3 |
| **X2** | **Security canary suite** ([security.md](rpl_security.md)) — must-pass, offline | F2 |
| **X3** | CI: offline PR job (lint + unit + integration + canaries + **name-hygiene guard** + version/checksum pins); scheduled live-smoke + **dogfood on self** | F1, X1, X2 |

## Parallelism & critical path

- **Round 1 (all parallel):** F1, F2, F3, F4, F5 + X1/X2/X3 skeletons.
- **Round 2 (all parallel once F3 frozen):** P1, P2, P3, P4, P5, P6 — each built against
  fixture data, no waiting on the stage upstream of it. P3's API adapters fan out further.
- **Integration** happens along the data flow (`discover→scan→resolve→flag→shortlist→
  report`), but implementation does not serialize on it.
- **Critical path to first value:** F3 → P2 → P6(main). Everything else runs alongside.

## Milestones

### M0 — Foundation & rails
Deliver F1–F5 and the X1/X2/X3 skeletons.
**Acceptance**
- [ ] `repolens --help` runs; config loads from untracked local files.
- [ ] F2 primitives implemented; their **security canaries pass offline**.
- [ ] Bootstrap installs Syft/ScanCode pinned, **verifying checksum + signature**.
- [ ] Name-hygiene guard **fails a deliberately seeded bad commit**.
- [ ] F3 schemas frozen and documented.

### M1 — Thin end-to-end inventory
Deliver P1 + P2 + P3(API layer only) + P6(main view, md/csv) against any `<OWNER>`.
**Acceptance**
- [ ] End-to-end run on a fixture owner **and** dogfood on RepoLens itself.
- [ ] Multi-language deduped inventory with provenance, versions, source URLs.
- [ ] Clone hardening + **clone canaries green**; the watermark canary passes.
- [ ] Zero owner/repo strings anywhere (hygiene guard green).

### M2 — Resolution depth + flagging
Deliver P3(full: sandboxed mobile native + ScanCode on unknowns) + P4.
**Acceptance**
- [ ] Planted AGPL dep → BLOCK queue; planted no-license dep → UNKNOWN queue, with reasons.
- [ ] ScanCode invoked **only** on items unresolved by APIs.
- [ ] Mobile auto-detected; native enrichment runs **only sandboxed**; **mobile sandbox
      canaries green** (token absent, egress blocked); run never hard-fails on a missing toolchain.
- [ ] Components carry `origin`/`scope`/`distribution`; dedup correct.

### M3 — Human-in-loop + gated full report
Deliver P5 + P6(full: categories → main + appendices + docx, gate).
**Acceptance**
- [ ] **Injection canaries green**: suspicious content routed to human, never auto-resolved;
      every cited evidence URL re-fetched and verified.
- [ ] `report` **refuses to assemble** while any flagged item is open.
- [ ] Excluded categories + first-party appear in appendices (nothing deleted).
- [ ] docx renders from the generic template; org/legal text injected at runtime.
- [ ] **Full [definition of done](rpl_requirements.md)** met; dogfood disclosure produced.

## Standing gates (every milestone)

- The full **security canary suite** ([security.md](rpl_security.md)) is green — no deviation.
- The **name-hygiene guard** is green; no owner/repo names in code, tests, or docs.
- Tool versions pinned + checksum/signature-verified; CI runs offline and deterministic.
