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

**The rule (no exceptions):** open a round only when its gate is green, then launch
**every** Quest in that round in parallel. Never start a round early; never serialize
within a round. Rounds, their members, and their gates are defined **once** in the
[execution doc → Rounds & gates](rpl_execution.md#rounds--gates) — that table is the
single source of truth.

**Before building a component**, read **Build rules + Where things live** in the
[execution doc](rpl_execution.md#build-rules--read-before-starting-any-component) — one
home per concern, extend don't fork, don't rename frozen contracts. (Skipping this is
what caused the R0 drift.)

**Critical path to first value:** F3 → P2 → P6a.

## Milestones

> **Delivery tracking lives here, in the docs — not in code.** Each component's Quest
> ticks its **Delivery** box when its PR merges; the **Acceptance** boxes are ticked
> when their checks are green. A milestone is done when every Delivery box and every
> Acceptance box is checked. `P3` and `P6` each deliver across two rounds, so each half
> is its **own ID** — `P3a` (R1) / `P3b` (R2), `P6a` (R1) / `P6b` (R3) — and no ID ever
> appears in two rounds. No separate status file or code is needed to know what's shipped.

### M0 — Foundation & rails
Deliver F1–F5 and the X1/X2/X3 skeletons.
**Delivery** (each Quest ticks its ID on merge)
- [x] F1 — CLI skeleton + config + exit codes
- [ ] F2 — Security primitives
- [x] F3 — Data model + on-disk schemas (the unlock)
- [x] F4 — Tool bootstrap (pin + checksum/signature verify)
- [x] F5 — Policy engine (SPDX normalize, compound, tiers)
- [x] X1 — test harness + fixtures + watermark (skeleton)
- [x] X2 — security canary suite (skeleton)
- [x] X3 — CI offline PR pipeline (skeleton)

**Acceptance**
- [ ] `repolens --help` runs; config loads from untracked local files.
- [ ] F2 primitives implemented; their **security canaries pass offline**.
- [ ] Bootstrap installs Syft/ScanCode pinned, **verifying checksum + signature**.
- [ ] Name-hygiene guard **fails a deliberately seeded bad commit**; public CI uses
      invented sentinels, while real names are private gitignored local config.
- [ ] F3 schemas frozen and documented.

### M1 — Thin end-to-end inventory
Deliver P1 + P2 + P3a (API layer) + P6a (main view, md/csv) against any `<OWNER>`.
**Delivery** (each Quest ticks its ID on merge)
- [x] P1 — discover (gh → categorize → approval file)
- [x] P2 — scan (hardened clone + Syft)
- [x] P3a — resolve, API layer only
- [ ] P6a — report, main view (md/csv)
- [ ] X1 — fixtures grown to cover R1 components
- [ ] X2 — canaries grown for R1 (clone canaries)
- [ ] X3 — CI grown for R1
- [ ] X3b — branch protection on `main` via `gh` (see [Branch protection](#branch-protection-applied-once-checks-exist-from-m1))
- [ ] Docs — flesh out `docs/usage.md` for the shipped commands (grows M1 → M3)

**Acceptance**
- [ ] End-to-end run on a fixture owner **and** dogfood on RepoLens itself.
- [ ] Multi-language deduped inventory with provenance, versions, source URLs.
- [ ] Clone hardening + **clone canaries green**; the watermark canary passes.
- [ ] Zero owner/repo strings anywhere (hygiene guard green).
- [ ] `main` is protected: required checks must pass **and** the branch must be
      up to date before a PR can merge.

### M2 — Resolution depth + flagging
Deliver P3b (full: sandboxed mobile native + ScanCode on unknowns) + P4.
**Delivery** (each Quest ticks its ID on merge)
- [ ] P3b — resolve full (mobile sandbox + ScanCode-on-unknowns)
- [ ] P4 — flag (tag `origin`/`scope`/`distribution` + policy + dedup)
- [ ] X1 — fixtures grown for R2
- [ ] X2 — canaries grown for R2 (mobile sandbox canaries)
- [ ] X3 — CI grown for R2

**Acceptance**
- [ ] Planted AGPL dep → BLOCK queue; planted no-license dep → UNKNOWN queue, with reasons.
- [ ] ScanCode invoked **only** on items unresolved by APIs.
- [ ] Mobile auto-detected; native enrichment runs **only sandboxed**; **mobile sandbox
      canaries green** (token absent, egress blocked); run never hard-fails on a missing toolchain.
- [ ] Components carry `origin`/`scope`/`distribution`; dedup correct.

### M3 — Human-in-loop + gated full report
Deliver P5 + P6b (full: categories → main + appendices + docx, gate).
**Delivery** (each Quest ticks its ID on merge)
- [ ] P5 — shortlist (capability-minimized agent + human approval)
- [ ] P6b — report full (categories → main + appendices + docx, gate)
- [ ] X1 — fixtures grown for R3
- [ ] X2 — canaries grown for R3 (injection canaries)
- [ ] X3 — CI grown for R3 (+ dogfood on self)

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
  Public CI uses invented sentinel tokens only. Real owner/repo/company names are
  supplied privately through gitignored local config discovered from the main checkout.
- Tool versions pinned + checksum/signature-verified; CI runs offline and deterministic.

## Branch protection (applied once checks exist, from M1)

Once the offline PR checks are real (M1), enable GitHub branch protection on `main`
via `gh` so merges are safe and current:

- **Required status checks must pass** — lint, unit, integration, security canaries,
  and the name-hygiene guard. (The Codex review is advisory / `continue-on-error`; do
  **not** mark it required, or an OpenAI quota hiccup would block every merge.)
- **Require branches to be up to date before merging** — set `strict: true` on the
  required checks, so a PR must be rebased on the latest `main` before it can merge
  (pairs with the quest brief's rebase-before-PR step).
- Recommended: require a PR (no direct pushes to `main`) and ≥1 approving review.

Applied with `gh api` (branch-protection / rulesets) — a one-time config step, kept in
a small script and re-run to update the required-check set as tests grow. It's a roadmap
**step**, not just config drift: ticking `X3b` means protection is live and verified.
