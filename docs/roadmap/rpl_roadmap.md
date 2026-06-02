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

**Build in parallel, merge serially:** all quests in a round build at once, but their
PRs merge **one at a time** — each rebases onto the latest `main` and recomputes
`tests/canaries/security/canary_matrix.json`'s `expected_active_count` right before
merge, because every quest in a round adds canaries to that one shared file. Once
`X3b` lands (`strict: true`), GitHub enforces the rebase; until then it's discipline.

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
>
> **Who delivers the X boxes:** from R1 onward, X1/X2/X3 "grown for round N" are shipped
> **inside that round's P-quests** — each P-quest brings its own fixtures, canaries, and
> CI wiring (R1 did exactly this: the canary matrix grew 9 → 31 through P1/P2/P3a/P6a).
> Tick the round's X boxes when every P-quest of the round has merged with its canaries
> active in the matrix. There is no separate X quest per round.

### M0 — Foundation & rails
Deliver F1–F5 and the X1/X2/X3 skeletons.
**Delivery** (each Quest ticks its ID on merge)
- [x] F1 — CLI skeleton + config + exit codes
- [x] F2 — Security primitives
- [x] F3 — Data model + on-disk schemas (the unlock)
- [x] F4 — Tool bootstrap (pin + checksum/signature verify)
- [x] F5 — Policy engine (SPDX normalize, compound, tiers)
- [x] X1 — test harness + fixtures + watermark (skeleton)
- [x] X2 — security canary suite (skeleton)
- [x] X3 — CI offline PR pipeline (skeleton)

**Acceptance**
- [x] `repolens --help` runs; config loads from untracked local files.
- [x] F2 primitives implemented; their **security canaries pass offline**.
- [x] Bootstrap installs Syft/ScanCode pinned, **verifying checksum + signature**.
- [x] Name-hygiene guard **fails a deliberately seeded bad commit**; public CI uses
      invented sentinels, while real names are private gitignored local config.
- [x] F3 schemas frozen and documented.

### M1 — Thin end-to-end inventory
Deliver P1 + P2 + P3a (API layer) + P6a (main view, md/csv) against any `<OWNER>`.
**Delivery** (each Quest ticks its ID on merge)
- [x] P1 — discover (gh → categorize → approval file)
- [x] P2 — scan (hardened clone + Syft)
- [x] P3a — resolve, API layer only
- [x] P6a — report, main view (md/csv)
- [x] X1 — fixtures grown to cover R1 components (shipped inside the R1 P-quests)
- [x] X2 — canaries grown for R1 (clone + scan + per-stage canaries; matrix 9 → 31)
- [x] X3 — CI grown for R1 (all new canaries active in the matrix gate)
- [x] X3b — branch protection on `main` via `gh` (see [Branch protection](#branch-protection-applied-once-checks-exist-from-m1)); re-apply with `scripts/apply_branch_protection.sh`
- [x] Docs — flesh out `docs/usage.md` for the shipped commands (grows M1 → M3)

**Acceptance**
- [x] End-to-end run on a fixture owner **and** dogfood on RepoLens itself.
- [ ] Multi-language deduped inventory with provenance, versions, source URLs.
- [x] Clone hardening + **clone canaries green**; the watermark canary passes.
- [x] Zero owner/repo strings anywhere (hygiene guard green).
- [x] `main` is protected: required checks must pass **and** the branch must be
      up to date before a PR can merge. *(Live: `security-canaries` + `codex-review` +
      `offline-ci` required, `strict: true`, ≥1 review — verified via
      `scripts/apply_branch_protection.sh`.)*

### M2 — Resolution depth + flagging
Deliver P3b (full: sandboxed mobile native + ScanCode on unknowns) + P4.

**Scope boundary (read first):** P3b **extends the merged P3a** `resolve` — same CLI
route, same `resolved.ndjson` contract — and stops there. P4 **consumes**
`resolved.ndjson`. P3b never tags or applies policy (that's P4); P4 never resolves
licenses (that's P3). The "planted AGPL → BLOCK" acceptance is **P4's**, not P3b's.

**Delivery** (each Quest ticks its ID on merge)
- [x] P3b — resolve full: (1) ScanCode invoked **only** on items the API ladder left
      unresolved, scoped to a single package dir / `LICENSE*` files
      ([architecture, ladder step 3](rpl_architecture.md)); (2) mobile native enrichment
      (AboutLibraries / LicensePlist) — auto-detected, **opt-in and off by default**,
      run only inside the sandbox spec of [security.md §2 + §4](rpl_security.md)
      (no secrets mounted, read-only repo mount, egress allowlist, quotas + timeout).
- [x] P4 — flag: tag `origin`/`scope`/`distribution`, apply F5 policy tiers, dedup →
      write `inventory.json` + `shortlist.md`; exit non-zero while any item is open.
- [ ] X1 — fixtures grown for R2: planted AGPL dep, planted no-license dep, one Android
      and one iOS fixture repo (invented names) — shipped inside the P3b/P4 quests
- [ ] X2 — canaries grown for R2: mobile sandbox canaries (`GITHUB_TOKEN` absent inside
      the sandbox; egress blocked) — shipped inside the P3b quest
- [ ] X3 — CI grown for R2: new canaries active in the matrix, `expected_active_count`
      recomputed — shipped inside the P3b/P4 quests

**Acceptance** (owner in bold)
- [ ] **P4** — planted AGPL dep → BLOCK queue; planted no-license dep → UNKNOWN queue,
      each with a stated reason.
- [x] **P3b** — ScanCode invoked **only** on items unresolved by APIs.
- [x] **P3b** — mobile auto-detected; native enrichment runs **only sandboxed**; **mobile
      sandbox canaries green** (token absent, egress blocked); a missing mobile toolchain
      degrades gracefully — it never hard-fails the run.
- [ ] **P4** — components carry `origin`/`scope`/`distribution`; dedup correct.
- [ ] **Round** — re-run the M1 dogfood pipeline against this repo (owner at runtime
      only) and re-measure the coverage gaps tracked in **issue #20**: the SBOM must
      include the pyproject-declared runtime deps, and license + source-URL coverage
      must be ~complete now that ScanCode-on-unknowns exists. When met: tick M1's
      still-open inventory acceptance box and close issue #20. If a gap remains
      (e.g. workflow-action deps), re-scope the issue to exactly what's left.

### M3 — Human-in-loop + gated full report
Deliver P5 + P6b (full: categories → main + appendices + docx, gate).

**Scope boundary (read first):** P5 owns the *resolution* of flagged items (the
agent + the human checkboxes + evidence re-verification). P6b owns the *assembly*
(categories, appendices, docx, and the refuse-while-open gate). P6b reads P5's
resolved shortlist; it never resolves items itself.

**Delivery** (each Quest ticks its ID on merge)
- [ ] P5 — shortlist: capability-minimized resolution agent (**no shell, no secrets,
      no arbitrary network** — fetch/sanitize only via the F2 primitives) + the
      two-queue `shortlist.md` with human checkboxes; every cited evidence URL is
      **re-fetched and verified** before an item can close. **Security-critical: full
      workflow lane** ([execution doc](rpl_execution.md#execution-intensity--model-lanes)).
- [ ] P6b — report full: extends the merged P6a with category selection →
      `report.main.{md,csv,docx}` + `report.appendix.<category>.*`; docx from the
      generic template with org/legal text injected at runtime; **refuses to assemble
      while any flagged item is open**.
- [ ] X1 — fixtures grown for R3: injection-bearing fixtures (prompt-injection content
      in package metadata / LICENSE files) — shipped inside the P5 quest
- [ ] X2 — canaries grown for R3: injection canaries — shipped inside the P5 quest
- [ ] X3 — CI grown for R3: + the scheduled **dogfood-on-self** job — shipped inside
      the P5/P6b quests

**Acceptance** (owner in bold)
- [ ] **P5** — **injection canaries green**: suspicious content routed to human, never
      auto-resolved; every cited evidence URL re-fetched and verified.
- [ ] **P6b** — `report` **refuses to assemble** while any flagged item is open.
- [ ] **P6b** — excluded categories + first-party appear in appendices (nothing deleted).
- [ ] **P6b** — docx renders from the generic template; org/legal text injected at runtime.
- [ ] **Round** — full [definition of done](rpl_requirements.md) met; dogfood disclosure
      produced for RepoLens itself. **Not tickable while issue #20 (dogfood coverage
      gaps) is open** — M3 is the final backstop if the M2 re-measure left anything.

## Standing gates (every milestone)

- The full **security canary suite** ([security.md](rpl_security.md)) is green — no deviation.
- The **name-hygiene guard** is green; no owner/repo names in code, tests, or docs.
  Public CI uses invented sentinel tokens only. Real owner/repo/company names are
  supplied privately through gitignored local config discovered from the main checkout.
- Tool versions pinned + checksum/signature-verified; CI runs offline and deterministic.

## Branch protection (applied once checks exist, from M1)

Once the offline PR checks are real (M1), enable GitHub branch protection on `main`
via `gh` so merges are safe and current.

**Live since X3b** (re-apply / evolve with `scripts/apply_branch_protection.sh`):

- **Required checks:** `security-canaries`, `codex-review`, `offline-ci` (lint, unit,
  integration, the canary matrix gate, and the name-hygiene guard).
- **`strict: true`** — a PR must be up to date with `main` before merging, which makes
  the "recompute the canary-matrix count at final rebase" rule machine-enforced.
- **≥1 approving review** required.
- `codex-review` stays required for now (deliberate trade-off vs. the original
  "advisory-only" advice); if OpenAI quota flakiness ever blocks merges, demote it
  to advisory and note it here.

Applied with `gh api` (branch-protection / rulesets) — a one-time config step, kept in
a small script and re-run to update the required-check set as tests grow. It's a roadmap
**step**, not just config drift: ticking `X3b` means protection is live and verified.
