# Execution model — how we drive the build

The [roadmap](rpl_roadmap.md) says *what* to build and in what order. This says *how
we run it*: which driver, and the fan-out model.

## TL;DR

- **Quest is the build driver.** One Quest per component (an `F`/`P`/`X` item). Each
  Quest internally runs plan → review → build → fix with quality gates — that's where
  code is written and tested.
- **We launch multiple Quests in parallel per round — not one agent doing everything.**
  The roadmap's dependency gates define round boundaries; independent components in a
  round run as concurrent Quests.
- **Workflows are for verification sweeps**, not for writing the app (adversarial
  security review, cross-component code review, tool-API research refresh).
- **Plain prompts** ("just do it") only for trivial mechanical edits.

## Drivers — when to use which

| Driver | Use for | Not for |
|--------|---------|---------|
| **Quest** | Building any `F`/`P`/`X` component: real code + tests, with plan/review/build/fix gates | Throwaway sweeps |
| **Workflow** | Parallel *verification*: adversarial security review, cross-component code review, research refresh on an orchestrated tool's API | Writing production code |
| **Plain prompt** | A rename, a config tweak, a doc fix | Anything with acceptance criteria |

## Fan-out model

- **Across components:** *we* fan out by launching several Quests concurrently within a
  round. Round boundaries = the roadmap dependency gates.
- **Within a component:** *Quest* fans out internally (planner → reviewer → builder →
  fixer). We do not hand-roll per-component agent orchestration.
- So "one agent fanning out to everything" is explicitly **not** the model. It is
  *N parallel Quests per round, each itself a small multi-agent pipeline.*

## Rounds & gates

Each round = a set of Quests that can run in parallel. A round closes only when its
**standing gate** is green: the full **security canary suite** ([rpl_security](rpl_security.md))
passes offline **and** the name-hygiene guard is green.

| Round | Milestone | Parallel Quests | Opens when |
|-------|-----------|-----------------|-----------|
| **R0** | M0 foundation | F1, F2, F3, F4, F5 + X1/X2/X3 skeletons | start |
| **R1** | M1 thin slice | P1, P2, P3·api-layer, P6·main-view | **F3 schemas frozen** + F2 primitives + their canaries green |
| **R2** | M2 depth | P3·full (mobile sandbox + ScanCode-on-unknowns), P4 | R1 integrated |
| **R3** | M3 human-loop | P5, P6·full | R2 integrated |

`X1` (fixtures/watermark), `X2` (security canaries), `X3` (CI) start in R0 and **grow
every round** alongside the components they cover.

## Component → driver map

| ID | Component | Driver | Round |
|----|-----------|--------|-------|
| F1 | CLI skeleton + config + exit codes | Quest | R0 |
| F2 | Security primitives | Quest (critical) | R0 |
| F3 | Data model + on-disk schemas (the unlock) | Quest | R0 |
| F4 | Tool bootstrap (pin + checksum/signature verify) | Quest | R0 |
| F5 | Policy engine (SPDX normalize, compound, tiers) | Quest | R0 |
| P1 | discover (gh → categorize → approval file) | Quest | R1 |
| P2 | scan (hardened clone + Syft) | Quest | R1 |
| P3 | resolve (ladder; API adapters → mobile → ScanCode) | Quest | R1 (api) → R2 (full) |
| P4 | flag (tag + policy + dedup) | Quest | R2 |
| P5 | shortlist (capability-minimized agent + human) | Quest (critical) | R3 |
| P6 | report (categories → main + appendix + docx) | Quest | R1 (main) → R3 (full) |
| X1 | test harness + fixtures + watermark | Quest | R0+ |
| X2 | security canary suite | Quest | R0+ |
| X3 | CI (offline PR + scheduled live-smoke + dogfood) | Quest | R0+ |

## Where Workflows plug in (verification only)

- **After F2 + X2:** an adversarial **security review** Workflow — parallel red-team
  lenses try to defeat each guardrail; findings feed back as Quest fixes.
- **At each round close:** a **cross-component code-review** Workflow — parallel
  reviewers over the round's changes, before integration.
- **On demand:** a **research-refresh** Workflow if an orchestrated tool's API/output
  shape changed (Syft, ScanCode, deps.dev, GitHub, registries).

## Quest brief seed (template)

Every component Quest is briefed the same way (DRY — point at the docs, don't restate):

```
Build <ID> <component> for directory/repo RepoLens.
- create a worktree based of origin/main, the branch and worktree name shoudl follow the format `<ID>__ <component_first_10_letters_with_underscore_and_no_space>`
- First action on the git worktree branch is to mark 
- Scope/deliverable: see docs/roadmap/rpl_roadmap.md (this component's row) and
  docs/roadmap/rpl_decisions.md.
- Acceptance: the rpl_roadmap M<n> criteria for this component, plus every applicable
  canary in docs/roadmap/rpl_security.md is green.
- Hard rules: orchestrate, don't reimplement scanners; security guardrails are
  mandatory; no owner/repo/company names in code, tests, or docs (CI hygiene guard);
  owner is a runtime input only.
- Output: code + tests + the component's canaries wired into CI.
```

## Quest placement — recommendation: outside-in

Two options; the brief seeds and rounds above work with either.

| Approach | What it means | Trade-off |
|----------|---------------|-----------|
| **Outside-in (recommended)** | Quest runs from the surrounding workspace and lands commits/PRs in the RepoLens repo; Quest's own plan/review artifacts stay **outside** the repo | Keeps RepoLens's tree **product-only and public-ready**; no Quest scaffolding committed; plans aren't versioned with the code (fine — they're process, not product) |
| Install-in | Quest installed inside RepoLens; artifacts in `.quest/` (gitignored) | Native git/PR flow, plans versioned with code; but injects Quest tooling into a repo meant to stay clean / possibly public |

**Recommendation: outside-in**, because keeping RepoLens minimal, repo-agnostic, and
public-ready has been the governing constraint. Pick install-in only if you later want
the build plans versioned alongside the code in this repo.
