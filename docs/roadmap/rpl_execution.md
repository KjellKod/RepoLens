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

**The rule (no exceptions):** open a round only when its **Opens when** gate is green →
then launch **every** Quest in that round in parallel → merge each only when the
**standing gate** is green (security canary suite [rpl_security](rpl_security.md) +
name-hygiene guard). The next round opens when the current one is fully merged. Never
start a round early; never serialize within a round. This table is the single source of
truth for round membership and gates.

| Round | Milestone | Parallel Quests | Opens when |
|-------|-----------|-----------------|-----------|
| **R0** | M0 foundation | F1, F2, F3, F4, F5 + X1/X2/X3 skeletons | start |
| **R1** | M1 thin slice | P1, P2, P3a, P6a | **F3 schemas frozen** + F2 primitives + their canaries green |
| **R2** | M2 depth | P3b (mobile sandbox + ScanCode-on-unknowns), P4 | R1 integrated |
| **R3** | M3 human-loop | P5, P6b | R2 integrated |

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
| P3a / P3b | resolve — **P3a**: API layer (R1); **P3b**: + mobile sandbox & ScanCode-on-unknowns (R2) | Quest | R1 / R2 |
| P4 | flag (tag + policy + dedup) | Quest | R2 |
| P5 | shortlist (capability-minimized agent + human) | Quest (critical) | R3 |
| P6a / P6b | report — **P6a**: main view (R1); **P6b**: + categories, appendices, docx, gate (R3) | Quest | R1 / R3 |
| X1 | test harness + fixtures + watermark | Quest | R0+ |
| X2 | security canary suite | Quest | R0+ |
| X3 | CI (offline PR + scheduled live-smoke + dogfood) | Quest | R0+ |

## Execution intensity & model lanes

Not every component needs the full pipeline or two models. Tune per ID via the
allowlist (`~/ws/extra/.ai/allowlist.json`) — no code involved.

**Intensity**
- **Full workflow** (plan → dual review + arbiter → build → dual review → fix) for
  anything security-critical or contract-defining: **F2, F3, P3b, P4, P5**.
- **Solo / lighter** (single agent, fewer fix iterations — allowlist `solo`) is fine for
  mechanical scaffolding and docs-shaped work: **F1, F4, the X* skeletons, P3a, P6a**.
- `review_mode` (`auto`/`fast`/`full`) + `fast_review_thresholds` already auto-lighten
  review for tiny diffs.

**Model lanes** (allowlist `models` map, per role)
- **Mixed (default, best quality):** Claude and Codex on opposite review slots, so each
  catches what the other misses.
- **Claude-only / Codex-only:** set every role to one model — you lose cross-model
  review diversity, which is fine for routine components or when one provider is down.

**Token wall → codex-only.** Quest **already falls back cross-runtime automatically** (a
failed Claude slot retries on Codex), so hitting Claude limits mid-quest degrades rather
than dies. To switch deliberately, set the `models` map to the Codex model for all roles
(one edit) and/or run solo to cut total calls. No redesign, no re-plan — so you don't
have to improvise it under pressure.

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
Build <ID> <component> for the RepoLens repo.
- Quest creates the worktree off origin/main (quest_startup.branch_mode: worktree) —
  you don't create it manually. Preferred branch/worktree name: `<ID>__<slug>`, where
  <slug> is the first 10 characters of the component name, lowercased, spaces →
  underscores (no spaces in the ref).
- Ensure the worktree's .quest is a symlink to the gitignored RepoLens/.quest store
  (create the symlink if Quest hasn't). Write this quest's artifacts under its own
  <ID>__<slug>/ subdir so parallel quests don't collide. Because the store lives in
  RepoLens/.quest, artifacts survive worktree deletion — so an interrupted quest can be
  resumed, or handed to a different model.
- Scope/deliverable: see docs/roadmap/rpl_roadmap.md (this component's row) and
  docs/roadmap/rpl_decisions.md.
- Acceptance: the rpl_roadmap M<n> criteria for this component, plus every applicable
  canary in docs/roadmap/rpl_security.md is green.
- Hard rules: orchestrate, don't reimplement scanners; security guardrails are
  mandatory; no owner/repo/company names in code, tests, or docs (CI hygiene guard);
  owner is a runtime input only. Public CI proves the hygiene guard with invented
  sentinel names only; real denylist values live in gitignored local config.
- Output: code + tests + the component's canaries wired into CI.
- On completion (in order):
  A. Rebase onto the latest origin/main and resolve conflicts — auto-resolve where it's
     unambiguous; ask the human only if a conflict genuinely needs judgment. Always do
     this first so B–E land on the latest.
  B. Tick THIS component's delivery box in docs/roadmap/rpl_roadmap.md. Mark nothing you
     did not do yourself — be accurate.
  C. Create the PR with pr-assistant, then mark it ready-to-review. You have permission;
     don't ask.
  D. Ping the human that the PR is ready to review.
  E. Celebrate, archive, and journal the quest.
```

## Quest placement — worktrees off main, shared gitignored `.quest`

Quests run in **git worktrees created off `origin/main`** of the RepoLens repo
(Quest creates them natively — `quest_startup.branch_mode: worktree`). Each
worktree's `.quest` is a **symlink to one gitignored `RepoLens/.quest`** artifact store,
namespaced per quest (`<ID>__<slug>/`). Consequences:

- **Product-only repo.** `.quest` is gitignored, so no Quest scaffolding ever enters
  history or a public tree — the committed repo stays clean.
- **Durable artifacts.** Centralized in `RepoLens/.quest`, they **survive worktree
  deletion**, so an interrupted quest can be **resumed — or handed to a different model**
  even if the original agent is unavailable.
- **Safe parallelism.** Many worktrees symlink to the same store; each writes under its
  own `<ID>__<slug>/` subdir, so concurrent quests don't collide.

Runtime-only local config follows the same placement rule. Put private name-hygiene
values in the main checkout's gitignored `.name-hygiene.local.json`, not in a specific
worktree. The leading dot is intentional so the private denylist is not visible in a
normal directory listing. The guard discovers that file from the scan root upward and,
for linked worktrees, checks the checkout that owns the shared `.git` directory. This
keeps public CI repo-agnostic while letting local checks enforce real
owner/repo/company names.
