# How RepoLens works — a visual walkthrough

RepoLens is a **license-disclosure orchestrator**. You point it at an owner; it inventories
every dependency your repositories ship, resolves each license from the cheapest trustworthy
source, flags anything risky or unknown, settles the leftovers against *fetchable* evidence
under human approval, and assembles one clean, deduplicated disclosure report.

This page is the **picture-first** tour. It does not reinvent scanners — it **conducts**
them. If you want the exact commands and flags, see **[usage.md](usage.md)**; for the design
rationale and security model, see the **[roadmap docs](roadmap/rpl_README.md)**.

---

## The whole pipeline at a glance

Six stages, run left to right. Each stage reads and writes plain JSON/NDJSON on disk, so any
stage can be re-run or resumed on its own. You approve twice — once for the repo list, once
for the shortlist — and the final report is gated on a clean shortlist.

```
      ┌────────────────────────────────────────────────────────┐
      │                   you approve twice                    │
      │ (1) the repo list                    (2) the shortlist │
      ▼                                                        ▼
 ┌──────────┐   ┌────────┐   ┌──────────┐   ┌────────┐   ┌───────────┐   ┌────────┐
 │ discover │──▶│  scan  │──▶│ resolve  │──▶│  flag  │──▶│ shortlist │──▶│ report │
 └────┬─────┘   └───┬────┘   └────┬─────┘   └───┬────┘   └─────┬─────┘   └───┬────┘
      │             │             │             │              │             │
   gh repo       git clone     license       SPDX norm     verify-first   gate on
  list / view   (hardened)*    ladder:       + policy      evidence +     0 open
  + taxonomy    + Syft SBOM    APIs first,    tiers +       human          findings,
   classify     per repo       ScanCode last  dedup         approval       then render
      │             │             │             │              │             │
      ▼             ▼             ▼             ▼              ▼             ▼
  discovered    work/<repo>/  work/<repo>/  inventory.json shortlist.json reports/
    .json       sbom.syft     resolved      shortlist.json shortlist.md   report.main.*
  repos          .json        .ndjson       shortlist.md   (+ contexts/   report.present.*
  .candidate.md                                            proposals/     report.appendix.*
                                                           evidence)      (+ .docx)
```

**Legend** — `┌─┐` boxes are pipeline stages · the middle row is *what each stage does and
which tools/endpoints it calls* · the bottom row is *the artifacts it leaves on disk* for the
next stage (and for you) to read.

\* **Not a full clone.** `scan` does a *hardened, sparse + partial* checkout — only dependency
manifests, lockfiles, `.gitmodules`, and `LICENSE`/`COPYING` files are written to disk (git hooks,
symlinks, and `file://` access are disabled), so none of the repo's source code runs or even lands
locally. Detail in **Stage 2** below.

**SPDX** — the industry-standard catalog of short license identifiers (`MIT`, `Apache-2.0`,
`GPL-3.0-only`, and so on). "Normalize to SPDX" means mapping whatever license string a tool
reports onto that one canonical id, so every source can be compared apples-to-apples; an "SPDX
expression" is a compound like `Apache-2.0 OR MIT`.

The fastest way to run all of this is one command:

```bash
repolens run --work-root work --owner <OWNER>
```

`run` walks the same six stages and stops at the human checkpoints. Everything below is what
happens inside it.

---

## What RepoLens builds vs. what it conducts

The "smart" part is never a scanner — it is the **workflow, policy, evidence, and report**
wrapped around trusted tools.

```
 ┌─────────────────────────────┐        ┌────────────────────────────────────────┐
 │ RepoLens builds             │        │ RepoLens conducts (never trusts blind) │
 ├─────────────────────────────┤        ├────────────────────────────────────────┤
 │ • the CLI + stage pipeline  │ ─────▶ │ • gh, git            (discover, clone) │
 │ • the resolution ladder     │        │ • Syft               (SBOM inventory)  │
 │ • policy engine (SPDX norm, │        │ • ScanCode           (deep detection)  │
 │   compound exprs, tiers)    │        │ • deps.dev / registry / GitHub /       │
 │ • tagging, dedup, category  │        │   ClearlyDefined / ecosyste.ms (APIs)  │
 │ • evidence model + verify   │        │ • AboutLibraries, LicensePlist         │
 │ • report views + docx       │        │   (mobile, sandboxed, opt-in)          │
 │ • security primitives       │        │ • cosign             (tool integrity)  │
 └─────────────────────────────┘        └────────────────────────────────────────┘
```

Every conducted tool is **acquired and integrity-verified** from a pinned manifest
(`src/repolens/bootstrap/pins.toml`: exact versions + sha256, cosign-verified) rather than
trusting whatever happens to be on the machine.

---

## Stage 1 — `discover`: which repos, and what kind?

You give it an owner (or an explicit repo-name list). It asks GitHub what exists, classifies
each repo from your local taxonomy config, hard-excludes archived/dead/`internal-*` repos
with a **visible reason**, and writes a checklist for you to approve.

```
   --owner <OWNER>                      taxonomy (local, untracked):
        │                                 explicit / patterns / topics
        ▼                                 exclude_patterns / dead
 ┌─────────────────┐   gh repo list   ┌──────────────────────────┐
 │     discover    │                  │ classify + hard-exclude  │
 └─────────────────┘   gh repo view   └────────────┬─────────────┘
                                                   ▼
                            discovered.json   (structured, for later stages)
                            repos.candidate.md  ← YOU untick anything you don't want
```

> **Human checkpoint #1.** `repos.candidate.md` is yours to edit. Candidates default to
> checked; untick to exclude. A re-run won't clobber your edits unless you pass `--force`.

---

## Stage 2 — `scan`: hardened clone + Syft → one SBOM per repo

For each approved repo, RepoLens clones **read-only and sandboxed** and runs Syft to produce
a Software Bill of Materials. No code from the scanned repo ever executes.

```
  approved repos
       │
       ▼
 ┌───────────────────────────────────────────────┐
 │ scan  (in-process, per repo)                  │  no secrets in child env
 │  • partial + sparse clone: manifests,         │  hooks/symlinks/file:// off
 │    lockfiles, .gitmodules, LICENSE/COPYING    │  ephemeral workdir, always cleaned
 │  • separate clone + Syft wall-clock timeouts  │
 │  • Syft = static inventory, never builds      │
 └───────────────────────┬───────────────────────┘
                         ▼
         work/<repo>/sbom.syft.json     ← canonical dependency inventory
         work/<repo>/scan.status.json   ← per-repo status (for resume)
```

**Resume** is conservative: a repo is "done" only when its `sbom.syft.json` exists *and*
passes schema validation. Crash mid-run? Re-run — finished repos are skipped.

Syft catalogs cargo, cocoapods, go-module, maven, npm, nuget, pypi, rubygems, swift, and
GitHub Actions. (Build/CI packages are inventoried but routed to an appendix, never the
shipped main report.)

---

## Stage 3 — `resolve`: the cheapest-source-first license ladder

This is the heart of the "smart" part. Every dependency gets its license from the **first
layer that succeeds**, and each records *where the answer came from* as evidence. Cheap,
no-clone sources run first so the expensive/human work shrinks to the smallest possible set.

```
        a dependency from the SBOM (license unknown or uncertain)
                                  │
                                  ▼
   0 ┌─────────────────────────────────────────────────┐  cheap
     │ Syft declared metadata                          │  already in the SBOM
     └────────────────────────────┬────────────────────┘
                                  │ miss
                                  ▼
   1 ┌─────────────────────────────────────────────────┐  cheap · NO clone
     │ free license APIs, in precedence order:         │
     │   deps.dev                                      │  ── calls out to ──▶ deps.dev
     │     → native registry (npm, PyPI, Crates,       │  npmjs / pypi / crates.io /
     │       RubyGems, NuGet, Maven, Go proxy,         │  rubygems / nuget / maven /
     │       CocoaPods trunk, SwiftPM GitHub pins)     │  proxy.golang / cocoapods
     │       → GitHub License API                      │  api.github.com/.../license
     │         → ClearlyDefined → ecosyste.ms          │  clearlydefined / ecosyste.ms
     └────────────────────────────┬────────────────────┘
                                  │ miss
                                  ▼
   2 ┌─────────────────────────────────────────────────┐  medium · sandboxed · opt-in
     │ mobile native enrichment (auto-detected only)   │  AboutLibraries / LicensePlist,
     │ metadata/API by default                         │  the one execution-bearing step
     └────────────────────────────┬────────────────────┘
                                  │ miss
                                  ▼
   3 ┌─────────────────────────────────────────────────┐  expensive
     │ ScanCode on the remaining unknowns              │  scoped to a single package dir /
     │                                                 │  LICENSE* files, never the whole repo
     └────────────────────────────┬────────────────────┘
                                  │ still unknown / risky
                                  ▼
   4 ┌─────────────────────────────────────────────────┐  human
     │ evidence-anchored shortlist (Stage 5)           │  flagged items only — never guessed
     └─────────────────────────────────────────────────┘
                                  │
                                  ▼
                 work/<repo>/resolved.ndjson
                 (one line per dependency: license + evidence source + tags)
```

A **string→SPDX normalization** pass runs before any policy lookup. By default the ladder
stops at the first verified API source; `resolve --detect-conflicts` instead cross-checks
every API adapter and demotes any verified disagreement to `CONFLICT` for human review.

---

## Stage 4 — `flag`: policy + tagging + dedup → inventory & shortlist

`flag` turns raw resolved lines into a **deduplicated, tagged, policy-scored** dataset, and
splits off the items that need a human.

```
  work/<repo>/resolved.ndjson (all repos)
            │
            ▼
 ┌─────────────────────────────────────────────────┐
 │ flag                                            │
 │  • normalize SPDX → apply license-policy tiers  │  tiers: permissive / copyleft /
 │    (risk classification)                        │  network-copyleft / non-commercial /
 │  • tag each component:                          │  source-available …
 │      origin · scope · distribution              │
 │  • dedup → one row per (name, normalized-SPDX)  │  keeps found_in[], versions seen,
 │    with provenance                              │  source_url, modified?
 └───────────────┬───────────────────────┬─────────┘
                 ▼                       ▼
         inventory.json            shortlist.json + shortlist.md
       (full tagged dataset       (the open BLOCK / REVIEW / UNKNOWN queue —
        behind every report)       what still needs evidence or judgment)
```

Re-running `flag` after a ScanCode/resolver retry **preserves** decisions you already made
for matching rows, and only re-opens findings that genuinely changed.

---

## Stage 5 — `shortlist`: verify-first evidence, then human approval

The leftovers from the ladder land here. RepoLens **never asks a model to decide** and never
trusts a proposal — it re-fetches and verifies every cited URL itself, then a human approves.

```
 flag leaves open items ─────────▶ shortlist.json + shortlist.md
            │
            │  repolens shortlist --emit-contexts
            ▼
   shortlist.contexts.json
   (each open item's untrusted text — LICENSE / README / description / evidence —
    is capped, NFC-normalized, and screened for injection markers.
    These are request *shapes* only: no shell, no secrets, no paths, no callables.
    RepoLens itself calls no model.)
            │
   ┌────────┴───────────────────────────────┐
   ▼                                          ▼
 deterministic research               external AI assistant
 `repolens shortlist research`        (the bundled `$repolens` skill)
 (public metadata lookups,            reads contexts, looks up public
  no model)                           evidence, writes the same artifacts
   │                                          │
   └───────────────────┬──────────────────────┘
                       ▼
   shortlist.proposals.json   (component_ref, spdx_id, evidence_url,
   shortlist.evidence.json     evidence_anchor, disposition, confidence,
                               rationale, sanity_check — all metadata only)
                       │  repolens shortlist --proposals --evidence
                       ▼
   ┌───────────────────────────────────────────────────────────┐
   │ VERIFY, don't trust                                       │
   │  • schema-validate the artifact (fail-closed)             │
   │  • re-fetch each citation through the SSRF-guarded,       │
   │    allowlisted HTTP client                                │
   │  • require an EXACT SPDX anchor match                     │
   │  bad / off-allowlist / mismatched / low-confidence /      │
   │  abstained  ⇒  the item stays OPEN                        │
   └───────────────────────────┬───────────────────────────────┘
                               ▼
   grouped review surface in shortlist.md:
     ┌────────────────────┬───────────────────────┬──────────────────────────┐
     │ ACCEPT-RECOMMENDED │ NEEDS-JUDGMENT        │ LOW-CONFIDENCE / CONFLICT│
     │ verified allow,    │ real block/review or  │ abstentions, conflicts,  │
     │ low-risk class     │ mixed-risk; group +   │ verify failures, invalid │
     │ (group checkbox)   │ drill-in per item     │ proposals (per item)     │
     └─────────┬──────────┴───────────┬───────────┴────────────┬─────────────┘
               └────────────── you tick [x] approve / [r] reject ────────────┘
                               │
                               ▼
   decisions recorded (status, decided_by, decided_at, decided_via, provenance)
   shortlist exits 0 only when NOTHING is left open ── this gates the report.
```

> **Human checkpoint #2.** You make the call in `shortlist.md`. RepoLens guarantees the
> evidence behind each proposal is real and fetchable before you ever see it; unpinned
> default-branch evidence (e.g. a GitHub License API answer on a repo's default branch) is
> accepted only when provenance binds it, and is **labelled `review:`** so you can see exactly
> what is less certain.

---

## Stage 6 — `report`: gated, deduplicated disclosure (a *set* of views)

The report only renders when the shortlist is clean. It is not one file — it is a **set** of
views over the same gated dataset, driven by category selection.

```
 inventory.json + resolved + discovered categories + local report config
            │
            ▼
   ┌────────────────────────────────────────────┐
   │ GATE: shortlist.json has 0 open items?     │  ── no ──▶ exit 1, write NOTHING
   └───────────────────┬────────────────────────┘
                       │ yes
                       ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │ report.main.{md,csv,html}        the shipped disclosure (one row    │
   │                                  per library, nothing silently      │
   │                                  dropped; rejected items excluded)  │
   │ report.presentation.{md,csv,html} sibling view, grouped by exact    │
   │                                  SPDX expression                    │
   │ report.appendix.<category>.{md,csv} excluded categories + first-    │
   │                                  party + build-ci                   │
   │ report.main.docx / report.presentation.docx   optional shareable    │
   │                                  cover (from report.header config   │
   │                                  or an interactive prompt)          │
   └─────────────────────────────────────────────────────────────────────┘
```

Re-scoping which categories ship is **config + re-render, never a re-scan**. An optional
`repolens report review` step lets a human pick the disclosure wording for compound/`OR`
license expressions before the presentation artifacts are finalized — without touching the
raw detected SPDX in the main report.

---

## The artifacts, end to end

Everything lives under a gitignored work root. Each stage's output is the next stage's input —
and your audit trail.

```
 work/
 ├─ discovered.json                 # discover: structured repo list + categories
 ├─ repos.candidate.md              # discover: YOUR approval checklist (checkpoint #1)
 ├─ work/<repo>/sbom.syft.json      # scan:     canonical Syft SBOM, per repo
 ├─ work/<repo>/scan.status.json    # scan:     per-repo status (resume)
 ├─ work/<repo>/resolved.ndjson     # resolve:  license + evidence source + tags, per dep
 ├─ inventory.json                  # flag:     deduped, tagged, full dataset
 ├─ shortlist.json                  # flag:     canonical open-items queue
 ├─ shortlist.md                    # flag/shortlist: grouped review surface (checkpoint #2)
 ├─ shortlist.contexts.json         # shortlist: sanitized, model-free request shapes
 ├─ shortlist.proposals.json        # shortlist: external proposals (validated, then verified)
 ├─ shortlist.evidence.json         # shortlist: researched browser evidence (validated)
 ├─ report.review.json / .md        # report:   optional disclosure-license review decisions
 ├─ tool_versions.json              # bootstrap: resolved + verified tool versions/digests
 └─ reports/
    ├─ report.main.{md,csv,html}        # the gated shipped disclosure
    ├─ report.presentation.{md,csv,html}# sibling view, grouped by SPDX
    ├─ report.*.docx                     # optional shareable Word output
    └─ report.appendix.<category>.{md,csv}
```

Every disk read enforces a byte cap and schema-validates before returning; every write redacts
GitHub-token-shaped strings, validates, and atomically replaces the file.

---

## The trust model in one breath

```
 read-only against your code   ·   no install/build scripts ever run
 conducted tools are pinned + cosign-verified before they execute
 external proposal contexts carry no shell / secrets / paths / callables
 RepoLens calls no model — it VERIFIES every cited URL itself before a human approves
 a sanity "watermark" canary fails the run loudly if an expected dependency goes missing,
   so "0 findings" means clean, not broken
```

---

## Where to go next

- **Run it** → [usage.md](usage.md) — every command, flag, and config key.
- **Why it's built this way** → [roadmap/rpl_architecture.md](roadmap/rpl_architecture.md),
  [roadmap/rpl_decisions.md](roadmap/rpl_decisions.md).
- **Security guarantees** → [roadmap/rpl_security.md](roadmap/rpl_security.md).
- **License policy tiers** → [roadmap/rpl_license-policy.md](roadmap/rpl_license-policy.md).
- **Artifact schemas** → [data-model.md](data-model.md).
