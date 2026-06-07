---
title: Attribution / NOTICE generation
purpose: Design for turning RepoLens's verified license evidence into the attribution artifacts redistribution actually requires, and the report/review changes that support it.
audience: RepoLens maintainers and contributors
scope: Attribution bundle generation, presentation-report enrichment, and a new "attribution coverage" review lane. Excludes copyleft source-disclosure automation.
status: draft
owner: KjellKod
---

# Attribution / NOTICE generation

## Problem

RepoLens proves *which* license each component is under, with evidence. But the
obligation that actually ships with a product is not "name the license" — it is
**reproduce the required paperwork**. Today the presentation report is a disclosure /
decision document (columns: name, disclosure SPDX, detected SPDX, description, version,
source url, evidence source, notes). It does **not** emit the text a team is legally
required to redistribute. That last step — the attribution bundle — is the single most
tedious chore in the "last mile," and the one teams most often hand-assemble or skip.

The opportunity: because RepoLens already re-fetches and verifies each license against an
authoritative source (verify-don't-trust), it is uniquely positioned to generate that
bundle **from proven sources rather than scraped guesses** — every line of attribution
traceable to evidence it already fetched.

## What redistribution actually requires (obligation model)

The trigger is **distribution** (shipping a binary/container; for AGPL, also network use).
Obligations differ sharply by family:

| Family | Examples | What must be shared |
|---|---|---|
| **Permissive** | MIT, ISC | Reproduce the **copyright notice** + the **full license text** in distributed copies. |
| **Permissive (notice-heavy)** | BSD-2/3 | Copyright notice + conditions + disclaimer; BSD-3 also bars endorsement use of names. |
| **Permissive (Apache family)** | Apache-2.0 | License copy + **preserve all attribution/copyright/patent/trademark notices** + **propagate the upstream `NOTICE` file** + **state that files were changed** if modified. |
| **No-attribution** | 0BSD, CC0, Unlicense, WTFPL | Effectively nothing. |
| **Weak copyleft** | MPL-2.0, EPL, LGPL | License text **plus source availability** for covered files / relink ability. Not satisfiable by an attribution line. |
| **Strong copyleft** | GPL-2.0/3.0, AGPL-3.0 | **Complete corresponding source** under the same license; AGPL extends to network users. |

**Design consequence:** the attribution bundle satisfies the *permissive* majority in full.
Copyleft is **not** an attribution problem — it is a source-availability/policy problem.
RepoLens will **detect, label the obligation, and escalate** copyleft, never silently
"satisfy" it with a NOTICE entry.

## Scope

In scope:
- Generate a per-repo attribution artifact for permissive components from verified evidence.
- Enrich the presentation report with per-license **obligation** labels.
- Add an **attribution-coverage** review lane for components missing the data to comply.

Out of scope (this iteration):
- Automating copyleft source-disclosure (GPL/AGPL/LGPL/MPL) — flag + escalate only.
- Patent/trademark legal analysis beyond preserving notices that are present.
- Deciding dual-license selection automatically (stays a human decision; surfaced, not chosen).

## The new artifact

Primary deliverable: a generated **`THIRD-PARTY-NOTICES.md`** per repository (and an
optional plain `NOTICE` for build pipelines that expect that filename). Because it is a
redistribution artifact, the convention is to **commit it to the repo and/or bundle it in
the release** — so for org-wide runs RepoLens emits one per repo, and can optionally open a
PR to commit it (reusing existing PR tooling).

Per-component block format:

```
## <package> @ <version>
SPDX: <spdx-id>            (e.g. Apache-2.0)
Copyright: <holders>       (verbatim from the proven source; "see license text" if none separable)
Source: <verified evidence url>
Modified: <yes/no>         (Apache-2.0 change-statement; omitted for others)

<full license text, verbatim>
--- NOTICE (upstream, if present) ---
<verbatim upstream NOTICE contents>     (Apache-2.0 only, when the dependency ships one)
```

Rules:
- License **text and copyright are reproduced verbatim** from the verified source; never
  paraphrased or regenerated.
- Identical license texts are stored once and referenced, but each component still lists its
  own copyright line (dedup the body, not the attribution).
- Copyleft components are **not** emitted here; they appear in the review lane (below).

## Report changes (keep the presentation report a decision doc)

Do **not** dump license bodies into the presentation report — wrong audience, and it bloats
the grouped view. Instead, two light additions:

1. **Obligation signal** per license group (or a new `obligation` column): e.g.
   *MIT/BSD → reproduce license text*, *Apache-2.0 → + NOTICE + state changes*,
   *(A)GPL/LGPL/MPL → source-availability — review required*.
2. **Attribution-coverage flag** per component: ✅ ready / ⚠ missing data. A component is
   "ready" only when the obligation's required inputs are present (copyright holder captured
   **and** license body fetched for permissive; for copyleft, never auto-ready).

## New review lane: "attribution coverage"

Structurally identical to today's UNKNOWN queue, fail-closed by default. A component lands in
the lane when:
- it is permissive but **missing** a copyright notice or the full license text, or
- it is **copyleft** (always — requires a human source-availability decision), or
- it is **multi-licensed** and the operative choice has not been recorded.

Each lane item carries the same evidence receipts as the disclosure queue, so a reviewer
resolves it with proof, not guesswork.

## Evidence to capture (extension of verify-don't-trust)

Verification today confirms the *license identity*. To generate attribution honestly,
capture two more fields from the **same already-fetched, verified source**:
- the **copyright notice text**, and
- the **full license body**.

For example, the GitHub License API response already returns the license body; a fetched
`LICENSE` file is the body itself. No new trust surface — the bundle is built only from
sources that passed the existing fail-closed checks. If the body/copyright can't be obtained
from a verified source, the component goes to the coverage lane rather than into the bundle
with a guess.

## Risks / open questions

- **Copyright extraction accuracy.** Holders/years are inconsistently formatted upstream;
  when not cleanly separable, reproduce the full text and omit a synthesized copyright line
  rather than fabricate one.
- **Multi-license operative choice.** Needs an explicit, recorded human decision; default to
  the coverage lane.
- **NOTICE propagation (Apache-2.0).** Must fetch and reproduce the upstream `NOTICE` when
  present — another verified fetch, not an assumption.
- **Bundle size / churn.** Committed `THIRD-PARTY-NOTICES.md` can be large and noisy in
  diffs; consider stable ordering + body dedup to keep diffs meaningful.
- **SaaS vs distribution.** Obligation triggers differ; the report should not imply a
  distribution obligation exists if the artifact is never conveyed (future refinement).

## Suggested phasing

1. Capture license body + copyright in the verified evidence (data layer only; no output).
2. Add the obligation label + coverage flag to the presentation report.
3. Generate `THIRD-PARTY-NOTICES.md` for permissive components from captured evidence.
4. Add the attribution-coverage review lane (copyleft + gaps + multi-license).
5. Optional: per-repo PR to commit the generated bundle on org-wide runs.
