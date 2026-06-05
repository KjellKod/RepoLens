---
name: repolens
description: Run RepoLens end to end and review open license shortlist items by looking up verifiable evidence, producing external proposal artifacts, and keeping RepoLens model-free, verify-first, and human-approved.
---

# RepoLens Runbook

Use this skill when a RepoLens run has open shortlist items or when an operator asks for
AI-assisted license shortlist triage. RepoLens itself must never invoke a model. The AI
role is proposal-only: read emitted context artifacts, look up public registry evidence,
write proposal and review-note artifacts, and let RepoLens re-fetch and verify every cited
URL before a human approves anything.

## Non-negotiables

- RepoLens does not call a model, shell out to a model, or auto-approve proposals.
- Never invent unsupported evidence. You may construct deterministic package metadata URLs
  only for RepoLens-verifiable hosts, then fetch/inspect them before proposing a change.
- Abstain when unsure, when evidence is missing, or when the context is contradictory.
- Genuine shipped copyleft or source-available BLOCK risk is never the AI's to clear.
- Proposal `disposition`, `confidence`, `rationale`, and `sanity_check` are metadata only.
- Humans approve or reject in `shortlist.md`; RepoLens verifies citations first.

## End-to-end flow

1. Discover:

```bash
repolens discover --owner <OWNER> --work-root work
```

Review `work/repos.candidate.md`, untick repos that should not be scanned, then continue.

2. Scan:

```bash
repolens scan --work-root work
```

3. Resolve:

```bash
repolens resolve --work-root work
```

4. Flag:

```bash
repolens flag --work-root work
```

5. Emit external proposal contexts:

```bash
repolens shortlist --work-root work --emit-contexts work/shortlist.contexts.json
```

6. Deterministic research or external assistant pass:

Read `work/shortlist.contexts.json`. For each row, inspect only `component_ref`,
`wrapped_context`, and read-only `triage`. Review every row, not only the easy ones. For
each item, either propose a verified correction, confirm the existing finding needs human
judgment, or abstain because evidence is missing/contradictory.

Before writing artifacts, load these references from the RepoLens repository root:

- `.skills/repolens/reference/evidence-lookup.md` for the per-item lookup workflow and
  allowed evidence hosts.
- `.skills/repolens/reference/proposal-schema.md` and
  `src/repolens/data/schemas/shortlist_proposals.schema.json` for the output contract.
- `src/repolens/data/schemas/shortlist_evidence.schema.json` for the evidence contract.
- `.skills/repolens/reference/triage-cheatsheet.md` when judging distribution/scope risk.

Prefer the product-owned deterministic research command when a work root has contexts:

```bash
repolens shortlist research --work-root work \
  --contexts work/shortlist.contexts.json \
  --proposals work/shortlist.proposals.json \
  --evidence work/shortlist.evidence.json \
  --review work/shortlist.review.md
```

It writes machine-verifiable allow proposals only when deterministic public metadata can
be re-fetched by RepoLens. It writes `work/shortlist.evidence.json` for every row with one
explicit outcome: `machine_verified`, `pending_verifier_support`, `no_public_evidence`,
`conflict`, or `legal_or_vendor_review`. It also writes `work/shortlist.review.md` with
one compact row per context row, direct short-label evidence links or lookup trails, and
outcome counts.
For compatibility with older artifact workflows, `.skills/repolens/scripts/generate_shortlist_proposals.py`
can still generate proposal artifacts from an existing contexts file.
For one-off evidence debugging, use
`.skills/repolens/scripts/inspect_evidence.py` with exact allowlisted evidence URLs.

Run a BLOCK sanity pass before writing the file:

- Any proposal that clears GPL, LGPL, AGPL, SSPL, BUSL, Elastic, PolyForm, Prosperity, NC,
  or similar shipped/distributed risk must be downgraded to abstain unless the case is
  plainly non-distributed and still needs human review.
- Any proposal with missing evidence, a fabricated URL, or a mismatched anchor must
  abstain.
- Conflicts and low confidence stay for human judgment.
- Private commercial licenses, private contract proof, or local business knowledge cannot
  be encoded as verified public evidence. Note those cases in `shortlist.review.md` and
  leave the proposal abstained.

7. Ingest proposals and evidence through RepoLens verification:

```bash
repolens shortlist --work-root work \
  --proposals work/shortlist.proposals.json \
  --evidence work/shortlist.evidence.json
```

RepoLens re-fetches supported proposal citations through its allowlisted HTTP client and
checks the exact SPDX anchor. Verified proposals remain open until human approval.
Research evidence is preserved separately, including browser evidence whose verifier
support is pending. Evidence ingestion never approves, rejects, or clears an item.

8. Human grouped approval loop:

Open `work/shortlist.md`. It has three tiers:

- `ACCEPT-RECOMMENDED`: bulk checkbox is available only when all members are verified
  allow and low-risk.
- `NEEDS-JUDGMENT`: group approve/reject checkbox plus per-item rows for block/review
  or mixed-risk exceptions.
- `LOW-CONFIDENCE / CONFLICT`: per-item only.

Mark `[x]` to approve or `[r]` to reject. Item `rpl:ref` decisions override group
`rpl:group` decisions. Do not edit markers. Re-run. RepoLens records `decided_by` from the
logged-in OS user by default; `--identity <REVIEWER>` is only an override:

```bash
repolens shortlist --work-root work
```

Repeat proposal ingestion and human review until `shortlist.json` has `open_count == 0`.

9. Report:

```bash
repolens report --work-root work --out-dir reports
```

## One-command run

For normal operation:

```bash
repolens run --work-root work --owner <OWNER> --out-dir reports
```

When open shortlist items remain, `run` emits `work/shortlist.contexts.json`, pauses for
an optional research pass to `work/shortlist.proposals.json`,
`work/shortlist.evidence.json`, and `work/shortlist.review.md`, ingests proposals/evidence
if those files exist, renders grouped `work/shortlist.md`, and loops until no item is open.

For automation:

```bash
repolens run --work-root work --owner <OWNER> --out-dir reports --yes
```

`--yes` does not approve findings, does not run an AI proposal pass, and does not write a
report while shortlist items remain open.
