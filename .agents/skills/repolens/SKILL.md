---
name: repolens
description: Use when the user invokes $repolens or asks to run a RepoLens disclosure / resolve flagged licenses.
---

# RepoLens Runbook

Use this skill when a RepoLens run has open shortlist items or when an operator asks for
AI-assisted license shortlist triage. RepoLens itself must never invoke a model. The AI
role is proposal-only: read emitted context artifacts, write proposal artifacts, and let
RepoLens re-fetch and verify every cited URL before a human approves anything.

## Non-negotiables

- RepoLens does not call a model, shell out to a model, or auto-approve proposals.
- Never invent evidence URLs. Use only URLs present in the context/triage data or abstain.
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

6. External AI proposal pass:

Read `work/shortlist.contexts.json`. For each row, inspect only `component_ref`,
`wrapped_context`, and read-only `triage`. Write `work/shortlist.proposals.json` as a JSON
array. Use the schema in `reference/proposal-schema.md`.

Run a BLOCK sanity pass before writing the file:

- Any proposal that clears GPL, LGPL, AGPL, SSPL, BUSL, Elastic, PolyForm, Prosperity, NC,
  or similar shipped/distributed risk must be downgraded to abstain unless the case is
  plainly non-distributed and still needs human review.
- Any proposal with missing evidence, a fabricated URL, or a mismatched anchor must
  abstain.
- Conflicts and low confidence stay for human judgment.

7. Ingest proposals through RepoLens verification:

```bash
repolens shortlist --work-root work --proposals work/shortlist.proposals.json
```

RepoLens re-fetches every cited URL through its allowlisted HTTP client and checks the
exact SPDX anchor. Verified proposals remain open until human approval.

8. Human grouped approval loop:

Open `work/shortlist.md`. It has three tiers:

- `ACCEPT-RECOMMENDED`: bulk checkbox is available only when all members are verified
  allow and low-risk.
- `NEEDS-JUDGMENT`: group approve/reject checkbox plus per-item rows for block/review
  or mixed-risk exceptions.
- `LOW-CONFIDENCE / CONFLICT`: per-item only.

Mark `[x]` to approve or `[r]` to reject. Item `rpl:ref` decisions override group
`rpl:group` decisions. Do not edit markers. Re-run:

```bash
repolens shortlist --work-root work --identity <REVIEWER>
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
an optional external proposal pass to `work/shortlist.proposals.json`, ingests proposals if
that file exists, renders grouped `work/shortlist.md`, and loops until no item is open.

For automation:

```bash
repolens run --work-root work --owner <OWNER> --out-dir reports --yes
```

`--yes` does not approve findings, does not run an AI proposal pass, and does not write a
report while shortlist items remain open.
