# Human License Overrides

## Problem

RepoLens has a safe path for automatic and AI-assisted corrections: resolver output and
`shortlist.proposals.json` must cite evidence that RepoLens can independently fetch and
verify. That is the right default, but it leaves an operator stuck when they know the
correct license and can cite a reasonable source, while RepoLens cannot verify that source
with its current adapters.

Examples:

- A package registry page or project page clearly states the license, but the resolver does
  not yet support that field or host.
- A commercial license, internal agreement, or vendor email controls usage, and public
  metadata is incomplete or stale.
- A package has a known SPDX license such as `ZPL-2.1`, but the current artifact still shows
  `UNKNOWN` until resolver support catches up.

Editing `shortlist.md` should not be used for this. The checklist is for approval or
rejection of existing findings, not for changing license facts. Editing `shortlist.json`
directly is also not a durable workflow because later stages can rewrite it.

## Goals

- Let a human provide a deliberate license correction without pretending RepoLens resolved
  it automatically.
- Keep the override local, untracked, auditable, and explicit.
- Validate the override shape, SPDX value, component identity, and required rationale.
- Preserve existing trust boundaries: owner/repo inputs remain runtime input, local config
  remains local, and RepoLens must not invent policy or license values silently.
- Make report output distinguish human overrides from resolver evidence.

## Non-Goals

- Do not make policy runtime-configurable through overrides.
- Do not silently approve a risky license just because it was manually overridden.
- Do not store organization, owner, or repo discovery inputs in the override artifact.
- Do not treat unverified public URLs as equivalent to resolver-verified evidence.

## Proposed Artifact

Add a local artifact such as:

```text
<WORK>/shortlist.overrides.json
```

Suggested schema:

```json
[
  {
    "component_ref": "zope.site|UNKNOWN",
    "spdx_id": "ZPL-2.1",
    "evidence_url": "https://pypi.org/project/zope.site/",
    "evidence_note": "PyPI project page identifies the package license as ZPL-2.1.",
    "reason": "Correcting stale UNKNOWN resolver output after manual review.",
    "decided_by": "kjell"
  }
]
```

Required fields:

- `component_ref`: exact current shortlist component reference.
- `spdx_id`: SPDX ID or supported expression accepted by RepoLens policy normalization.
- `reason`: short human rationale.
- `decided_by`: local reviewer identity or handle.

Optional fields:

- `evidence_url`: public or private reference URL.
- `evidence_note`: short human-readable evidence summary.
- `expires_at`: optional date for temporary or contract-based decisions.

## Validation Rules

`repolens shortlist --overrides <path>` should:

- Validate that the JSON root is an array and reject unknown keys.
- Require every `component_ref` to match an open or existing shortlist item exactly.
- Require `spdx_id` to normalize through the policy engine.
- Classify the resulting license through the existing policy tiers.
- Keep `BLOCK` or `REVIEW` overrides open for explicit human approval unless the override
  also supplies an approved decision in a separate, explicit field.
- Preserve `evidence_url` and `evidence_note`, but mark them as human-supplied unless they
  pass the existing verifier.
- Reject duplicate overrides for the same `component_ref` unless a deterministic conflict
  rule is defined.

## Ingestion Behavior

When an override is valid:

- Update the matching shortlist item with `candidate_spdx` and evidence metadata.
- Set provenance fields such as:

```json
{
  "decision_provenance": "human_override",
  "override_reason": "Correcting stale UNKNOWN resolver output after manual review.",
  "override_evidence_verified": false
}
```

- Leave approval state separate from license correction state. A corrected permissive license
  can become an `accept-recommended` item, but a human still needs to approve it unless the
  product explicitly supports a combined correction plus approval action.
- Keep changed or unmatched items open instead of carrying stale approval.

## CLI UX

Possible commands:

```bash
repolens shortlist --work-root <WORK> --overrides <WORK>/shortlist.overrides.json
repolens shortlist overrides schema
repolens shortlist overrides validate <path> --work-root <WORK>
```

`shortlist` output should mention this path when open `UNKNOWN` items remain:

```text
Manual license corrections:
  If you know a license that RepoLens cannot verify yet, create:
    <WORK>/shortlist.overrides.json
  Validate and ingest it with:
    repolens shortlist --work-root <WORK> --overrides <WORK>/shortlist.overrides.json
```

## Reporting

Reports should distinguish:

- Resolver evidence: fetched and verified by RepoLens.
- Proposal evidence: fetched and verified during proposal ingestion.
- Human override: supplied by a named reviewer, possibly with unverified evidence.

Main and appendix rows could include a `provenance` or `evidence_status` value such as
`human_override_unverified` so legal/compliance review can see what still depends on human
attestation.

## Open Questions

- Should human overrides be allowed to approve permissive `ALLOW` items in the same artifact,
  or should approval always remain a checkbox/proposals step?
- Should private evidence paths be allowed, and if so how should they be redacted in reports?
- Should overrides be keyed only by `component_ref`, or also by package URL/version to survive
  a component_ref license correction?
- Should expired overrides fail the report gate or only warn?
