# External Proposal Artifact Schema

Write `shortlist.proposals.json` as a JSON array.

The packaged JSON Schema is
`src/repolens/data/schemas/shortlist_proposals.schema.json`. It validates the
artifact container, known fields, and field types. RepoLens still parses each proposal
fail-closed so missing proposal fields remain explicit `proposal:invalid_*` reasons.

Resolution proposal:

```json
{
  "component_ref": "acme-lib|MIT",
  "spdx_id": "MIT",
  "evidence_url": "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
  "evidence_anchor": "MIT",
  "disposition": "allow",
  "confidence": 0.95,
  "rationale": "The fetched registry metadata anchors MIT for this version.",
  "sanity_check": "No BLOCK terms found in the cited evidence."
}
```

Abstention:

```json
{
  "component_ref": "acme-lib|UNKNOWN",
  "abstain": true,
  "reason": "No fetchable evidence URL in context."
}
```

Rules:

- `component_ref` must match an emitted context item exactly.
- `spdx_id`, `evidence_url`, and `evidence_anchor` must be supported by the cited evidence.
- Do not invent unsupported URLs. You may construct deterministic package metadata URLs
  from exact package/version facts only when they use RepoLens-verifiable hosts and you
  fetched/inspected the response before proposing. Abstain when evidence is absent or
  uncertain.
- `disposition`, `confidence`, `rationale`, and `sanity_check` are AI-suggested metadata
  only. RepoLens ignores them for approval and verifies the URL/anchor itself.
