# External Proposal Artifact Schema

Write `shortlist.proposals.json` as a JSON array. Browser evidence that RepoLens cannot
verify as a proposal today belongs in `shortlist.evidence.json`, not as a generic
abstention that hides the evidence.

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

Evidence row with pending verifier support:

```json
{
  "component_ref": "acme-lib|UNKNOWN",
  "context_fingerprint": "abc123def456",
  "package": "acme-lib",
  "version": "1.2.3",
  "ecosystem": "pypi",
  "found_in": ["acme-alpha"],
  "outcome": "pending_verifier_support",
  "machine_verification": "pending_verifier_support",
  "lookups_attempted": ["PyPI metadata"],
  "likely_spdx": "MIT",
  "browser_evidence": [
    {
      "label": "PyPI metadata",
      "url": "https://pypi.org/pypi/acme-lib/1.2.3/json",
      "source_type": "pypi",
      "anchor": "MIT"
    }
  ],
  "review_note": "Browser evidence found; verifier support pending."
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
- Evidence rows require stable context identity. Pending evidence needs direct HTTP(S)
  browser links with short labels, no-public-evidence needs lookup attempts, conflicts
  need all disagreeing URLs, and legal/vendor review needs a clear note.
