# Evidence Lookup Workflow

Use this reference when producing `shortlist.proposals.json` from
`shortlist.contexts.json`.

Prefer running the deterministic helper from the repository root:

```bash
PYTHONPATH=src python3 .skills/repolens/scripts/generate_shortlist_proposals.py \
  --work-root <WORK>
```

For debugging an individual metadata URL and seeing what RepoLens extracts, run:

```bash
PYTHONPATH=src python3 .skills/repolens/scripts/inspect_evidence.py <URL> [...]
```

## Goal

For every context row, choose exactly one outcome:

- `proposed`: public, allowlisted evidence supports a specific SPDX id for the exact
  package/version.
- `confirmed-needs-review`: evidence confirms the current flagged license or confirms a
  copyleft/source-available risk that a human must decide.
- `abstained`: evidence is missing, contradictory, not allowlisted, private, or not exact
  to the package/version.

The JSON artifact can only express `proposed` or `abstained`. Put the richer outcome and
reasoning in `work/shortlist.review.md`.

## Evidence Hosts RepoLens Can Verify

Proposal `evidence_url` values must use hosts from RepoLens's resolver allowlist. Prefer:

- `https://api.deps.dev/v3alpha/...`
- `https://registry.npmjs.org/...`
- `https://pypi.org/pypi/.../json`
- `https://crates.io/api/v1/crates/...`
- `https://proxy.golang.org/...`
- `https://repo.maven.apache.org/maven2/...`
- `https://api.clearlydefined.io/definitions/...`
- `https://api.ecosyste.ms/packages/lookup?...`

Do not cite package homepages, raw GitHub files, vendor marketing pages, or private
commercial-license records in `shortlist.proposals.json`; RepoLens will not verify them as
proposal evidence. Mention useful non-verifiable context only in `shortlist.review.md`.

## Per-Item Process

1. Extract package name, ecosystem, version, current license, distribution, scope, and
   source/evidence hints from the context row.
2. Check the exact package/version through the preferred metadata source for that ecosystem.
3. Inspect the fetched response for a target-package license field, not dependency or
   repository-neighbor text.
4. If the fetched evidence clearly anchors one SPDX id or SPDX expression for that exact
   version, write a proposal with that `spdx_id`, `evidence_url`, and exact
   `evidence_anchor`.
5. If the fetched evidence confirms a risky current license, abstain and note
   `confirmed-needs-review`.
6. If evidence is missing, versionless, contradictory, or only supports a different major
   package/version, abstain.

## URL Patterns

- npm:
  `https://registry.npmjs.org/<package>/<version>`
  Use `%2F` for scoped package slashes, for example `@scope%2Fname`.
- PyPI:
  `https://pypi.org/pypi/<package>/<version>/json`
- deps.dev:
  `https://api.deps.dev/v3alpha/systems/<system>/packages/<encoded-package>/versions/<version>`
  Common systems: `npm`, `pypi`, `cargo`, `maven`, `go`, `nuget`, `rubygems`.
- Go module proxy:
  `https://proxy.golang.org/<module>/@v/<version>.info`
  Use this for module/version existence only unless it exposes a license anchor; prefer
  deps.dev or clearlydefined for license evidence.

## Important Cases

- If an item is `UNKNOWN` because an API lookup missed a Go semantic import suffix, try
  deps.dev with the full module path including `/v2`, `/v3`, `/v4`, etc.
- If the package has changed licenses across major versions, only use evidence for the
  exact version in the context. Do not apply a current website license to older installed
  versions.
- If the company has a private commercial license, the proposal artifact cannot prove that.
  Abstain and tell the operator to record the private-license decision in `shortlist.md` /
  internal records.
- For GPL/LGPL/AGPL/SSPL/BUSL/Elastic/PolyForm/NC findings in shipped runtime code, do not
  turn a verified risky license into `allow`; record that the evidence was checked and
  leave it for human/legal judgment.

## Review Note Format

Use a compact Markdown table:

| component_ref | outcome | evidence checked | recommendation |
| --- | --- | --- | --- |
| `pkg|UNKNOWN` | proposed | deps.dev exact version shows `MIT` | Proposal changes to `MIT`; rerun shortlist ingestion. |

Keep notes factual and short. Do not include secrets, local filesystem paths outside the
work root, or long copied license text.
