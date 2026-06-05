# Evidence Lookup Workflow

Use this reference when producing `shortlist.proposals.json`, `shortlist.evidence.json`,
and `shortlist.review.md` from `shortlist.contexts.json`.

Prefer running the deterministic product research command from the repository root:

```bash
repolens shortlist research --work-root <WORK> \
  --contexts <WORK>/shortlist.contexts.json \
  --proposals <WORK>/shortlist.proposals.json \
  --evidence <WORK>/shortlist.evidence.json \
  --review <WORK>/shortlist.review.md
```

For debugging an individual metadata URL and seeing what RepoLens extracts, run:

```bash
PYTHONPATH=src python3 .skills/repolens/scripts/inspect_evidence.py <URL> [...]
```

## Goal

For every context row, choose exactly one evidence outcome:

- `machine_verified`: public, allowlisted evidence supports a specific allow SPDX id for
  the exact package/version and can be emitted as a proposal.
- `pending_verifier_support`: direct browser evidence supports a likely SPDX id, but
  RepoLens cannot verify that source shape today.
- `no_public_evidence`: no public deterministic evidence was found; include concrete
  `lookups_attempted`.
- `conflict`: deterministic sources disagree; include all disagreeing direct URLs.
- `legal_or_vendor_review`: evidence confirms a license or vendor/legal situation a human
  must decide.

Machine-verifiable allow candidates go in `shortlist.proposals.json`. Browser evidence,
lookup trails, conflicts, and legal/vendor review outcomes go in `shortlist.evidence.json`
and `shortlist.review.md`.

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
- `https://trunk.cocoapods.org/api/v1/pods/.../specs/...`
- `https://raw.githubusercontent.com/CocoaPods/Specs/.../*.podspec.json` only when it is
  the guarded CocoaPods trunk exact-spec redirect target.
- `https://api.github.com/repos/.../license?ref=<tag-or-sha>`

Do not cite package homepages, arbitrary raw GitHub files, vendor marketing pages,
search-result pages, or private commercial-license records in `shortlist.proposals.json`;
RepoLens will not verify them as proposal evidence. Put useful direct browser evidence
that RepoLens cannot verify today in `shortlist.evidence.json` with a short label such as
`LICENSE`, `podspec`, `Package.swift`, `PyPI metadata`, `GitHub license API`, or
`vendor license page`.

## Per-Item Process

1. Extract package name, ecosystem, version, current license, distribution, scope, and
   source/evidence hints from the context row.
2. Check the exact package/version through the preferred metadata source for that ecosystem.
3. Inspect the fetched response for a target-package license field, not dependency or
   repository-neighbor text.
4. If the fetched evidence clearly anchors one allow SPDX id or supported expression for
   that exact version, write a proposal and a `machine_verified` evidence row.
5. If evidence is useful but unsupported by the verifier, write a
   `pending_verifier_support` evidence row with direct browser links.
6. If evidence confirms risky shipped/copyleft or source-available terms, write a
   `legal_or_vendor_review` evidence row and no allow proposal.
7. If evidence is missing, versionless, contradictory, or only supports a different major
   package/version, write `no_public_evidence` or `conflict` with lookup trails or URLs.

## URL Patterns

- npm:
  `https://registry.npmjs.org/<package>/<version>`
  Use `%2F` for scoped package slashes, for example `@scope%2Fname`.
- PyPI:
  `https://pypi.org/pypi/<package>/<version>/json`
- CocoaPods:
  `https://trunk.cocoapods.org/api/v1/pods/<pod>/specs/<version>`
- GitHub license API:
  `https://api.github.com/repos/<owner>/<repo>/license?ref=<tag-or-sha>`
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
| `acme-lib|UNKNOWN` | pending_verifier_support | [LICENSE](https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3) | Browser evidence found; verifier support pending. |

Keep notes factual and short. Do not include secrets, local filesystem paths outside the
work root, or long copied license text.
