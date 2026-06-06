# GitHub License API download_url verification

Issue: https://github.com/KjellKod/RepoLens/issues/65

## Problem

RepoLens can fetch GitHub License API responses during license research, but the shortlist
proposal verifier does not fully use the response shape. A typical response from
`https://api.github.com/repos/<owner>/<repo>/license` includes:

- `license.spdx_id`, `license.key`, and `license.name`
- base64 `content` for the license file
- `download_url` for the raw license file
- `html_url` for human review

Today, raw GitHub repository license files are blocked as primary proposal evidence except
for CocoaPods Specs podspec JSON. That is correct as a broad SSRF/provenance guardrail, but
it creates false unresolved shortlist rows when RepoLens has already fetched the GitHub
License API response and the API response itself identifies the SPDX license.

## Desired rule

Treat the GitHub License API response as the verifier source of truth when the package to
source repository binding is acceptable.

If the API response has a concrete `license.spdx_id` that is not `NOASSERTION`, RepoLens
should be able to verify a proposal against that API response. The verifier may also decode
the response `content` and check that the license text contains the expected anchor.

The `download_url` should be preserved as supporting browser evidence derived from the
already-fetched API response. Operators and external agents should not need to cite the raw
GitHub URL as the primary verifier URL.

If `license.spdx_id` is missing, `NOASSERTION`, ambiguous, or mismatched, the row should
stay open for human review. In that case RepoLens can still preserve `download_url` and
`html_url` as browser evidence.

## Guardrails

- Keep package-to-source-repo provenance checks for GitHub source repository proposals.
- Keep raw GitHub URLs blocked as arbitrary primary proposal evidence.
- Allow raw GitHub license file evidence only when it is derived from a GitHub License API
  response fetched by RepoLens.
- Keep mutable default branch evidence out of fully automatic version-bound approval unless
  the provenance model explicitly marks it as a human/external candidate.
- Fail closed when the API SPDX id and decoded license content disagree.

## Acceptance tests

- A GitHub License API response with `license.spdx_id: MIT` and a matching decoded license
  body verifies an MIT proposal.
- `license.spdx_id: NOASSERTION`, null license metadata, and missing license metadata fail
  closed.
- A mismatched proposal SPDX id fails closed.
- A package/source repository mismatch fails closed.
- A direct raw GitHub license URL remains blocked unless it is derived from the validated
  GitHub License API response path.
