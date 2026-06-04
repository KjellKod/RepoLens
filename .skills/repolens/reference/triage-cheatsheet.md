# Triage Cheatsheet

Group key: `(spdx_family, distribution, scope)`.

Distribution:

- `not-distributed`: lowest distribution risk, but still needs verification and human
  approval.
- `server`: review copyleft, network copyleft, source-available, and unclear terms
  conservatively.
- `client-or-mobile`: treat copyleft and notice obligations as higher-risk.
- `unknown`: do not bulk-clear without human judgment.

Scope:

- `runtime`: shipped/executed dependency. Be conservative.
- `dev`, `build`, `test`: may be lower risk, but still cite evidence and let humans decide.
- `unknown`: keep in judgment or abstain.

Report review:

- `scope: build` with `distribution: not-distributed` belongs in the `build-ci`
  appendix, not the shipped main report or the human accept/reject shortlist. It can
  still show `UNKNOWN` and coverage gaps for visibility, but do not manufacture a
  proposal just to clear CI tools, fixtures, or bootstrap-only packages.
- When `source_url` is a `pkg:...` package URL, treat it as an identifier for
  investigation, not as verified license evidence.

Common family boundaries:

- Keep `GPL`, `LGPL`, and `AGPL` separate.
- Keep `MPL`, `EPL`, `CDDL`, `SSPL`, `BUSL`, Apache, MIT, BSD, ISC, and Artistic separate.
- Do not clear genuine shipped copyleft based on confidence alone.
