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

Common family boundaries:

- Keep `GPL`, `LGPL`, and `AGPL` separate.
- Keep `MPL`, `EPL`, `CDDL`, `SSPL`, `BUSL`, Apache, MIT, BSD, ISC, and Artistic separate.
- Do not clear genuine shipped copyleft based on confidence alone.
