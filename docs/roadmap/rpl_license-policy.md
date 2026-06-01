# Default license-risk policy

Engineering guidance to *flag* risk — not legal advice. Shipped as **versioned config**;
counsel tunes it. Every resolved license maps to one tier; the tier drives the flag,
the exit code, and whether the item lands on the human shortlist.

| Tier | Meaning | Default action |
|------|---------|----------------|
| **ALLOW** | Permissive; safe for proprietary distribution with notice | pass |
| **REVIEW** | Weak/file-level copyleft or notable obligations | flag → shortlist |
| **BLOCK** | Strong/network copyleft, non-commercial, source-available | flag → shortlist (hard) |
| **UNKNOWN** | Unfindable / `NOASSERTION` / non-SPDX / custom | flag → shortlist |

Unresolved defaults to **BLOCK until cleared** (`default_unknown_action: BLOCK`, tunable).

## Starter SPDX sets

- **ALLOW** — MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, 0BSD, Unlicense,
  CC0-1.0, Zlib, BSL-1.0, Python-2.0, PSF-2.0, BlueOak-1.0.0, Artistic-2.0, X11,
  Libpng, curl, HPND, W3C.
- **REVIEW** — LGPL-2.0/2.1/3.0 (`-only`/`-or-later`), MPL-2.0, MPL-1.1, EPL-1.0/2.0,
  CDDL-1.0, EUPL-1.2, MS-RL, MS-PL, APSL-2.0, CECILL-2.1, CC-BY-SA-4.0, CPL-1.0, IPL-1.0.
- **BLOCK** — AGPL-3.0 (`-only`/`-or-later`), GPL-2.0/3.0 (`-only`/`-or-later`), SSPL-1.0,
  BUSL-1.1, Elastic-2.0, OSL-3.0, RPL-1.5, EUPL-1.1, Prosperity-*, PolyForm-Noncommercial/
  Small-Business, all `CC-*-NC*`, and the **Commons-Clause** addendum (text pattern).
- **UNKNOWN** — `NOASSERTION`, `NONE`, empty, `"Proprietary"`/`"Commercial"`, deprecated
  ids (`GPL-2.0` without a suffix), any non-SPDX freeform string.

## Compound SPDX expressions (required)

- **`OR`** (recipient chooses) → take the **lowest-risk** branch (record the choice).
- **`AND`** (all apply) → take the **highest-risk** branch.
- **`WITH <exception>`** → exception table may **downgrade** tier
  (e.g. `GPL-2.0-only WITH Classpath-exception-2.0` → REVIEW;
  `GPL-3.0-only WITH Autoconf-exception-3.0` → ALLOW for generated output).

## Dual licensing

Detect (README "commercial license available"/"dual licensed"; a `LICENSE-COMMERCIAL`
file; registry sales link), set `dual_license_detected: true`, classify under the
open-source arm (usually BLOCK), and route to human resolution.

## Config shape

`license-policy.yaml`: `policy_version`, `default_unknown_action`, the four tier→SPDX-id
lists, `non_spdx_patterns` (regex for NC / Commons-Clause), `compound_expression_rules`
(`OR`=min, `AND`=max, `WITH`=exception table), a `dual_license_detection` block, and
`allowlist_overrides` — **per-dependency approvals carrying a justification and an
expiry** (so overrides cannot silently rot).

## Standing caveats (surface on the flag, never auto-clear)

- **LGPL static vs dynamic linking** — REVIEW assumes dynamic linking; static linking
  may be effectively BLOCK and is usually invisible in metadata.
- **BUSL Change Date** — fetch and surface it; a static BLOCK can be wrong once the date
  has passed.
- **Declared ≠ actual** — for BLOCK/REVIEW flags prefer file-level (ScanCode)
  verification over the declared field.
- **Non-SPDX strings** — normalize to SPDX before tier lookup or REVIEW/BLOCK leaks
  through as UNKNOWN.
