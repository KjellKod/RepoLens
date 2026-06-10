# RepoLens Current Roadmap

This is the active operator roadmap. The original M0-M3 build plan is archived under
`docs/roadmap/archive/`; this file tracks the next product push: make RepoLens easier to
operate, harder to misuse, and precise about what a product actually ships or must
disclose.

RepoLens remains a license-disclosure orchestrator. It should help teams avoid accidental
release, notice, and attribution mistakes, but it must not pretend to be counsel or hide the
evidence behind a yes/no answer.

## Status Protocol

Every roadmap row must use exactly one status:

| Status | Meaning |
| --- | --- |
| `LEFT_TODO` | Not started. |
| `INPROGRESS` | A branch or Quest is actively working it. |
| `DONE-PR_OPEN` | Implementation is complete enough for review and a PR is open. |
| `DONE_MERGED` | The PR is merged to `main`; validation and docs are complete. |

Quest agents must update this file as part of their work:

1. Before coding, change their row from `LEFT_TODO` to `INPROGRESS`.
2. When opening or marking a PR ready, change it to `DONE-PR_OPEN` and add the PR number.
3. After merge, change it to `DONE_MERGED` and add the merge commit.
4. If scope changes, update the row and the relevant Quest prompt in this document.

## Product Guardrails

- Do not hardcode release/disclosure decisions in Python conditionals. License actions must
  live in versioned policy data with schema validation.
- Unknown license actions are blocking. If RepoLens sees a license or expression whose
  disclosure/release action is not modeled, it must block release output until the policy is
  updated or an explicit human override path exists.
- Do not globally suppress permissive licenses. For example, MIT often requires preserving
  copyright and license notices when software is distributed. The right model is not
  "MIT never discloses"; it is "for this license, this delivery context, and this disclosure
  surface, what notice or release action is required?"
- Keep disclosure surfaces separate:
  - Public/user-facing notices.
  - Bundled notice files.
  - Internal engineering/legal review.
  - CI-readable release gates.
- Do not claim `not_delivered` unless a relevant delivery artifact was scanned. If no
  artifact was scanned, say `not_scanned`.
- Non-delivered future risks stay visible, but they must not look equivalent to shipped
  obligations.
- RepoLens should block unsafe releases, not block because the UI is confusing. Make the
  reason and next step explicit.

## Merge Strategy

Use two product PRs if possible, but **do not run those two product PRs in parallel**.
Run one roadmap item at a time. Parallelism belongs inside the active Quest/PR through
coordinated subtasks that share one branch and one product surface.

| ID | Status | PR | Start gate | Work | Internal parallelism |
| --- | --- | --- | --- | --- | --- |
| `RPL-NEXT-1` | `DONE_MERGED` | #71 (merge f730d73) | Start next. One active product PR. | Presence model plus UX-first shortlist/report split. | Yes, inside this Quest only: schema/model, npm enrichment, shortlist UX, report UX, and validation can build in parallel against agreed fixtures. |
| `RPL-FIX-1` | `DONE_MERGED` | #74 (merge 99e5777) | Allowed concurrently: `RPL-NEXT-1` is `DONE_MERGED`, `RPL-NEXT-2` is `LEFT_TODO`, and no product row is mid-flight. | Resolve auto-provisions work-root ScanCode through pinned+verified tooling readiness. Follow-up: fix `offline-ci` integration tests that assumed the pre-auto-provision degraded path. | No, focused reliability/security fix on the active Quest branch. |
| `RPL-NEXT-2` | `INPROGRESS` | TBD | **Wait. Start only after `RPL-NEXT-1` is `DONE_MERGED`.** | Disclosure-action policy, artifact scan pilot, release outputs, and Sketch2md pilot. | Yes, inside the later `RPL-NEXT-2` Quest only: policy model, artifact scan, release writers, Sketch2md integration, and validation can build in parallel after `RPL-NEXT-1` schemas are merged. |

Do not create an `RPL-NEXT-2` branch while `RPL-NEXT-1` is open. If a useful discovery
comes up while `RPL-NEXT-1` is active, add a note to this roadmap or to the open PR, but
do not start implementation until the start gate is satisfied.

If `RPL-NEXT-2` becomes too large, split it once along this boundary:

- `RPL-NEXT-2a`: disclosure-action policy and release gate.
- `RPL-NEXT-2b`: artifact scan pilot, generated notices, Sketch2md consumption.

Do not split only by file ownership if that makes the UX incomplete.

## RPL-NEXT-1: Presence Model And UX Split

Goal: make delivered, installed-only, lockfile-only, future-risk, and not-scanned states
first-class in the existing pipeline, then drive the human-facing experience from those
states.

### Required Technical Shape

Add a `presence` block that can survive from resolved records through inventory,
shortlist, and reports:

```json
{
  "presence": {
    "install_state": "installed",
    "delivery_state": "not_scanned",
    "relation": "direct",
    "path": ["root-package", "dependency"],
    "platform_match": "unknown",
    "source": "syft",
    "target": "unknown",
    "reopen_on_delivery_change": true
  }
}
```

Allowed initial values:

- `install_state`: `installed`, `not_installed`, `lockfile_only`, `unknown`
- `delivery_state`: `delivered`, `not_delivered`, `not_scanned`, `unknown`
- `relation`: `direct`, `transitive`, `peer`, `optional`, `dev`, `devOptional`, `mixed`,
  `unknown`
- `platform_match`: `target`, `host`, `cross_platform`, `no`, `unknown`

Conservative defaults:

- Existing runtime/server records without artifact evidence should become
  `install_state=installed`, `delivery_state=not_scanned`.
- Existing build/not-distributed records should become `install_state=installed`,
  `delivery_state=not_scanned`, with UX language that they are not currently proven
  delivered.
- Lockfile-only inference is allowed only when the scanner/enricher has evidence that the
  package was seen in package-manager metadata but not in the install tree.

Shortlist UX must split top-level sections:

```text
DELIVERED / SHIPPED - ACTION REQUIRED
INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW
LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR
DELIVERY ARTIFACT NOT SCANNED - UNKNOWN
```

Each row should show:

- Delivery artifact status: delivered, not delivered, not scanned, or unknown.
- Install state: installed, lockfile only, not installed, or unknown.
- Relation: direct, transitive, optional, dev, peer, mixed, or unknown.
- Dependency path when available.
- Target or artifact scope when available.

Report UX:

- `report.main.*` should foreground delivered obligations and explicit not-scanned blockers.
- Monitored non-delivered risks should move to clearly labeled appendix/secondary output.
- `report.presentation.*` should be readable by a human who has not seen the shortlist.
  It must explain why a row is shipped, monitored, or blocked.
- CLI output should print presence counts and next steps. If report review or release policy
  review is required before final artifacts are publishable, say that before pointing the
  operator at the final report command.

Reopen behavior:

- Approval of a future-risk or not-scanned row must not silently carry over if the same
  component later becomes `delivered`.
- A delivery-state change to `delivered` must reopen the matching shortlist item unless an
  explicit current approval covers delivered usage.

### Acceptance Criteria

- A lockfile-only optional LGPL package is not rendered as delivered runtime code.
- A delivered GPL/LGPL/AGPL package appears in the top action-required section when delivery
  evidence exists.
- If artifact scanning was skipped, RepoLens says `delivery artifact not scanned`.
- Mixed groups split by presence state.
- Shortlist, report main, presentation, and appendices all show presence in plain language.
- Existing tests and security canaries remain green.

### Quest Prompt

```text
/quest "RepoLens RPL-NEXT-1: presence model and UX-first delivered/installed split

Before coding
- Open docs/roadmap/rpl_current_roadmap.md.
- Confirm `RPL-NEXT-1` is the only active product roadmap item. Do not start this Quest if another `RPL-NEXT-*` row is already INPROGRESS or DONE-PR_OPEN unless the user explicitly tells you to take over that same branch/PR.
- Change row RPL-NEXT-1 from LEFT_TODO to INPROGRESS.
- Keep this roadmap updated: when the PR opens, set DONE-PR_OPEN and add the PR number; after merge, set DONE_MERGED and add the merge commit.

Objective
Make dependency presence first-class through resolved records, inventory, shortlist, and reports. The UX must clearly separate delivered/shipped dependencies from installed-only, lockfile-only future risks, and not-scanned unknowns.

Read first
- docs/roadmap/rpl_current_roadmap.md
- ideas/delivered-vs-installed-dependencies.md
- docs/data-model.md
- docs/usage.md sections for flag, shortlist, report
- src/repolens/resolve/stage.py
- src/repolens/flag/stage.py and src/repolens/flag/dedup.py
- src/repolens/shortlist/grouping.py and src/repolens/shortlist/render.py
- src/repolens/report/main.py and src/repolens/report/presentation.py

Technical requirements
1. Add a schema-valid presence block to resolved/inventory/shortlist/report data.
2. Use conservative defaults. Do not claim not_delivered without artifact evidence.
3. Add npm/package-manager enrichment where reasonable for relation/path/platform metadata, but keep the first slice bounded.
4. Split shortlist rendering into top-level presence sections:
   - DELIVERED / SHIPPED - ACTION REQUIRED
   - INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW
   - LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR
   - DELIVERY ARTIFACT NOT SCANNED - UNKNOWN
5. Include presence in group keys so mixed delivery states do not share one approval group.
6. Reopen approvals when an item moves from future-risk/not-scanned/not-delivered to delivered.
7. Update report.main, report.presentation, and appendix language so the final artifacts are readable and do not imply non-delivered optional packages are shipped obligations.
8. Update CLI follow-along output so the operator sees presence counts, not-scanned counts, and the correct next step when report review or release policy review is required.
9. Update docs/usage.md and docs/data-model.md.

Parallel work packages
- Model/schema lane: presence dataclass/helpers, schema updates, conservative defaults.
- Npm enrichment lane: relation/path/platform extraction with tight fixtures.
- Shortlist UX lane: presence sections, grouping key changes, reopen behavior.
- Report UX lane: main/presentation/appendix wording and CSV/HTML parity.
- Validation lane: fixtures and regression tests for lockfile-only optional LGPL, not-scanned, and mixed groups.

Automation expectations
- Add small reusable fixture builders or test helpers instead of hand-copying large JSON blobs.
- If a manual inspection command is needed to validate report readability, document it in the PR notes and prefer a repeatable script or pytest fixture.

Validation
- PYTHONPATH=src python3 -m pytest tests/unit/flag tests/unit/shortlist tests/unit/test_resolve_stage.py
- PYTHONPATH=src python3 -m pytest tests/e2e/test_cli.py
- PYTHONPATH=src python3 -m pytest tests/canaries/security
- ruff format --check .
- ruff check .

Acceptance
- Lockfile-only optional LGPL is monitored, not shipped.
- Delivered GPL/LGPL/AGPL is top-section action-required when delivery evidence exists.
- Missing artifact scan says delivery artifact not scanned.
- Mixed groups split by presence state.
- Human-facing outputs show what happened, why, and what to do next.

Do not
- Do not introduce legal advice.
- Do not suppress risky items because they are not delivered.
- Do not say not_delivered unless an artifact was scanned.
- Do not hardcode disclosure actions; RPL-NEXT-2 owns policy actions."
```

## RPL-NEXT-2: Disclosure Policy, Release Gate, Artifact Scan, Sketch2md Pilot

Goal: produce release-ready outputs that tell a product what it must disclose, what it
should monitor, and what blocks release, using policy data rather than hardcoded license
assumptions.

### Required Technical Shape

Add a versioned disclosure-action policy alongside the existing risk-tier policy. It should
answer at least:

```json
{
  "license": "MIT",
  "contexts": {
    "delivered_distribution": {
      "public_notice": "not_required_by_default",
      "bundled_notice": "required",
      "internal_review": "record",
      "release_gate": "pass"
    },
    "saas_not_distributed": {
      "public_notice": "not_required_by_default",
      "bundled_notice": "not_applicable",
      "internal_review": "record",
      "release_gate": "pass"
    }
  }
}
```

Names can change, but the concepts must survive:

- `public_notice`: whether user-facing disclosure is required, optional, blocked, or
  unknown.
- `bundled_notice`: whether a notice file must include the dependency.
- `internal_review`: whether to record, review, or escalate.
- `release_gate`: pass, warn, review, block.
- `rationale`: short policy explanation shown to operators.

Unknown policy actions must block release output:

- If license risk tier is known but disclosure action is missing, block.
- If delivery context is known but the policy has no action for that context, block.
- If SPDX expression cannot be reduced to a policy-supported action, block.

Release outputs:

- `release.licenses.json`: machine-readable delivered dependency/license/action manifest.
- `release.notices.md`: generated human-readable notices for dependencies requiring bundled
  notice or attribution.
- `release.notices.txt`: plain-text notice variant.
- `release.review.md`: operator summary with blocks, warnings, monitored future risks, and
  scan coverage.
- `release.policy.json`: deterministic CI-readable gate result.

Artifact scan pilot:

- Support one focused delivered-artifact target first, preferably a JS bundle or
  Cloudflare Worker/OpenNext output.
- Mark a package `delivered` only when artifact evidence supports it.
- Do not claim absence across targets that were not scanned.

Sketch2md pilot:

- Use sketch2md as the pilot product.
- Prove the generated notices can be consumed by the app or linked from `/about`.
- Keep the pilot instructions generic enough that another repo can follow the pattern.

### Acceptance Criteria

- A delivered license with a modeled notice action appears in generated notices when policy
  says it should.
- A license with no disclosure-action policy blocks release output until the policy is
  updated.
- MIT is not globally omitted; its action depends on context and notice surface.
- Delivered CC-BY-4.0 generates attribution/disclosure output without being treated like a
  copyleft blocker.
- Delivered GPL/LGPL/AGPL and other configured unfriendly licenses fail the release policy
  gate.
- Lockfile-only Sharp/libvips-style LGPL packages are monitored, not included as shipped
  user-facing notices.
- Sketch2md can run the pilot flow and consume generated notice output.

### Quest Prompt

```text
/quest "RepoLens RPL-NEXT-2: disclosure-action policy, release gate, artifact scan pilot, and Sketch2md pilot

Before coding
- Open docs/roadmap/rpl_current_roadmap.md.
- Confirm `RPL-NEXT-1` is DONE_MERGED. If it is not, stop and report that this Quest is blocked by the start gate.
- Change row RPL-NEXT-2 from LEFT_TODO to INPROGRESS.
- If this is split, add RPL-NEXT-2a and RPL-NEXT-2b rows before coding and explain the split in the roadmap.
- Keep this roadmap updated: when the PR opens, set DONE-PR_OPEN and add the PR number; after merge, set DONE_MERGED and add the merge commit.

Objective
Add release/disclosure policy actions and release-ready outputs without hardcoding legal decisions in code. Unknown disclosure actions must block. Pilot delivered-artifact scanning and generated notices with sketch2md.

Read first
- docs/roadmap/rpl_current_roadmap.md
- docs/roadmap/rpl_license-policy.md
- ideas/delivered-vs-installed-dependencies.md
- docs/data-model.md
- src/repolens/policy/data/license-policy.default.json
- src/repolens/policy/config.py and src/repolens/policy/engine.py
- src/repolens/report/main.py and src/repolens/report/presentation.py
- RPL-NEXT-1 implementation and tests

Technical requirements
1. Add a versioned disclosure-action policy data file and schema. Do not hardcode license actions in Python branches.
2. Model actions per license/expression and delivery context:
   - public/user-facing notice
   - bundled notice
   - internal review
   - CI release gate
   - rationale
3. Unknown license actions or unknown context actions must block release output with a clear message.
4. Add release outputs:
   - release.licenses.json
   - release.notices.md
   - release.notices.txt
   - release.review.md
   - release.policy.json
5. Add a focused delivered-artifact scan path for one target first, preferably JS bundle or Cloudflare Worker/OpenNext.
6. Mark delivered only from artifact evidence. Use not_scanned for unscanned targets.
7. Add a Sketch2md pilot flow. It may live in docs first if product repo changes should be separate, but it must be runnable and specific.
8. Update docs/usage.md, docs/data-model.md, and docs/roadmap/rpl_license-policy.md.

Parallel work packages
- Policy lane: disclosure-action schema, default policy data, unknown-action blocking.
- Release-output lane: release.licenses.json, notices, review, and policy writers.
- Artifact-scan lane: focused JS bundle or Cloudflare Worker/OpenNext delivered detection.
- Sketch2md pilot lane: runnable commands, generated artifact locations, and app-consumption notes.
- Validation lane: policy fixtures, unknown-action blocker tests, and delivered-vs-monitored regressions.

Automation expectations
- Provide commands that can be run directly for the Sketch2md pilot; avoid prose-only validation.
- Add scripts or pytest fixtures for generated notice comparisons if output review would otherwise be manual.
- When pilot output is generated, mention exact paths in the PR and keep generated files out of RepoLens unless they are intentional fixtures.

Policy stance
- Do not globally omit MIT. MIT often requires preserving notices when distributed; the policy may decide public notice is not required by default while bundled/internal notices are still required.
- Do not expose more public disclosure than policy requires by default.
- Do not hide monitored future risks.
- Do not call the result legal advice.

Validation
- PYTHONPATH=src python3 -m pytest tests/unit tests/e2e/test_cli.py
- PYTHONPATH=src python3 -m pytest tests/canaries/security
- Run the Sketch2md pilot commands documented by this PR and save/mention the generated artifacts.
- ruff format --check .
- ruff check .

Acceptance
- Unknown disclosure action blocks release output.
- Modeled delivered attribution license generates notices.
- Delivered copyleft/non-commercial/source-available policy blockers fail release.policy.json.
- Lockfile-only optional LGPL is monitored and not emitted as shipped disclosure.
- Sketch2md pilot is documented and runnable.

Do not
- Do not turn RepoLens into legal advice.
- Do not make a license disappear just because it is permissive.
- Do not publish public notices for licenses that policy says should stay internal/bundled only.
- Do not claim not_delivered without artifact evidence."
```

## Future Work After These PRs

Keep these out of `RPL-NEXT-1` and `RPL-NEXT-2` unless they are required for the pilot:

| ID | Status | Work |
| --- | --- | --- |
| `RPL-FUTURE-1` | `LEFT_TODO` | Docker image artifact scanning. |
| `RPL-FUTURE-2` | `LEFT_TODO` | Electron/macOS/desktop package artifact scanning. |
| `RPL-FUTURE-3` | `LEFT_TODO` | Mobile app artifact scanning beyond existing native metadata enrichment. |
| `RPL-FUTURE-4` | `LEFT_TODO` | Organization-supplied disclosure policy overlays with expiry and audit trail. |
| `RPL-FUTURE-5` | `LEFT_TODO` | CI stale-notice checker for generated release artifacts. |

Future rows must get full Quest prompts before they are started.
