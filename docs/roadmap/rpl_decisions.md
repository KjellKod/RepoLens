# Locked decisions

These are settled. Build to them.

## Platform & shape
- **Language/runtime:** Python 3.
- **Orchestration only:** wrap external tools; never reimplement SBOM generation or
  license detection.
- **CLI with subcommands**, one per pipeline stage; each reads/writes on-disk
  artifacts and is independently re-runnable.
- **Storage:** plain on-disk JSON / NDJSON, one directory per repo. No database.
- **Sources:** repositories discovered under a single `<OWNER>` per run via `gh`
  (public + private per token).

## Orchestrated tools
- **SBOM / inventory:** Syft (broad, multi-language, read-only).
- **Deep license detection:** ScanCode — invoked **only** on items left unresolved.
- **No-clone license resolution APIs:** deps.dev (primary for npm/PyPI/Cargo/Maven/
  NuGet/RubyGems/Go), native registry APIs, GitHub license API, ClearlyDefined and
  ecosyste.ms as targeted fallbacks.
- **Mobile license enrichment:** AboutLibraries (Android) and LicensePlist (iOS),
  invoked only for auto-detected mobile repos and only in a sandbox.

## Resolution model (cheapest source first)
1. Syft declared metadata → 2. free license APIs (no clone) → 3. mobile native
enrichment (auto-detected mobile repos) → 4. ScanCode on the remaining unknowns →
5. evidence-anchored agent + human approval. Every resolution records its **source as
evidence**. A string→SPDX normalization pass runs before any policy lookup.

## Scope & tagging (capture all, tag, never silently filter)
- Capture the **full transitive dependency tree, all scopes**.
- Tag every component with:
  - `origin`: `third-party-oss` | `first-party` — only `third-party-oss` is eligible
    for the OSS disclosure table; first-party is listed separately.
  - `scope`: `runtime` | `dev` | `build` | `test` (best-effort; unknown → kept,
    marked `unknown`).
  - `distribution`: `server` | `client-or-mobile` | `not-distributed` | `unknown`.
- Required columns: `version`, `source_url`, `modified?`.
- The legal table is a **view**, defaulting to `distributed`
  (server runtime + client/mobile). `--scope` selects `distributed` | `all` | `direct-only`.

## Repository categorization
- Every repo is scanned and tagged with a **configurable `category`** from an
  org-defined taxonomy (assigned by name pattern / GitHub topic / explicit mapping;
  unmatched → a default category). Categories classify; they do not exclude.
- The report **selects categories** (and items within) into `report.main`; excluded
  categories and first-party/internal components go to `report.appendix.<category>`.
  Re-scoping = edit selection + re-render, no re-scan.
- Only genuinely dead/archived repos may be hard-excluded from scanning, and only
  with a visible, recorded reason.

## Mobile
- **Auto-detected** by marker files (`build.gradle`/`settings.gradle` + Android plugin
  → Android; `*.xcodeproj`/`Package.swift`/`Podfile`/`Cartfile` → iOS).
- Mobile lockfiles carry no license data, so mobile deps are always license-enriched.
  Default enrichment is the metadata/API path (no build toolchain). Native-tool
  enrichment runs only when the toolchain is present, **always sandboxed**, and never
  hard-fails a run.

## Risk policy
- Default tiers **ALLOW / REVIEW / BLOCK / UNKNOWN** per [license-policy.md](rpl_license-policy.md),
  shipped as versioned config. Unresolved defaults to BLOCK until cleared.
- SPDX compound expressions handled: `OR` → lowest-risk branch; `AND` → highest-risk
  branch; `WITH` → exception table can downgrade tier.

## Resolution agent
- **Capability-minimized:** allowlisted HTTP GET + read-only single-item path +
  schema output **only**. No shell, file-write, secrets, arbitrary network, or
  sub-agents. Token never in its environment or prompt.
- One isolated invocation per item. Abstains rather than guesses. Suspicious content
  is routed to a human, never auto-resolved. The orchestrator re-fetches and verifies
  every cited evidence URL.

## Output & report
- Tool emits structured data unconditionally; the `.docx` renders from a **generic
  template** with org name / legal header injected at runtime from untracked config.
- Report assembly is gated on a clear shortlist.

## Security
- The guardrails in [security.md](rpl_security.md) are **mandatory and non-negotiable**.

## Name hygiene
- `<OWNER>` and all repo names are runtime/config inputs, never literals in code,
  tests, fixtures, or docs. Live runs read the owner from an untracked env var or local
  config. Fixtures and public CI use invented names only. Real forbidden names live in
  gitignored local config and are discovered from the main checkout when commands run
  inside a linked worktree.
