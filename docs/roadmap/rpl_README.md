# RepoLens — roadmap

RepoLens produces a **trustworthy open-source license disclosure** across an
owner's repositories, in any language, with risky or unfindable licenses flagged,
resolved with anchored evidence under human approval, and assembled into a clean,
deduplicated report.

> **We orchestrate mature tools; we do not reimplement scanners.** RepoLens owns the
> *workflow, policy, evidence, categorization, report, and security* — not SBOM
> generation or license detection.

## North star

For a configured `<OWNER>`: discover every repo → categorize → inventory dependencies
across all languages → resolve each license cheapest-source-first → tag and flag by
policy → resolve the flagged shortlist with evidence + human approval → render a
deduplicated disclosure (main report + companion appendices). Crash-safe, resumable,
and secure against untrusted repo content by design.

## Operating principles

| Principle | How it shows up |
|-----------|-----------------|
| **Orchestrate, don't reimplement** | Wrap Syft, ScanCode, registry/GitHub/deps.dev APIs, native mobile tools. No home-grown parsers or license DB. |
| **Ship the thin slice first** | A working multi-language inventory + report lands in M1; depth is added behind it. |
| **Parallel by default** | Fixed on-disk schemas let every pipeline stage be built concurrently. See the [archived roadmap](archive/rpl_roadmap.md). |
| **Security is scope, not a phase** | The [security guardrails](rpl_security.md) are mandatory from M0 and gate every milestone. No deviation. |
| **KISS / DRY / SRP / quality** | Small single-purpose components; shared primitives; on-disk files over a database; tested. |
| **No speculative scope** | Build exactly the stated requirements — fully — and nothing invented beyond them. |

## Documents

| Doc | Purpose |
|-----|---------|
| [requirements.md](rpl_requirements.md) | What the tool must achieve + global definition of done |
| [decisions.md](rpl_decisions.md) | The locked technical decisions |
| [architecture.md](rpl_architecture.md) | The orchestration design (pipeline, resolution ladder, storage, report views) |
| [security.md](rpl_security.md) | **Mandatory** guardrails + canary tests — must not deviate |
| [license-policy.md](rpl_license-policy.md) | The default, config-ready risk policy |
| [current-roadmap.md](rpl_current_roadmap.md) | Active roadmap with status tracking, Quest prompts, delivered/installed UX, release disclosure policy, and Sketch2md pilot plan |
| [github-license-api-download-url.md](rpl_github-license-api-download-url.md) | Follow-up verifier fix for GitHub License API `download_url` evidence |
| [archive/roadmap.md](archive/rpl_roadmap.md) | 📦 *Archived build plan (historical).* The original parallel workstreams, sequencing, milestones, and acceptance model. Not current planning. |
| [archive/execution.md](archive/rpl_execution.md) | 📦 *Archived build plan (historical).* How the build was driven: Quest vs Workflow lanes, parallel rounds, gates. |
