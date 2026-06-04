# Requirements & definition of done

## What RepoLens must achieve

1. **Generic & repo-agnostic.** Operate on any configured `<OWNER>` (a person or an
   organization) via the `gh` CLI. No hard-coded paths, repos, or owner names anywhere
   in code, tests, or docs.
2. **Every repo captured.** Discover and scan **all** repositories under the owner —
   not a curated subset. Nothing is silently skipped.
3. **All languages.** Inventory dependencies across Node, Python, Go, Rust, .NET/C#,
   Ruby, PHP, Java/Kotlin, Dart, and mobile (Android/iOS), plus whatever else the
   underlying SBOM tool supports. Coverage gaps are reported, never hidden.
4. **Deduplicated output.** One row per `(name, normalized-license)` with provenance —
   no repeated entries.
5. **Risk flagging.** Flag licenses that are dangerous for commercial/proprietary use,
   and flag dependencies whose license cannot be determined.
6. **Evidence-anchored resolution.** Every flagged item is resolved with a fetchable,
   human-validatable source; a human approves before it enters the report.
7. **Gated assembly.** The final report is produced **only after** all flagged items
   are resolved.
8. **Categorized, not filtered.** Every repo carries a configurable `category`; the
   report selects categories into a main disclosure and routes the rest to companion
   appendices. Nothing is deleted.
9. **Crash-safe & resumable.** Per-repo artifacts persist to disk; a re-run skips
   completed work.
10. **Secure against untrusted input.** Cloning, parsing, resolving, and rendering are
    hardened per [security.md](rpl_security.md) — mandatory.

## Inputs

- `<OWNER>` (runtime parameter / env, never committed).
- A read-scoped, fine-grained GitHub token (held by the orchestrator only).
- Config: category taxonomy, report selection, report header, and scan options
  in untracked local JSON config. License policy is packaged behavior today,
  not runtime-configurable local config.
- Name-hygiene denylist: private names in gitignored local config, never in public CI
  variables or committed docs.

## Outputs

- `inventory.json` — the complete tagged dataset.
- `report.main.{md,csv,docx}` — the disclosure for included categories/items.
- `report.appendix.<category>.{md,csv}` — one per excluded category + first-party.
- `shortlist.md` — the human approval / audit artifact.
- Per-item evidence + agent I/O audit log.

## Definition of done (global acceptance)

- [ ] Runs end-to-end against any `<OWNER>` supplied at runtime; zero owner/repo
      strings in the codebase, tests, fixtures, or docs (CI hygiene guard green with
      public invented sentinels and private local denylist values).
- [ ] Produces a deduplicated, multi-language disclosure with provenance, versions,
      source URLs, and a `modified?` indicator.
- [ ] Every disclosed license is either machine-resolved with a recorded source or
      human-approved with anchored evidence.
- [ ] BLOCK/REVIEW/UNKNOWN items are flagged; the report will not assemble while any
      remain open.
- [ ] Excluded categories appear in appendices, never dropped.
- [ ] All [security guardrails](rpl_security.md) implemented; the full **canary suite**
      passes offline in CI.
- [ ] Resumable after an interrupted run with no recomputation of completed repos.
- [ ] RepoLens scanned on **itself** as a dogfood smoke test, producing its own
      third-party disclosure.
- [ ] Clean exit codes: `0` ok / `1` findings (open flags) / `2` usage error.
