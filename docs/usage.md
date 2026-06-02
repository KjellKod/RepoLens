# RepoLens — usage

> In active development. This guide describes the intended workflow and **grows as each
> command ships** (tracked on the [roadmap](roadmap/rpl_roadmap.md)). For the full design,
> see [docs/roadmap](roadmap/rpl_README.md).

## Prerequisites

- `gh` (authenticated), `git`, `python3`.
- `syft` + `scancode` — installed and version-pinned by `repolens bootstrap`
  (checksum/signature-verified).
- For mobile license enrichment (optional, auto-detected): a build toolchain
  (JDK + Gradle for Android, Xcode/SPM or a `GITHUB_TOKEN` for iOS).

## Configuration (all untracked / local)

- **Owner** — supplied at runtime (`--owner` / env); never committed.
- **Category taxonomy** — how repos are bucketed (e.g. `product`, `internal`).
- **License policy** — the ALLOW / REVIEW / BLOCK / UNKNOWN tiers.
- **Report selection + header** — which categories land in the main report, and the
  org/legal boilerplate (injected at render time).

## The pipeline

```
repolens discover  --owner <OWNER>   # enumerate + categorize repos → approval checklist
repolens scan                        # hardened clone + Syft → per-repo SBOM (resumable)
repolens resolve                     # license ladder: APIs → mobile → ScanCode on unknowns
repolens flag                        # tag + apply policy + dedup → inventory + shortlist
repolens shortlist                   # evidence-anchored agent + human checkbox approval
repolens report                      # gated: assemble main report + appendices
```

Discovery (you approve the repo list) and the final report (gated until the shortlist is
clear) are the two human checkpoints. Everything else is automatic, read-only against
your code, and resumable after an interruption.

## Outputs

- `inventory.json` — the complete, tagged dataset.
- `report.main.{md,csv,docx}` — the disclosure for the included categories.
- `report.appendix.<category>.{md,csv}` — one per excluded category + first-party.
- `shortlist.md` — the human approval / audit artifact, plus a per-item evidence log.

## Safety

Read-only against your code; never runs install/build scripts; the resolution agent has
no shell, secrets, or arbitrary network. See the
[security model](roadmap/rpl_security.md) for the full guardrails.
