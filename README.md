# RepoLens

**Know exactly what open source you ship — and what it obligates you to.**

RepoLens is a **license-disclosure orchestrator**. It points best-in-class tools at every
repository under an owner, in any language, and turns the ambiguity they leave behind
into one clean, evidence-backed disclosure. It **doesn't reinvent scanners — it conducts
them**, and adds the workflow, policy, evidence, and reporting on top.

> Status: in active development. See **[docs/roadmap](docs/roadmap/rpl_README.md)** for the
> design, decisions, security model, and build plan; **[docs/usage.md](docs/usage.md)** for
> how to run it.

## What you get

- **A deduplicated license disclosure** — `Name | License | …`, as a main report plus
  per-category appendices. One row per library, nothing silently dropped.
- **Risk flagged, not buried** — copyleft, network-copyleft, non-commercial, and
  source-available licenses surfaced against a configurable policy.
- **Ambiguity resolved with evidence** — anything the tooling can't determine is flagged
  and settled against a *fetchable* source (LICENSE permalink, registry field, SPDX
  match), with a human approving before it lands.
- **A complete, categorized inventory** (`inventory.json`) behind the report — every
  component tagged by origin, scope, and distribution.
- **Repeatable & resumable** — runs read-only against your code; crash-safe; re-runnable.

## Why it's needed

OSS license obligations are triggered by what you **ship**, and they're easy to lose
track of across dozens of repositories, a dozen languages, and thousands of transitive
dependencies. A single missed copyleft or non-commercial license can become a liability
during a security review, a funding round, or an acquisition — and hand-maintained
spreadsheets drift the moment they're written.

## How it works — orchestration, not reinvention

RepoLens conducts mature, trusted tools and resolves their gaps intelligently:

| Job | Tool it conducts |
|-----|------------------|
| Multi-language dependency inventory (SBOM) | **Syft** |
| Deep license detection (only where needed) | **ScanCode** |
| No-clone license resolution | **public APIs** — deps.dev, package registries, GitHub |
| Mobile (Android / iOS) | **native tooling** — AboutLibraries, LicensePlist |

The "smart" part is the **ambiguity resolution**: a cheapest-source-first ladder fills
most licenses without cloning; whatever's left — or is risky — is flagged and resolved
with **anchored evidence under human approval**, never guessed.

## Usage

```
repolens discover  --owner <OWNER>   # find + categorize repos; you approve the list
repolens scan                        # inventory dependencies across all languages
repolens resolve                     # resolve licenses cheapest-source-first
repolens flag                        # apply policy; flag risky / unknown licenses
repolens shortlist                   # resolve flagged items with evidence + approval
repolens report                      # assemble the disclosure (main + appendices)
```

Discovery and the final report are **human-gated**; everything between is automatic and
resumable. The owner, repo categories, and report header are runtime inputs — never
baked into the tool. **Full guide: [docs/usage.md](docs/usage.md).**

## Contributing

Contributions are welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**. In short: keep the
orchestrate-don't-reinvent principle, honor the non-negotiable security guardrails, never
put a real owner/org/repo name in code or tests, and make sure CI (tests + security
canaries + name-hygiene) is green.

## Disclaimer

RepoLens is provided **“as is”, without warranty of any kind.** It is an aid, **not** a
substitute for legal review, and nothing it produces is legal advice. License detection
across ecosystems is inherently imperfect — results may be incomplete or wrong.

**You are solely responsible for validating its output.** The authors and contributors
accept **no liability** for any decision, disclosure, or representation made on the basis
of this tool's results. When accuracy matters, verify against the source and consult
qualified counsel.

## License

See [LICENSE](LICENSE).
