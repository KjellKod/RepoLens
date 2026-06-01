# RepoLens

**Know exactly what open source you ship — and what it obligates you to.**

RepoLens scans every repository under an owner, in any language, and produces a clean,
deduplicated **open-source license disclosure**: what each dependency is, the license
that governs it, and whether that license is a problem for commercial use.

> Status: in active development — see **[docs/roadmap](docs/roadmap/rpl_README.md)** for the design, decisions, security model, and build plan.

## Why it's needed

Open-source license obligations are triggered by what you **ship**, and they're easy to
lose track of across dozens of repositories, a dozen languages, and thousands of
transitive dependencies. A single missed copyleft, network-copyleft, or
non-commercial license can turn into a real liability during a security review, a
funding round, or an acquisition — and hand-maintained spreadsheets drift the moment
they're written.

RepoLens makes the inventory **automatic, repeatable, and evidence-backed**:

- **Every repo, every language** — Node, Python, Go, Rust, .NET, Ruby, PHP, Java,
  mobile, and more.
- **Risk surfaced, not buried** — copyleft, network-copyleft, non-commercial, and
  source-available licenses are flagged against a configurable policy.
- **Unknowns resolved with evidence** — anything the tooling can't determine is flagged
  and resolved against a *fetchable* source, with a human approving before it lands.
- **Deduplicated & categorized** — one row per library, grouped the way you need it,
  with nothing silently dropped.

RepoLens **orchestrates** mature, trusted tools (Syft, ScanCode, public license APIs,
native mobile tooling) — it does not reinvent scanners.

## How it's used

```
repolens discover  --owner <OWNER>   # find + categorize repos; you approve the list
repolens scan                        # inventory dependencies across all languages
repolens resolve                     # resolve licenses cheapest-source-first
repolens flag                        # apply policy; flag risky / unknown licenses
repolens shortlist                   # resolve flagged items with evidence + approval
repolens report                      # assemble the disclosure (main + appendices)
```

Discovery and the final report are **human-gated**; everything between is automatic,
resumable, and read-only against your code. The owner, repo categories, and report
header are runtime inputs — never baked into the tool.

## Disclaimer

RepoLens is provided **“as is”, without warranty of any kind.** It is an aid, **not** a
substitute for legal review, and nothing it produces is legal advice. License detection
across ecosystems is inherently imperfect — results may be incomplete or wrong.

**You are solely responsible for validating its output.** The authors and contributors
accept **no liability** for any decision, disclosure, or representation made on the
basis of this tool's results. When accuracy matters, verify against the source and
consult qualified counsel.

## License

See [LICENSE](LICENSE).
