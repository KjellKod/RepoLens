# Contributing to RepoLens

Thanks for your interest — contributions are welcome.

## Ground rules

- **Orchestrate, don't reinvent.** RepoLens conducts existing tools (Syft, ScanCode,
  license APIs, native mobile tooling). Prefer improving orchestration, policy, evidence,
  or reporting over adding a new scanner engine.
- **Security guardrails are non-negotiable.** See
  [docs/roadmap/rpl_security.md](docs/roadmap/rpl_security.md). Changes must not weaken
  them, and new functionality ships with its security canary.
- **No real names, ever.** No owner / org / company / private-repo names in code, tests,
  docs, or fixtures. Fixtures use invented names (`acme-*`). A CI hygiene guard enforces
  this and will fail the build on a match.
- **Principles:** KISS, DRY, SRP, YAGNI. Small, single-purpose changes.

## Workflow

1. **Open an issue** first for anything non-trivial, so we can agree on the approach.
2. **Branch** (or fork) and keep the PR **focused** — one logical change.
3. **Add or extend tests** for the behavior you change, plus any relevant security canary.
4. **Open a PR** and fill in the description (what changed and why).
5. **Make CI green** — tests, security canaries, and the name-hygiene guard must pass.
   - The agentic Codex review runs automatically on maintainers' PRs. External / fork PRs
     don't receive repository secrets by design, so a maintainer runs the review for you.
6. **Stay current** — rebase your branch on the latest `main` before merge (a PR must be
   up to date to merge).

## Quality bar

Deterministic, offline tests; behavior covered by tests; no speculative scope. If a
change touches license policy or risk classification, call it out explicitly in the PR —
those decisions carry weight.

## Licensing of contributions

By contributing, you agree your contributions are licensed under the repository
[LICENSE](LICENSE).
