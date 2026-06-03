"""Pure renderers for P1 discovery artifacts."""

from __future__ import annotations

from collections.abc import Sequence

from repolens.data.limits import SCHEMA_VERSION
from repolens.security.redaction import redact_tokens
from repolens.security.sanitize import markdown_link, render_code_span, sanitize_markdown

from .models import CategorizedRepository


def build_discovered_payload(
    owner: str,
    repositories: Sequence[CategorizedRepository],
    *,
    generated_at: str,
) -> dict[str, object]:
    """Build the schema-validated ``discovered.json`` value."""

    ordered_repositories = sort_discovered_repositories(repositories)
    repo_values = [_repo_payload(repo) for repo in ordered_repositories]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "owner": owner,
        "repository_count": len(repo_values),
        "candidate_count": sum(1 for repo in ordered_repositories if not repo.hard_excluded),
        "hard_exclusion_count": sum(1 for repo in ordered_repositories if repo.hard_excluded),
        "repositories": repo_values,
    }


def render_repos_candidate_markdown(
    owner: str,
    repositories: Sequence[CategorizedRepository],
    *,
    generated_at: str,
) -> str:
    """Render a sanitized human approval file for discovered repositories."""

    ordered_repositories = sort_discovered_repositories(repositories)
    candidates = [repo for repo in ordered_repositories if not repo.hard_excluded]
    excluded = [repo for repo in ordered_repositories if repo.hard_excluded]
    lines = [
        "# Repository candidates",
        "",
        f"Generated: {render_code_span(generated_at)}",
        f"Owner: {render_code_span(owner)}",
        "",
        "## Candidates",
        "",
        "Every checked repo below will be scanned — UNTICK to exclude; consider noting why "
        "(e.g. `— excluded: <reason>`).",
        "",
    ]

    if candidates:
        for item in candidates:
            lines.extend(_repo_markdown(item, checkbox=True))
    else:
        lines.append("_No candidate repositories discovered._")
        lines.append("")

    lines.extend(["## Hard exclusions", ""])
    if excluded:
        for item in excluded:
            lines.extend(_repo_markdown(item, checkbox=False))
    else:
        lines.append("_No hard exclusions._")
        lines.append("")

    return sanitize_markdown(redact_tokens("\n".join(lines).rstrip() + "\n"))


def sort_discovered_repositories(
    repositories: Sequence[CategorizedRepository],
) -> tuple[CategorizedRepository, ...]:
    """Return the deterministic review order for discovery artifacts."""

    return tuple(sorted(repositories, key=_repository_sort_key))


def _repository_sort_key(
    item: CategorizedRepository,
) -> tuple[bool, str, str, str, str, str, str]:
    repo = item.repo
    return (
        item.hard_excluded,
        item.category.casefold(),
        repo.name.casefold(),
        repo.name_with_owner.casefold(),
        item.category,
        repo.name,
        repo.name_with_owner,
    )


def _repo_payload(item: CategorizedRepository) -> dict[str, object]:
    repo = item.repo
    return {
        "name": repo.name,
        "name_with_owner": repo.name_with_owner,
        "url": repo.url,
        "description": repo.description,
        "topics": list(repo.topics),
        "archived": repo.archived,
        "private": repo.private,
        "category": item.category,
        "category_source": item.category_source,
        "hard_excluded": item.hard_excluded,
        "exclusion_reason": item.hard_exclusion_reason,
    }


def _repo_markdown(item: CategorizedRepository, *, checkbox: bool) -> list[str]:
    repo = item.repo
    prefix = "- [x]" if checkbox else "-"
    # A trailing marker after the source fence; scan.inputs._CANDIDATE_ROW_RE's
    # `(?:\s.*)?$` tolerates trailing text, so checkbox parsing is unaffected.
    private_marker = " — private - needs auth to clone" if repo.private else ""
    lines = [
        (
            f"{prefix} {render_code_span(repo.name_with_owner)} "
            f"- category {render_code_span(item.category)} "
            f"({render_code_span(item.category_source)}){private_marker}"
        )
    ]
    if item.hard_exclusion_reason:
        lines.append(f"  - reason: {render_code_span(item.hard_exclusion_reason)}")
    if repo.url:
        lines.append(f"  - url: {markdown_link(repo.name_with_owner, repo.url)}")
    lines.append(f"  - private: {render_code_span('yes' if repo.private else 'no')}")
    lines.append(f"  - archived: {render_code_span('yes' if repo.archived else 'no')}")
    lines.append(f"  - topics: {_topic_list(repo.topics)}")
    if repo.description:
        lines.append(f"  - description: {render_code_span(repo.description)}")
    lines.append("")
    return lines


def _topic_list(topics: Sequence[str]) -> str:
    if not topics:
        return render_code_span("none")
    return ", ".join(render_code_span(topic) for topic in topics)
