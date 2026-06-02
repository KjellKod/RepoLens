"""End-to-end discover orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from repolens.config import Config

from .artifacts import write_discovery_artifacts
from .gh import DEFAULT_GH_LIMIT, GhRunner, fetch_repositories, list_repositories
from .taxonomy import categorize_repositories, taxonomy_from_config


@dataclass(frozen=True)
class DiscoverResult:
    discovered_path: Path
    candidate_path: Path
    repository_count: int
    candidate_count: int
    hard_exclusion_count: int


def run_discover(
    *,
    owner: str,
    work_root: str | Path,
    config: Config,
    limit: int = DEFAULT_GH_LIMIT,
    repos: tuple[str, ...] | None = None,
    runner: GhRunner | None = None,
    generated_at: str | None = None,
    force_candidate: bool = False,
) -> DiscoverResult:
    """Run discovery using ``gh`` metadata and local taxonomy config.

    When ``repos`` is supplied, exactly those named repos under ``owner`` are
    fetched (one ``gh repo view`` each); otherwise every repo under ``owner`` is
    enumerated via ``gh repo list``. Everything from categorization onward is
    identical for both paths.
    """

    timestamp = generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    if repos is not None:
        repositories = fetch_repositories(owner, repos, runner=runner)
    else:
        repositories = list_repositories(owner, limit=limit, runner=runner)
    categorized = categorize_repositories(repositories, taxonomy_from_config(config))
    discovered_path, candidate_path = write_discovery_artifacts(
        work_root,
        owner=owner,
        repositories=categorized,
        generated_at=timestamp,
        force_candidate=force_candidate,
    )
    return DiscoverResult(
        discovered_path=discovered_path,
        candidate_path=candidate_path,
        repository_count=len(categorized),
        candidate_count=sum(1 for repo in categorized if not repo.hard_excluded),
        hard_exclusion_count=sum(1 for repo in categorized if repo.hard_excluded),
    )
