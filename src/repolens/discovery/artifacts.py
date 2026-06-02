"""Artifact writers for the discover stage."""

from __future__ import annotations

from pathlib import Path

from repolens.data.errors import ArtifactExistsError, LimitExceeded
from repolens.data.limits import max_bytes_for
from repolens.data.store import atomic_write_bytes, write_discovered

from .models import CategorizedRepository
from .render import build_discovered_payload, render_repos_candidate_markdown


def write_discovery_artifacts(
    work_root: str | Path,
    *,
    owner: str,
    repositories: tuple[CategorizedRepository, ...],
    generated_at: str,
    force_candidate: bool = False,
) -> tuple[Path, Path]:
    """Write ``discovered.json`` and ``repos.candidate.md``."""

    candidate_path = repos_candidate_path(work_root)
    _ensure_candidate_can_be_written(candidate_path, force=force_candidate)
    payload = build_discovered_payload(owner, repositories, generated_at=generated_at)
    discovered_path = write_discovered(work_root, payload)
    candidate_path = write_repos_candidate_md(
        work_root,
        owner=owner,
        repositories=repositories,
        generated_at=generated_at,
        force=force_candidate,
    )
    return discovered_path, candidate_path


def repos_candidate_path(work_root: str | Path) -> Path:
    """Return the human approval artifact path for a work root."""

    return Path(work_root) / "repos.candidate.md"


def write_repos_candidate_md(
    work_root: str | Path,
    *,
    owner: str,
    repositories: tuple[CategorizedRepository, ...],
    generated_at: str,
    force: bool = False,
) -> Path:
    """Write the Markdown approval artifact with an explicit byte cap."""

    path = repos_candidate_path(work_root)
    _ensure_candidate_can_be_written(path, force=force)
    data = render_repos_candidate_markdown(
        owner,
        repositories,
        generated_at=generated_at,
    ).encode("utf-8")
    max_bytes = max_bytes_for("repos_candidate_md")
    if len(data) > max_bytes:
        raise LimitExceeded(f"{path} exceeds {max_bytes} bytes")
    atomic_write_bytes(path, data)
    return path


def _ensure_candidate_can_be_written(path: Path, *, force: bool) -> None:
    if force or not path.exists():
        return
    raise ArtifactExistsError(
        f"{path} already exists; re-running discover would discard your selections. "
        "Pass --force to overwrite."
    )
