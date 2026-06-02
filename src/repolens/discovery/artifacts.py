"""Artifact writers for the discover stage."""

from __future__ import annotations

from pathlib import Path

from repolens.data.errors import LimitExceeded
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
) -> tuple[Path, Path]:
    """Write ``discovered.json`` and ``repos.candidate.md``."""

    payload = build_discovered_payload(owner, repositories, generated_at=generated_at)
    discovered_path = write_discovered(work_root, payload)
    candidate_path = write_repos_candidate_md(
        work_root,
        owner=owner,
        repositories=repositories,
        generated_at=generated_at,
    )
    return discovered_path, candidate_path


def write_repos_candidate_md(
    work_root: str | Path,
    *,
    owner: str,
    repositories: tuple[CategorizedRepository, ...],
    generated_at: str,
) -> Path:
    """Write the Markdown approval artifact with an explicit byte cap."""

    path = Path(work_root) / "repos.candidate.md"
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
