"""API-only license resolution stage."""

from pathlib import Path
from typing import Any


def run_resolve(work_root: str | Path, repo_ref: str, **kwargs: Any) -> Path:
    """Resolve an SBOM using the API-only stage."""

    from repolens.resolve.stage import run_resolve as _run_resolve

    return _run_resolve(work_root, repo_ref, **kwargs)


__all__ = ["run_resolve"]
