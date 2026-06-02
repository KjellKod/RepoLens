"""On-disk artifact contracts and storage helpers."""

from repolens.data.errors import (
    ArtifactError,
    CorruptArtifactError,
    LimitExceeded,
    SchemaValidationError,
)

_STORE_EXPORTS = {
    "is_repo_scanned",
    "iter_resolved",
    "read_discovered",
    "read_inventory",
    "read_sbom",
    "read_shortlist",
    "repo_dir",
    "write_discovered",
    "write_inventory",
    "write_resolved",
    "write_sbom",
    "write_shortlist",
}

__all__ = [
    "ArtifactError",
    "CorruptArtifactError",
    "LimitExceeded",
    "SchemaValidationError",
    "is_repo_scanned",
    "iter_resolved",
    "read_discovered",
    "read_inventory",
    "read_sbom",
    "read_shortlist",
    "repo_dir",
    "write_discovered",
    "write_inventory",
    "write_resolved",
    "write_sbom",
    "write_shortlist",
]


def __getattr__(name: str):
    if name in _STORE_EXPORTS:
        from repolens.data import store

        return getattr(store, name)
    raise AttributeError(f"module 'repolens.data' has no attribute {name!r}")
