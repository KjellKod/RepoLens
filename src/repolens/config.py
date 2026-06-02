"""Load local, untracked runtime config files."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .exit_codes import InputError

LOCAL_CONFIG_PATTERNS = (
    "*.local.json",
    "*.local.yml",
    "*.local.yaml",
    "*.local.toml",
)


@dataclass(frozen=True)
class Config:
    values: dict[str, Any]
    sources: tuple[Path, ...]


def load_config(base_dir: Path | str = ".", explicit_path: Path | str | None = None) -> Config:
    """Load local config using explicit, deterministic precedence.

    Files are merged from lowest to highest precedence:
    json -> yml -> yaml -> toml -> explicit path.
    Higher precedence replaces only colliding key paths.
    """
    root = Path(base_dir)
    sources = _discover_local_files(root)
    if explicit_path is not None:
        sources.append(Path(explicit_path))

    merged: dict[str, Any] = {}
    resolved_sources: list[Path] = []
    for source in sources:
        data = _read_config_file(source)
        _deep_merge(merged, data)
        resolved_sources.append(source)

    return Config(values=merged, sources=tuple(resolved_sources))


def _discover_local_files(base_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in LOCAL_CONFIG_PATTERNS:
        files.extend(sorted(base_dir.glob(pattern)))
    return files


def _read_config_file(path: Path) -> dict[str, Any]:
    if path.is_dir():
        raise InputError(
            f"Config path is a directory, not a config file: {_display_path(path)}. "
            "Use --work-root <DIR> for output directories."
        )
    if not path.is_file():
        raise InputError(
            f"Config file not found: {_display_path(path)}. "
            "--config expects a local config file; use --work-root <DIR> for output directories."
        )

    try:
        suffixes = path.suffixes
        if path.suffix == ".json":
            loaded = json.loads(path.read_text(encoding="utf-8"))
        elif path.suffix == ".toml":
            loaded = tomllib.loads(path.read_text(encoding="utf-8"))
        elif path.suffix in {".yaml", ".yml"}:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        else:
            raise InputError(f"Unsupported config extension: {path.suffix}")
    except InputError:
        raise
    except Exception as exc:
        raise InputError(f"Invalid config file: {_display_path(path)}") from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise InputError(f"Config root must be an object: {_display_path(path)}")
    if not all(isinstance(key, str) for key in loaded):
        raise InputError(f"Config keys must be strings: {_display_path(path)}")

    del suffixes
    return loaded


def _deep_merge(target: dict[str, Any], update: Mapping[str, Any]) -> None:
    for key, value in update.items():
        current = target.get(key)
        if isinstance(current, dict) and isinstance(value, Mapping):
            _deep_merge(current, value)
        else:
            target[key] = value


def _display_path(path: Path) -> str:
    return path.name
