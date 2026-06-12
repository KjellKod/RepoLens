"""Lockfile-based delivery + declared-license signals for bundled JS apps.

Minified production bundles do not retain ``node_modules/`` path markers or
sourcemaps, so positive-marker artifact scanning cannot prove what shipped. The
package manager already computed the answer: ``package-lock.json`` annotates
every installed package as production, dev, or optional, and records each
package's declared ``license``. For a bundled app the production dependency
closure is what ships, so that closure is the delivery signal. Dev-only packages
are build-time and never ship; optional packages are per-platform binaries that
only the matching platform installs (monitor, not ship).

This module reads the lockfile snapshot RepoLens already retains at
``<work_root>/work/<repo>/source.snapshot/`` and exposes:

- :func:`load_lockfile_scopes` — package-name -> prod/dev/optional/devOptional.
- :func:`load_lockfile_licenses` — package-name -> declared license string,
  used as an evidence-backed fallback when resolution left a delivered package
  UNKNOWN even though the lockfile plainly declares its license.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

LockfileScope = Literal["prod", "dev", "optional", "devOptional"]

_LOCKFILE_NAME = "package-lock.json"
_NODE_MODULES = "node_modules/"


@dataclass(frozen=True, slots=True)
class _PackageInfo:
    scope: LockfileScope
    license: str


def load_lockfile_scopes(snapshot_dir: Path) -> dict[str, LockfileScope]:
    """Return a ``package-name -> scope`` map from an npm lockfile snapshot."""

    return {name: info.scope for name, info in _load_packages(snapshot_dir).items()}


def load_lockfile_licenses(snapshot_dir: Path) -> dict[str, str]:
    """Return a ``package-name -> declared license`` map (non-empty values only)."""

    return {
        name: info.license for name, info in _load_packages(snapshot_dir).items() if info.license
    }


def _load_packages(snapshot_dir: Path) -> dict[str, _PackageInfo]:
    """Parse ``package-lock.json`` (v2/v3) into per-package scope + license.

    Returns an empty map when the lockfile is absent or has no usable
    ``packages`` section (for example lockfile v1), so callers fall back to the
    existing not-scanned behavior rather than guessing.
    """

    lockfile = Path(snapshot_dir) / _LOCKFILE_NAME
    if not lockfile.is_file():
        return {}
    try:
        document = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    packages = document.get("packages")
    if not isinstance(packages, dict):
        return {}

    result: dict[str, _PackageInfo] = {}
    for path, meta in packages.items():
        if not isinstance(path, str) or _NODE_MODULES not in path:
            continue
        if not isinstance(meta, dict):
            continue
        name = _package_name_from_path(path)
        if not name:
            continue
        scope = _scope_for_meta(meta)
        license_text = meta.get("license")
        license_str = license_text.strip() if isinstance(license_text, str) else ""
        existing = result.get(name)
        # A package can appear at multiple paths (hoisted + nested). Prefer the
        # least-restrictive scope (production wins) and keep any declared license.
        if existing is None or _rank(scope) < _rank(existing.scope):
            kept_license = license_str or (existing.license if existing else "")
            result[name] = _PackageInfo(scope=scope, license=kept_license)
        elif not existing.license and license_str:
            result[name] = _PackageInfo(scope=existing.scope, license=license_str)
    return result


def _package_name_from_path(path: str) -> str:
    """Extract the npm package name from a lockfile ``packages`` key.

    Handles nesting and scoped names, for example
    ``node_modules/a/node_modules/@img/sharp`` -> ``@img/sharp``.
    """

    tail = path.rsplit(_NODE_MODULES, 1)[-1].strip("/")
    if not tail:
        return ""
    parts = tail.split("/")
    if parts[0].startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
    return parts[0]


def _scope_for_meta(meta: dict[str, object]) -> LockfileScope:
    # npm marks a package `dev` (only in the devDependencies graph), `optional`
    # (only in optionalDependencies), or `devOptional` (reachable only via dev
    # AND optional edges). Absence of all three means it is in the production
    # runtime graph.
    if meta.get("dev") is True:
        return "dev"
    if meta.get("devOptional") is True:
        return "devOptional"
    if meta.get("optional") is True:
        return "optional"
    return "prod"


def _rank(scope: LockfileScope) -> int:
    # Lower rank = ships more certainly = wins when a package appears twice.
    return {"prod": 0, "optional": 1, "devOptional": 2, "dev": 3}[scope]
