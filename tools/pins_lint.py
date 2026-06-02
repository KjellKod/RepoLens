#!/usr/bin/env python3
"""Standalone pins lint — fails on `latest`/floating specs or missing digests.

Reuses the same validation as the runtime loader (``repolens.bootstrap.pins``) so
the CI gate and the loader cannot drift. Dependency-light: stdlib only.

Usage:
    python3 tools/pins_lint.py [PINS_TOML ...]
Exit codes: 0 = all manifests valid, 1 = a manifest is invalid, 2 = usage error.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a bare script (python3 tools/pins_lint.py) from an uninstalled
# checkout by ensuring the src-layout package root is importable.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from repolens.bootstrap.errors import InvalidPin  # noqa: E402
from repolens.bootstrap.pins import load_pins  # noqa: E402


def lint_path(path: Path) -> list[str]:
    """Return a list of error strings for ``path`` (empty list == valid)."""
    try:
        load_pins(path)
    except InvalidPin as exc:
        return [f"{path}: {exc}"]
    return []


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        args = [str(_REPO_ROOT / "src" / "repolens" / "bootstrap" / "pins.toml")]

    errors: list[str] = []
    for raw in args:
        path = Path(raw)
        if not path.exists():
            print(f"pins-lint: file not found: {path}", file=sys.stderr)
            return 2
        errors.extend(lint_path(path))

    if errors:
        for err in errors:
            print(f"pins-lint: FAIL {err}", file=sys.stderr)
        return 1

    print(f"pins-lint: OK ({len(args)} manifest(s) valid; no latest/floating specs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
