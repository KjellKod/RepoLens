"""``python3 -m repolens.bootstrap`` runner.

Thin argparse wrapper. The real acquire/cosign/pip runners are not wired here
(F4 does no runtime network); ``--dry-run`` validates the manifest + requirements
and is the only mode exercisable without injecting fetchers. A future F1 CLI can
register a ``repolens bootstrap`` subcommand that injects real runners and calls
``repolens.bootstrap.run(...)``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .errors import BootstrapError
from .orchestrate import (
    EXIT_OK,
    EXIT_USAGE,
)
from .pins import DEFAULT_PINS_PATH
from .scancode import DEFAULT_REQUIREMENTS_PATH, load_requirements


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m repolens.bootstrap",
        description="Verify-and-record the pinned RepoLens toolchain (F4).",
    )
    p.add_argument("--pins", type=Path, default=DEFAULT_PINS_PATH, help="pins.toml path")
    p.add_argument(
        "--requirements",
        type=Path,
        default=DEFAULT_REQUIREMENTS_PATH,
        help="ScanCode hash-pinned requirements path",
    )
    p.add_argument("--dest", type=Path, default=Path("work/tools"), help="binary dest dir")
    p.add_argument(
        "--versions-out",
        type=Path,
        default=Path("work/tool_versions.json"),
        help="where to write tool_versions.json",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the manifest + requirements only; acquire/verify no binaries",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from .pins import load_pins

        pins = load_pins(args.pins)
        load_requirements(args.requirements)
    except BootstrapError as exc:
        print(f"usage/config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.dry_run:
        print(
            f"OK: {len(pins.tools)} tool pins valid; requirements hash-pinned; "
            f"base image {pins.base_image}"
        )
        return EXIT_OK

    # A live bootstrap needs real acquire/cosign/pip runners, which are out of
    # F4's runtime scope (no network here). Direct callers should use
    # repolens.bootstrap.run(...) with injected runners.
    print(
        "note: live bootstrap requires injected acquire/cosign/pip runners; "
        "use --dry-run for offline validation or call repolens.bootstrap.run(...).",
        file=sys.stderr,
    )
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
