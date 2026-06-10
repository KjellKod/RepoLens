#!/usr/bin/env python3
"""Run the offline Sketch2md-style release pilot rehearsal."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from repolens import cli  # noqa: E402
from repolens.testing.fixtures import build_release_demo_work_root  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        help="Directory for the synthetic work root; defaults to a temporary directory.",
    )
    args = parser.parse_args(argv)
    if args.out is None:
        work_root = Path(tempfile.mkdtemp(prefix="repolens-release-pilot-"))
    else:
        work_root = args.out
        work_root.mkdir(parents=True, exist_ok=True)
    build_release_demo_work_root(work_root)
    code = cli.main(
        [
            "release",
            "--work-root",
            str(work_root),
            "--artifact",
            str(work_root / "dist" / "worker.js"),
            "--target",
            "js-bundle",
        ]
    )
    print("Pilot artifacts:")
    for filename in (
        "release.policy.json",
        "release.review.md",
        "release.licenses.json",
        "release.notices.md",
        "release.notices.txt",
    ):
        print(work_root / "release" / filename)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
