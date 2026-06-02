#!/usr/bin/env python3
"""Scheduled/manual live-smoke orchestration for trusted default-branch workflow code."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _runtime_value(cli_value: str | None, env_name: str) -> str | None:
    value = cli_value or os.environ.get(env_name)
    if value and value.strip():
        return value.strip()
    return None


def _write_summary(result: dict[str, object]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = [
        "### Live smoke result",
        "",
        f"dogfood_status={result['dogfood_status']}",
        f"pending_capability={str(result['pending_capability']).lower()}",
    ]
    if result.get("pending_reason"):
        lines.append(f"pending_reason={result['pending_reason']}")
    content = "\n".join(lines) + "\n"
    if summary_path:
        Path(summary_path).write_text(content, encoding="utf-8")
    else:
        print(content, file=sys.stderr)


def run(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    owner = _runtime_value(args.owner, "RPL_LIVE_OWNER")
    repository = _runtime_value(args.repository, "RPL_LIVE_REPOSITORY")
    token_present = bool(os.environ.get("RPL_LIVE_TOKEN") or os.environ.get("GITHUB_TOKEN"))

    if args.mode == "live" and not owner:
        return 2, {
            "dogfood_status": "input_error",
            "pending_capability": False,
            "pending_reason": None,
            "error": "runtime owner input is required for live mode",
        }

    cli = shutil.which("repolens")
    if cli is None:
        return 0, {
            "dogfood_status": "pending_capability",
            "pending_capability": True,
            "pending_reason": "repolens_cli_unavailable",
            "runtime_owner_supplied": owner is not None,
            "runtime_repository_supplied": repository is not None,
            "token_present": token_present,
        }

    proc = subprocess.run(
        [cli, "--help"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        return 1, {
            "dogfood_status": "cli_probe_failed",
            "pending_capability": False,
            "pending_reason": None,
            "error": "repolens CLI probe failed",
        }

    return 0, {
        "dogfood_status": "pending_capability",
        "pending_capability": True,
        "pending_reason": "repolens_smoke_command_unavailable",
        "cli_present": True,
        "runtime_owner_supplied": owner is not None,
        "runtime_repository_supplied": repository is not None,
        "token_present": token_present,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["r0", "live"], default="r0")
    parser.add_argument("--owner")
    parser.add_argument("--repository")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code, result = run(args)
    print(json.dumps(result, sort_keys=True))
    _write_summary(result)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
