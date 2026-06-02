#!/usr/bin/env python3
"""Run delegated X2 security canaries or the explicit R0 placeholder contract."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PASSED_RE = re.compile(r"(?P<count>\d+)\s+passed")
X2_GATE = Path("scripts/security_canary_gate.py")
X2_MATRIX = Path("tests/canaries/security/canary_matrix.json")


def placeholder_result() -> dict[str, object]:
    return {
        "canary_suite_status": "absent_pending_x2",
        "delegated": False,
        "guardrail_canaries_green": False,
    }


def validate_placeholder_contract(result: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if result.get("canary_suite_status") != "absent_pending_x2":
        errors.append("placeholder must report canary_suite_status=absent_pending_x2")
    if result.get("delegated") is not False:
        errors.append("placeholder must report delegated=false")
    if result.get("guardrail_canaries_green") is not False:
        errors.append("placeholder must report guardrail_canaries_green=false")
    return errors


def passed_count(output: str) -> int:
    matches = list(PASSED_RE.finditer(output))
    return sum(int(match.group("count")) for match in matches)


def run_delegated_suite(root: Path, suite_path: Path) -> tuple[int, dict[str, object]]:
    command = [sys.executable, "-m", "pytest", suite_path.as_posix(), "-q", "-rA"]
    proc = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = proc.stdout
    errors: list[str] = []
    if proc.returncode != 0:
        errors.append(f"delegated security canary suite failed with exit code {proc.returncode}")
    if "no tests ran" in output.lower() or proc.returncode == 5:
        errors.append("delegated security canary suite collected zero tests")
    if passed_count(output) == 0:
        errors.append("delegated security canary suite had no passing tests")

    result = {
        "canary_suite_status": "delegated_x2" if not errors else "delegated_x2_failed",
        "delegated": True,
        "guardrail_canaries_green": not errors,
        "command": command,
        "errors": errors,
    }
    return (1 if errors else 0), result


def run_x2_gate(root: Path) -> tuple[int, dict[str, object]]:
    command = [sys.executable, X2_GATE.as_posix()]
    proc = subprocess.run(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    errors: list[str] = []
    if proc.returncode != 0:
        errors.append(f"X2 security canary gate failed with exit code {proc.returncode}")

    result = {
        "canary_suite_status": "delegated_x2" if not errors else "delegated_x2_failed",
        "delegated": True,
        "guardrail_canaries_green": not errors,
        "command": command,
        "errors": errors,
    }
    return (1 if errors else 0), result


def run(
    root: Path, suite_path: Path, simulate_broken_placeholder: bool
) -> tuple[int, dict[str, object]]:
    if (root / X2_GATE).exists() and (root / X2_MATRIX).exists():
        return run_x2_gate(root)

    absolute_suite = root / suite_path
    if absolute_suite.exists():
        return run_delegated_suite(root=root, suite_path=suite_path)

    result = placeholder_result()
    if simulate_broken_placeholder:
        result["guardrail_canaries_green"] = True
    errors = validate_placeholder_contract(result)
    if errors:
        result["errors"] = errors
        result["canary_suite_status"] = "placeholder_contract_failed"
    return (1 if errors else 0), result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--suite-path", type=Path, default=Path("tests/security/canaries"))
    parser.add_argument("--simulate-broken-placeholder", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code, result = run(
        root=args.root.resolve(),
        suite_path=args.suite_path,
        simulate_broken_placeholder=args.simulate_broken_placeholder,
    )
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
