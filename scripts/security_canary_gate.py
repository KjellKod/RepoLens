#!/usr/bin/env python3
"""Fail-closed security canary gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import ast
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = Path("tests/canaries/security/canary_matrix.json")
SECURITY_TEST_ROOTS = ("tests/canaries/security", "tests/security")
EXPECTED_NAME_HYGIENE_NODE = "tests/security/test_name_hygiene.py"


@dataclass(frozen=True)
class CanaryMatrix:
    expected_active_count: int
    active_nodeids: frozenset[str]
    pending_ids: frozenset[str]


def load_matrix(path: Path) -> CanaryMatrix:
    payload = json.loads(path.read_text(encoding="utf-8"))
    allowed_statuses = {"active", "pending"}
    for entry in payload["canaries"]:
        status = entry.get("status")
        if status not in allowed_statuses:
            raise SystemExit(f"canary {entry.get('id', '<unknown>')} has invalid status: {status}")
    active_entries = [entry for entry in payload["canaries"] if entry["status"] == "active"]
    pending_entries = [entry for entry in payload["canaries"] if entry["status"] == "pending"]

    active_nodeids = frozenset(entry["nodeid"] for entry in active_entries)
    if len(active_nodeids) != len(active_entries):
        raise SystemExit("duplicate active canary nodeid in matrix")
    if payload["expected_active_count"] != len(active_entries):
        raise SystemExit("matrix expected_active_count does not match active entries")
    for entry in pending_entries:
        if not entry.get("pending_reason"):
            raise SystemExit(f"pending canary {entry.get('id', '<unknown>')} lacks a reason")

    return CanaryMatrix(
        expected_active_count=payload["expected_active_count"],
        active_nodeids=active_nodeids,
        pending_ids=frozenset(entry["id"] for entry in pending_entries),
    )


def collect_nodeids(extra_args: list[str]) -> frozenset[str]:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "--collect-only",
        "--strict-markers",
        *extra_args,
        *SECURITY_TEST_ROOTS,
        "-q",
    ]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(result.stdout + result.stderr)

    nodeids = frozenset(
        line.strip()
        for line in result.stdout.splitlines()
        if "::" in line and not line.startswith("<")
    )
    if not nodeids:
        raise SystemExit("security canary gate collected zero tests")
    return nodeids


def validate_collection(matrix: CanaryMatrix, collected: frozenset[str]) -> None:
    if matrix.expected_active_count != 9:
        raise SystemExit("M0 active security canary count must be exactly 9")
    if len(matrix.active_nodeids) != matrix.expected_active_count:
        raise SystemExit("active security canary matrix count mismatch")

    missing = matrix.active_nodeids - collected
    if missing:
        raise SystemExit("active canaries missing from collection:\n" + "\n".join(sorted(missing)))

    collected_canary_ids = frozenset(
        nodeid for nodeid in collected if nodeid.startswith("tests/canaries/security/")
    )
    extra = collected_canary_ids - matrix.active_nodeids
    if extra:
        raise SystemExit("collected canaries are not registered active matrix entries:\n" + "\n".join(sorted(extra)))

    if not any(nodeid.startswith(EXPECTED_NAME_HYGIENE_NODE) for nodeid in collected):
        raise SystemExit("name hygiene tests were not collected")


def required_runtime_nodeids(matrix: CanaryMatrix, collected: frozenset[str]) -> frozenset[str]:
    name_hygiene_nodes = frozenset(
        nodeid for nodeid in collected if nodeid.startswith(EXPECTED_NAME_HYGIENE_NODE)
    )
    return matrix.active_nodeids | name_hygiene_nodes


def validate_no_inactive_markers(matrix: CanaryMatrix) -> None:
    blocked_markers = ("skip", "skipif", "xfail")
    for nodeid in matrix.active_nodeids:
        path_text, test_name = nodeid.split("::", 1)
        tree = ast.parse((ROOT / path_text).read_text(encoding="utf-8"), filename=path_text)

        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and target.id == "pytestmark":
                        marker_text = ast.unparse(statement.value)
                        if any(marker in marker_text for marker in blocked_markers):
                            raise SystemExit(f"active canary has inactive module marker: {nodeid}")

        function = next(
            (
                statement
                for statement in tree.body
                if isinstance(statement, ast.FunctionDef) and statement.name == test_name
            ),
            None,
        )
        if function is None:
            raise SystemExit(f"active canary function missing from source: {nodeid}")
        for decorator in function.decorator_list:
            marker_text = ast.unparse(decorator)
            if any(marker in marker_text for marker in blocked_markers):
                raise SystemExit(f"active canary has inactive marker: {nodeid}")


def validate_active_outcomes(
    matrix: CanaryMatrix,
    junit_path: Path,
    required_nodeids: frozenset[str] | None = None,
) -> None:
    required = required_nodeids or matrix.active_nodeids
    seen: set[str] = set()
    skipped: list[str] = []
    for case in ET.parse(junit_path).iter("testcase"):
        nodeid = _nodeid_from_junit_case(case)
        if nodeid not in required:
            continue
        seen.add(nodeid)
        if any(child.tag == "skipped" for child in case):
            skipped.append(nodeid)

    missing = required - seen
    if missing:
        raise SystemExit("required security tests missing from runtime report:\n" + "\n".join(sorted(missing)))
    if skipped:
        raise SystemExit("required security tests skipped or xfailed:\n" + "\n".join(sorted(skipped)))


def run_tests(matrix: CanaryMatrix, required_nodeids: frozenset[str]) -> int:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    with tempfile.TemporaryDirectory() as tmp_dir:
        junit_path = Path(tmp_dir) / "security-canaries.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "--strict-markers",
            "-m",
            "offline and security",
            *SECURITY_TEST_ROOTS,
            "-q",
            "--junitxml",
            str(junit_path),
        ]
        result = subprocess.run(command, cwd=ROOT, env=env, check=False)
        if result.returncode == 0:
            validate_active_outcomes(matrix, junit_path, required_nodeids)
        return result.returncode


def _nodeid_from_junit_case(case: ET.Element) -> str:
    name = case.attrib.get("name", "")
    file_path = case.attrib.get("file")
    if file_path:
        return f"{file_path}::{name}"

    classname = case.attrib.get("classname", "")
    if classname:
        path = classname.replace(".", "/") + ".py"
        return f"{path}::{name}"
    return name


def main() -> int:
    matrix = load_matrix(ROOT / MATRIX_PATH)
    collected = collect_nodeids(["-m", "offline and security"])
    validate_collection(matrix, collected)
    validate_no_inactive_markers(matrix)
    return run_tests(matrix, required_runtime_nodeids(matrix, collected))


if __name__ == "__main__":
    raise SystemExit(main())
