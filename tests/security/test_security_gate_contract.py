import json
from pathlib import Path

import pytest

from scripts.security_canary_gate import (
    CanaryMatrix,
    MATRIX_PATH,
    ROOT,
    collect_nodeids,
    load_matrix,
    required_runtime_nodeids,
    validate_active_outcomes,
    validate_collection,
    validate_no_inactive_markers,
)


pytestmark = [pytest.mark.offline, pytest.mark.security]


def test_active_canary_count_matches_collection() -> None:
    matrix = load_matrix(ROOT / MATRIX_PATH)
    collection = collect_nodeids(["-m", "offline and security"])

    validate_collection(matrix, collection)
    validate_no_inactive_markers(matrix)


def test_pending_canaries_have_reasons() -> None:
    matrix = json.loads((ROOT / MATRIX_PATH).read_text(encoding="utf-8"))
    pending = [entry for entry in matrix["canaries"] if entry["status"] == "pending"]

    assert pending
    assert all(entry.get("pending_reason") for entry in pending)


def test_active_canary_runtime_skip_fails_gate(tmp_path: Path) -> None:
    nodeid = "tests/canaries/security/test_demo.py::test_runtime_skip"
    matrix = CanaryMatrix(
        expected_active_count=1,
        active_nodeids=frozenset({nodeid}),
        pending_ids=frozenset(),
    )
    report = tmp_path / "junit.xml"
    report.write_text(
        """
        <testsuite>
          <testcase classname="tests.canaries.security.test_demo" name="test_runtime_skip">
            <skipped message="runtime skip" />
          </testcase>
        </testsuite>
        """,
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="required security tests skipped"):
        validate_active_outcomes(matrix, report)


def test_name_hygiene_runtime_skip_fails_gate(tmp_path: Path) -> None:
    nodeid = "tests/security/test_name_hygiene.py::test_offline_name_hygiene_scans_committed_security_surfaces"
    matrix = CanaryMatrix(
        expected_active_count=0,
        active_nodeids=frozenset(),
        pending_ids=frozenset(),
    )
    report = tmp_path / "junit.xml"
    report.write_text(
        """
        <testsuite>
          <testcase classname="tests.security.test_name_hygiene" name="test_offline_name_hygiene_scans_committed_security_surfaces">
            <skipped message="runtime skip" />
          </testcase>
        </testsuite>
        """,
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="required security tests skipped"):
        validate_active_outcomes(matrix, report, frozenset({nodeid}))


def test_required_runtime_nodeids_include_name_hygiene_collection() -> None:
    matrix = CanaryMatrix(
        expected_active_count=1,
        active_nodeids=frozenset({"tests/canaries/security/test_demo.py::test_canary"}),
        pending_ids=frozenset(),
    )
    required = required_runtime_nodeids(
        matrix,
        frozenset(
            {
                "tests/canaries/security/test_demo.py::test_canary",
                "tests/security/test_name_hygiene.py::test_guard",
                "tests/security/test_other.py::test_not_required",
            }
        ),
    )

    assert required == {
        "tests/canaries/security/test_demo.py::test_canary",
        "tests/security/test_name_hygiene.py::test_guard",
    }
