from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "run_security_canaries.py"


def run_canaries(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT.as_posix(), "--root", root.as_posix(), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def test_security_canary_runner_invokes_x2_canary_suite_when_present(tmp_path: Path) -> None:
    canary_dir = tmp_path / "tests" / "security" / "canaries"
    canary_dir.mkdir(parents=True)
    (canary_dir / "test_delegated.py").write_text(
        "def test_delegated_canary_passes():\n    assert True\n",
        encoding="utf-8",
    )

    proc = run_canaries(tmp_path)

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["delegated"] is True
    assert payload["guardrail_canaries_green"] is True


def test_security_canary_runner_reports_absent_pending_x2_when_suite_missing(
    tmp_path: Path,
) -> None:
    proc = run_canaries(tmp_path)

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload == {
        "canary_suite_status": "absent_pending_x2",
        "delegated": False,
        "guardrail_canaries_green": False,
    }


def test_security_canary_runner_fails_broken_placeholder_contract(tmp_path: Path) -> None:
    proc = run_canaries(tmp_path, "--simulate-broken-placeholder")

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["canary_suite_status"] == "placeholder_contract_failed"
    assert payload["guardrail_canaries_green"] is True


def test_security_canary_runner_fails_when_delegated_suite_has_no_passing_tests(
    tmp_path: Path,
) -> None:
    canary_dir = tmp_path / "tests" / "security" / "canaries"
    canary_dir.mkdir(parents=True)
    (canary_dir / "test_delegated.py").write_text(
        "import pytest\n\n@pytest.mark.skip(reason='synthetic skip')\n"
        "def test_delegated_canary_skipped():\n    assert True\n",
        encoding="utf-8",
    )

    proc = run_canaries(tmp_path)

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["guardrail_canaries_green"] is False
    assert any("no passing tests" in error for error in payload["errors"])
