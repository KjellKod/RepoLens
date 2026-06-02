from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "live_smoke.py"


def run_live_smoke(*args: str, path: str = "") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("RPL_LIVE_OWNER", None)
    env.pop("RPL_LIVE_REPOSITORY", None)
    env["PATH"] = path
    return subprocess.run(
        [sys.executable, SCRIPT.as_posix(), *args],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_live_smoke_requires_runtime_owner_for_live_mode() -> None:
    proc = run_live_smoke("--mode", "live")

    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["dogfood_status"] == "input_error"
    assert "runtime owner input is required" in payload["error"]


def test_live_smoke_pending_capability_is_not_success() -> None:
    proc = run_live_smoke("--mode", "r0", "--owner", "synthetic-owner")

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["dogfood_status"] == "pending_capability"
    assert payload["pending_capability"] is True
    assert payload["pending_reason"] == "repolens_cli_unavailable"


def test_live_smoke_cli_help_probe_is_not_dogfood_success(tmp_path: Path) -> None:
    cli = tmp_path / "repolens"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o755)

    proc = run_live_smoke(
        "--mode",
        "r0",
        "--owner",
        "synthetic-owner",
        "--repository",
        "synthetic-repository",
        path=tmp_path.as_posix(),
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["dogfood_status"] == "pending_capability"
    assert payload["pending_capability"] is True
    assert payload["pending_reason"] == "repolens_smoke_command_unavailable"
