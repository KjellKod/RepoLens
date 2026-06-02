from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "name_hygiene.py"


def run_name_hygiene(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT.as_posix(), "--root", root.as_posix(), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def result_payload(proc: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return json.loads(proc.stdout)


def test_name_hygiene_fails_when_forbidden_token_is_seeded(tmp_path: Path) -> None:
    token = "-".join(["invented", "forbidden", "token"])
    seeded = tmp_path / "src" / "note.txt"
    seeded.parent.mkdir()
    seeded.write_text(f"contains {token}\n", encoding="utf-8")

    proc = run_name_hygiene(tmp_path, "--forbidden-name", token)

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["passed"] is False
    assert payload["findings"] == [{"path": "src/note.txt", "token_id": "sha256:466f45107fdf4f94"}]
    assert token not in proc.stdout
    assert token not in proc.stderr


def test_name_hygiene_ci_mode_fails_when_denylist_absent(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("no forbidden runtime inputs\n", encoding="utf-8")

    proc = run_name_hygiene(tmp_path, "--require-denylist")

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["denylist_status"] == "absent"
    assert payload["passed"] is False


def test_name_hygiene_accepts_ignored_local_config_path(tmp_path: Path) -> None:
    local_config = tmp_path / "owner.local.json"
    local_config.write_text(
        json.dumps({"forbidden_names": ["invented-local-token"]}),
        encoding="utf-8",
    )
    (tmp_path / "visible.txt").write_text("invented-local-token\n", encoding="utf-8")

    proc = run_name_hygiene(tmp_path, "--local-config", local_config.as_posix())

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["denylist_status"] == "present"
    assert payload["findings"] == [{"path": "visible.txt", "token_id": "sha256:ee978e4bd10bc74d"}]
    assert "invented-local-token" not in proc.stdout
    assert "invented-local-token" not in proc.stderr


def test_name_hygiene_scans_tracked_local_config_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    local_config = tmp_path / "owner.local.json"
    local_config.write_text("invented-tracked-local-token\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "-f", local_config.name], cwd=tmp_path, check=True, capture_output=True
    )

    proc = run_name_hygiene(tmp_path, "--forbidden-name", "invented-tracked-local-token")

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["findings"] == [
        {"path": "owner.local.json", "token_id": "sha256:8767cbb572cc3644"}
    ]
    assert "invented-tracked-local-token" not in proc.stdout
    assert "invented-tracked-local-token" not in proc.stderr


def test_name_hygiene_skips_ignored_artifact_paths(tmp_path: Path) -> None:
    for skipped_dir in [".quest", ".worktrees", ".pytest_cache", ".venv", "build", "dist"]:
        path = tmp_path / skipped_dir / "artifact.txt"
        path.parent.mkdir(parents=True)
        path.write_text("invented-skipped-token\n", encoding="utf-8")
    (tmp_path / "owner.local.json").write_text(
        json.dumps({"forbidden_names": ["invented-skipped-token"]}),
        encoding="utf-8",
    )
    (tmp_path / "visible.txt").write_text("clean\n", encoding="utf-8")

    proc = run_name_hygiene(tmp_path, "--forbidden-name", "invented-skipped-token")

    assert proc.returncode == 0
    payload = result_payload(proc)
    assert payload["passed"] is True
    assert payload["findings"] == []
