from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "name_hygiene.py"
LEGACY_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_name_hygiene.py"


def run_name_hygiene(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT.as_posix(), "--root", root.as_posix(), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def run_legacy_guard(
    *paths: Path, forbidden_names: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if forbidden_names is None:
        env.pop("REPOLENS_FORBIDDEN_NAMES", None)
    else:
        env["REPOLENS_FORBIDDEN_NAMES"] = forbidden_names

    return subprocess.run(
        [sys.executable, LEGACY_SCRIPT.as_posix(), *(path.as_posix() for path in paths)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
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
    local_config = tmp_path / "owner.LOCAL.json"
    local_config.write_text(
        json.dumps({"Forbidden_Names": ["Invented-Local-Token"]}),
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


def test_name_hygiene_accepts_runtime_forbidden_names_env(tmp_path: Path) -> None:
    token = "invented-env-token"
    (tmp_path / "visible.txt").write_text(f"{token}\n", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, SCRIPT.as_posix(), "--root", tmp_path.as_posix()],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "REPOLENS_FORBIDDEN_NAMES": token},
    )

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["findings"] == [{"path": "visible.txt", "token_id": "sha256:27f94394dc8f89bb"}]
    assert token not in proc.stdout
    assert token not in proc.stderr


def test_name_hygiene_discovers_default_local_config_upward(tmp_path: Path) -> None:
    local_config = tmp_path / ".name-hygiene.local.json"
    local_config.write_text(
        json.dumps({"forbidden_names": ["invented-upward-token"]}),
        encoding="utf-8",
    )
    scan_root = tmp_path / "nested" / "repo"
    scan_root.mkdir(parents=True)
    (scan_root / "visible.txt").write_text("Invented-Upward-Token\n", encoding="utf-8")

    proc = run_name_hygiene(scan_root, "--require-denylist")

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["denylist_status"] == "present"
    assert payload["findings"] == [{"path": "visible.txt", "token_id": "sha256:f7483a1db8ff60e0"}]
    assert "invented-upward-token" not in proc.stdout
    assert "Invented-Upward-Token" not in proc.stdout


def test_name_hygiene_discovers_default_local_config_from_mother_repo(
    tmp_path: Path,
) -> None:
    mother = tmp_path / "RepoLens"
    worktree = tmp_path / "feature-worktree"
    mother.mkdir()
    subprocess.run(["git", "init"], cwd=mother, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "init",
        ],
        cwd=mother,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "worktree", "add", worktree.as_posix(), "-b", "feature"],
        cwd=mother,
        check=True,
        capture_output=True,
    )
    (mother / ".Name-Hygiene.Local.Json").write_text(
        json.dumps({"forbidden_names": ["invented-mother-token"]}),
        encoding="utf-8",
    )
    (worktree / "visible.txt").write_text("INVENTED-MOTHER-TOKEN\n", encoding="utf-8")

    proc = run_name_hygiene(worktree, "--require-denylist")

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["denylist_status"] == "present"
    assert payload["findings"] == [{"path": "visible.txt", "token_id": "sha256:cb6deeba778edb92"}]
    assert "invented-mother-token" not in proc.stdout
    assert "INVENTED-MOTHER-TOKEN" not in proc.stdout


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


def test_name_hygiene_scans_untracked_nonignored_files_in_git_repo(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "README.md").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "hygiene-test.txt").write_text("invented-untracked-token\n", encoding="utf-8")

    proc = run_name_hygiene(tmp_path, "--forbidden-name", "invented-untracked-token")

    assert proc.returncode == 1
    payload = result_payload(proc)
    assert payload["findings"] == [
        {"path": "hygiene-test.txt", "token_id": "sha256:9ef5bf322198d6a9"}
    ]
    assert "invented-untracked-token" not in proc.stdout
    assert "invented-untracked-token" not in proc.stderr


def test_name_hygiene_tolerates_missing_tracked_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    missing = tmp_path / "missing.txt"
    missing.write_text("invented-missing-token\n", encoding="utf-8")
    subprocess.run(["git", "add", missing.name], cwd=tmp_path, check=True, capture_output=True)
    missing.unlink()

    proc = run_name_hygiene(tmp_path, "--forbidden-name", "invented-missing-token")

    assert proc.returncode == 0
    payload = result_payload(proc)
    assert payload["passed"] is True
    assert payload["findings"] == []


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


def test_legacy_name_hygiene_env_denylist_fails_without_echoing_terms(tmp_path: Path) -> None:
    doc = tmp_path / "notes.md"
    doc.write_text("This mentions internal-demo-name in prose.\n", encoding="utf-8")

    result = run_legacy_guard(doc, forbidden_names="other-name\ninternal-demo-name")

    assert result.returncode == 1
    assert "forbidden-literal" in result.stderr
    assert "denylist-entry" in result.stderr
    assert "internal-demo-name" not in result.stderr
    assert "other-name" not in result.stderr


def test_legacy_name_hygiene_structural_checks_redact_tokens(tmp_path: Path) -> None:
    fixture = tmp_path / "fixtures" / "sample.json"
    fixture.parent.mkdir()
    token = "ghp_" + "0123456789abcdefghijklmnop"
    fixture.write_text(
        f'{{\n  "token": "{token}",\n  "homepage": "https://sample.invalid-name.biz/project"\n}}\n',
        encoding="utf-8",
    )

    result = run_legacy_guard(fixture)

    assert result.returncode == 1
    assert "github-token" in result.stderr
    assert token[:12] not in result.stderr
    assert "redacted-token" in result.stderr
    assert "non-neutral-url" in result.stderr


def test_legacy_name_hygiene_quoted_keyed_domain_fails(tmp_path: Path) -> None:
    fixture = tmp_path / "fixtures" / "sample.json"
    fixture.parent.mkdir()
    fixture.write_text('{"homepage": "sample.invalid-name.biz"}\n', encoding="utf-8")

    result = run_legacy_guard(fixture)

    assert result.returncode == 1
    assert "non-neutral-domain" in result.stderr
