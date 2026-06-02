from __future__ import annotations

import json
from pathlib import Path

from repolens.security.name_hygiene import main, scan_tracked_files
from tests.conftest import git


def test_scan_uses_runtime_forbidden_terms_over_tracked_files(tmp_path: Path) -> None:
    git(tmp_path, "init")
    git(tmp_path, "config", "user.email", "acme@example.invalid")
    git(tmp_path, "config", "user.name", "Acme Tester")
    (tmp_path / "tracked.txt").write_text("acme-hidden-name\n", encoding="utf-8")
    (tmp_path / "untracked.txt").write_text("acme-hidden-name\n", encoding="utf-8")
    git(tmp_path, "add", "tracked.txt")
    findings = scan_tracked_files(tmp_path, ["acme-hidden-name"])
    assert len(findings) == 1
    assert findings[0].path == Path("tracked.txt")


def test_name_hygiene_self_test() -> None:
    assert main(["--self-test"]) == 0


def test_name_hygiene_cli_fails_closed_when_denylist_required_but_empty(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("REPOLENS_FORBIDDEN_NAMES", raising=False)
    monkeypatch.delenv("NAME_HYGIENE_FORBIDDEN_TERMS", raising=False)
    monkeypatch.delenv("REPOLENS_NAME_DENYLIST", raising=False)
    assert main(["--root", tmp_path.as_posix(), "--require-denylist"]) == 1


def test_name_hygiene_cli_passes_when_denylist_absent_and_not_required(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("REPOLENS_FORBIDDEN_NAMES", raising=False)
    monkeypatch.delenv("NAME_HYGIENE_FORBIDDEN_TERMS", raising=False)
    monkeypatch.delenv("REPOLENS_NAME_DENYLIST", raising=False)
    assert main(["--root", tmp_path.as_posix()]) == 0


def test_name_hygiene_cli_missing_root_returns_json_error(monkeypatch, tmp_path, capsys) -> None:
    # A configured denylist + a non-existent --root must produce a clean JSON
    # error and exit 1 — never an uncaught FileNotFoundError traceback.
    monkeypatch.delenv("REPOLENS_FORBIDDEN_NAMES", raising=False)
    monkeypatch.delenv("NAME_HYGIENE_FORBIDDEN_TERMS", raising=False)
    monkeypatch.delenv("REPOLENS_NAME_DENYLIST", raising=False)
    missing = tmp_path / "does-not-exist"
    code = main(["--root", missing.as_posix(), "--forbidden-name", "acme"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert "error" in payload
