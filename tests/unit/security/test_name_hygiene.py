from __future__ import annotations

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


def test_name_hygiene_cli_fails_when_runtime_terms_empty(monkeypatch) -> None:
    monkeypatch.delenv("NAME_HYGIENE_FORBIDDEN_TERMS", raising=False)
    assert main([]) == 2
