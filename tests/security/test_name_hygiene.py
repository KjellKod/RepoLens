from pathlib import Path

import pytest

from repolens.security.name_hygiene import (
    SYNTHETIC_SENTINEL,
    AllowlistEntry,
    committed_patterns,
    load_forbidden_patterns,
    scan_repository,
    scan_paths,
    validate_allowlist,
)


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.name_hygiene]


def test_offline_name_hygiene_catches_generic_token_and_sentinel(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    token = "ghp_" + "A" * 24
    target.write_text(f"{token}\n{SYNTHETIC_SENTINEL}\n", encoding="utf-8")

    violations = scan_paths(tmp_path, [target], patterns=committed_patterns())

    assert {violation.path for violation in violations} == {"target.txt"}
    assert len(violations) == 2


def test_offline_name_hygiene_scans_committed_security_surfaces() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    assert scan_repository(repo_root, patterns=committed_patterns()) == []


def test_offline_name_hygiene_repo_scan_fails_seeded_bad_content(tmp_path: Path) -> None:
    target = tmp_path / "src" / "seeded.py"
    target.parent.mkdir()
    target.write_text(SYNTHETIC_SENTINEL, encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(SYNTHETIC_SENTINEL, encoding="utf-8")
    usage = tmp_path / "docs" / "usage.md"
    usage.parent.mkdir()
    usage.write_text(SYNTHETIC_SENTINEL, encoding="utf-8")
    skill = tmp_path / ".skills" / "security" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(SYNTHETIC_SENTINEL, encoding="utf-8")
    ai_config = tmp_path / ".ai" / "allowlist.json"
    ai_config.parent.mkdir()
    ai_config.write_text(SYNTHETIC_SENTINEL, encoding="utf-8")

    violations = scan_repository(tmp_path, patterns=committed_patterns())

    assert {violation.path for violation in violations} == {
        ".ai/allowlist.json",
        ".skills/security/SKILL.md",
        "README.md",
        "docs/usage.md",
        "src/seeded.py",
    }


def test_protected_mode_fails_closed_without_live_denylist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOLENS_NAME_HYGIENE_MODE", "protected")
    monkeypatch.delenv("REPOLENS_NAME_HYGIENE_DENYLIST_FILE", raising=False)
    monkeypatch.delenv("REPOLENS_FORBIDDEN_NAMES", raising=False)

    with pytest.raises(RuntimeError, match="denylist is required"):
        load_forbidden_patterns()


def test_allowlist_is_bounded_to_synthetic_fixtures() -> None:
    validate_allowlist(
        (
            AllowlistEntry(
                path_glob="tests/fixtures/security/**",
                pattern="fixture-only",
                reason="synthetic fixture",
            ),
        )
    )

    with pytest.raises(ValueError, match="synthetic fixtures"):
        validate_allowlist(
            (
                AllowlistEntry(
                    path_glob="src/**",
                    pattern="fixture-only",
                    reason="too broad",
                ),
            )
        )
