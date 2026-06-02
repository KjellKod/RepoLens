"""Name-hygiene fail-closed contract (formerly tools/name_hygiene.py, AC #7).

The denylist is supplied at test time (never committed). A planted forbidden token
proves the matcher fails closed; a clean acme-* tree passes. These now exercise the
single canonical guard, ``repolens.security.name_hygiene``.
"""

from __future__ import annotations

from pathlib import Path

from repolens.security.name_hygiene import main, normalize_tokens, run

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_acme_tree_passes() -> None:
    exit_code, result = run(
        FIXTURES / "acme_clean_tree",
        normalize_tokens(["forbiddenname", "secret-org"]),
        require_denylist=True,
    )
    assert exit_code == 0
    assert result["passed"] is True
    assert result["findings"] == []


def test_seeded_bad_token_fails() -> None:
    exit_code, result = run(
        FIXTURES / "seeded_bad_token.txt",
        normalize_tokens(["FORBIDDENNAME"]),
        require_denylist=True,
    )
    assert exit_code == 1
    assert result["findings"], "matcher must flag the planted forbidden literal"
    assert result["findings"][0]["path"] == "seeded_bad_token.txt"


def test_matcher_is_case_insensitive() -> None:
    target = FIXTURES / "seeded_bad_token.txt"
    exit_code, _result = run(target, normalize_tokens(["FORBIDDENNAME"]), require_denylist=True)
    assert exit_code == 1


def test_run_empty_denylist_passes_when_not_required() -> None:
    exit_code, result = run(FIXTURES / "seeded_bad_token.txt", [], require_denylist=False)
    assert exit_code == 0
    assert result["denylist_status"] == "absent"


def test_main_fails_closed_when_denylist_unset(monkeypatch, tmp_path: Path) -> None:
    # Run in an isolated dir (no upward .name-hygiene.local.json) with the env unset.
    monkeypatch.delenv("REPOLENS_FORBIDDEN_NAMES", raising=False)
    monkeypatch.delenv("NAME_HYGIENE_FORBIDDEN_TERMS", raising=False)
    monkeypatch.delenv("REPOLENS_NAME_DENYLIST", raising=False)
    (tmp_path / "acme_example.py").write_text('ACME_OWNER = "acme-corp"\n', encoding="utf-8")

    rc = main(["--root", str(tmp_path), "--require-denylist"])
    assert rc == 1, "unconfigured denylist must fail the required gate, not pass vacuously"


def test_main_passes_with_configured_denylist() -> None:
    rc = main(
        [
            "--root",
            str(FIXTURES / "acme_clean_tree"),
            "--forbidden-name",
            "acmecorp",
            "--forbidden-name",
            "realowner",
        ]
    )
    assert rc == 0


def test_main_fails_on_seeded_token() -> None:
    rc = main(
        [
            "--root",
            str(FIXTURES / "seeded_bad_token.txt"),
            "--forbidden-name",
            "FORBIDDENNAME",
        ]
    )
    assert rc == 1
