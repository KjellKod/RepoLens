from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from repolens import cli


def test_config_schema_human_and_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config", "schema"]) == 0
    human = capsys.readouterr().out
    assert "RepoLens local config schema" in human
    assert "scan.clone_timeout_seconds" in human
    assert "Unknown keys are rejected" in human

    assert cli.main(["config", "schema", "--json"]) == 0
    raw = capsys.readouterr().out
    schema = json.loads(raw)
    assert schema["title"] == "RepoLens local runtime config"
    assert schema["additionalProperties"] is False


def test_config_init_help_explains_pattern_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config", "init", "--help"]) == 0

    out = capsys.readouterr().out
    assert "owner/repo=production" in out
    assert "obsolete-*=retired" in out
    assert "do not add shell quotes" in out
    assert "invalid entries are explained and re-prompted" in out


def test_config_validate_summarizes_exact_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / ".repolens.local.json"
    path.write_text(
        json.dumps(
            {
                "discover": {
                    "taxonomy": {
                        "explicit": {"sentinel-owner/sentinel-alpha": "runtime"},
                        "patterns": [{"glob": "tool-*", "category": "tools"}],
                        "topics": {"mobile": "apps"},
                        "dead": {"sentinel-retired": "retired"},
                    }
                },
                "scan": {"exclude_paths": ["fixtures/"], "clone_timeout_seconds": 45},
                "report": {"selection": {"include": ["runtime", "apps"]}},
            }
        ),
        encoding="utf-8",
    )

    assert cli.main(["config", "validate", str(path)]) == 0

    out = capsys.readouterr().out
    assert f"Config valid: {path}" in out
    assert "explicit=1, patterns=1, topics=1, dead=1" in out
    assert "exclude_paths=1, clone_timeout_seconds=45, syft.catalogers=default" in out
    assert "include=2, header=absent" in out


def test_config_validate_rejects_unknown_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / ".repolens.local.json"
    path.write_text(json.dumps({"scan": {"clone_timeout_second": 45}}), encoding="utf-8")

    assert cli.main(["config", "validate", str(path)]) == 2

    err = capsys.readouterr().err
    assert "scan.clone_timeout_second" in err
    assert "Remove the unknown key" in err


def test_config_init_writes_selected_fields_and_next_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / ".repolens.local.json"
    answers = (
        "\n".join(
            [
                "",
                "runtime",
                "sentinel-owner/sentinel-alpha=runtime",
                "tool-*=tools",
                "mobile=apps",
                "sentinel-retired=retired",
                "fixtures/, vendor/",
                "45",
                "python-package-cataloger",
                "runtime, apps",
                "y",
                "Sentinel",
                "Internal only",
                "",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(answers))

    assert (
        cli.main(["config", "init", "--work-root", str(tmp_path / "work"), "--out", str(path)]) == 0
    )

    values = json.loads(path.read_text(encoding="utf-8"))
    assert values == {
        "discover": {
            "taxonomy": {
                "dead": {"sentinel-retired": "retired"},
                "default_category": "runtime",
                "explicit": {"sentinel-owner/sentinel-alpha": "runtime"},
                "patterns": [{"category": "tools", "glob": "tool-*"}],
                "topics": {"mobile": "apps"},
            }
        },
        "report": {
            "header": {"legal_text": "Internal only", "org_name": "Sentinel"},
            "selection": {"include": ["runtime", "apps"]},
        },
        "scan": {
            "clone_timeout_seconds": 45,
            "exclude_paths": ["fixtures/", "vendor/"],
            "syft": {"catalogers": ["python-package-cataloger"]},
        },
    }
    out = capsys.readouterr().out
    assert "Categories are labels for grouping repositories" in out
    assert f"repolens run --work-root {tmp_path / 'work'} --owner <OWNER> --config {path}" in out
    assert (
        f"repolens --config {path} discover --owner <OWNER> --work-root {tmp_path / 'work'}"
    ) in out


def test_config_init_reprompts_invalid_pattern_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / ".repolens.local.json"
    answers = (
        "\n".join(
            [
                "",
                "PRODUCTION",
                "",
                "obsolete-*",
                "obsolete-*=retired",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(answers))

    assert cli.main(["config", "init", "--out", str(path)]) == 0

    values = json.loads(path.read_text(encoding="utf-8"))
    assert values["discover"]["taxonomy"]["patterns"] == [
        {"category": "retired", "glob": "obsolete-*"}
    ]
    out = capsys.readouterr().out
    assert "Invalid input: pattern category entries must use key=value" in out
    assert "Use glob=category pairs such as obsolete-*=retired" in out
    assert "Do not add quotes in the prompt" in out


def test_config_init_reprompts_invalid_clone_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / ".repolens.local.json"
    answers = (
        "\n".join(
            [
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "not-a-number",
                "300",
                "",
                "",
                "",
            ]
        )
        + "\n"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(answers))

    assert cli.main(["config", "init", "--out", str(path)]) == 0

    values = json.loads(path.read_text(encoding="utf-8"))
    assert values["scan"]["clone_timeout_seconds"] == 300
    out = capsys.readouterr().out
    assert "Invalid input: scan.clone_timeout_seconds must be a positive number" in out
    assert "Use a positive number such as 300" in out


def test_config_init_refuses_overwrite_without_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / ".repolens.local.json"
    path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO("\nn\n"))

    assert cli.main(["config", "init", "--out", str(path)]) == 2

    assert "Refused to overwrite existing config" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == "{}\n"


def test_config_init_rejects_non_json_output_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "bad.toml"
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))

    assert cli.main(["config", "init", "--out", str(path)]) == 2

    err = capsys.readouterr().err
    assert "must end in .json" in err
    assert "JSON-only" in err
    assert not path.exists()


def test_run_startup_prints_active_config_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    work_root = tmp_path / "work"
    work_root.mkdir()
    config_path = work_root / ".repolens.local.json"
    config_path.write_text(
        json.dumps({"scan": {"exclude_paths": ["fixtures/"], "clone_timeout_seconds": 45}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        cli,
        "_report_resume_complete",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(cli, "_load_existing_report_summary", lambda *_args, **_kwargs: None)

    assert (
        cli.main(
            [
                "run",
                "--work-root",
                str(work_root),
                "--owner",
                "sentinel-owner",
                "--yes",
            ]
        )
        == 0
    )

    err = capsys.readouterr().err
    assert "== RepoLens run ==" in err
    assert f"active: {config_path}" in err
    assert "exclude_paths=1, clone_timeout_seconds=45" in err


def test_discover_stage_prints_config_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    work_root = tmp_path / "work"
    work_root.mkdir()
    config_path = work_root / ".repolens.local.json"
    config_path.write_text(
        json.dumps({"discover": {"taxonomy": {"topics": {"mobile": "apps"}}}}),
        encoding="utf-8",
    )

    class Result:
        repository_count = 1
        candidate_count = 1
        hard_exclusion_count = 0
        discovered_path = work_root / "discovered.json"
        candidate_path = work_root / "repos.candidate.md"

    monkeypatch.setattr(cli, "run_discover", lambda **_kwargs: Result())

    assert cli.main(["discover", "--owner", "sentinel-owner", "--work-root", str(work_root)]) == 0

    err = capsys.readouterr().err
    assert "== discover config ==" in err
    assert f"active: {config_path}" in err
    assert "topics=1" in err
