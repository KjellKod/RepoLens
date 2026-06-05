from __future__ import annotations

import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repolens import cli
from repolens.data import store
from repolens.scan.runner import RepoScanOutcome, ScanReport


class _TtyStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


def _discover_result(work_root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        repository_count=2,
        candidate_count=2,
        hard_exclusion_count=0,
        discovered_path=work_root / "discovered.json",
        candidate_path=work_root / "repos.candidate.md",
    )


def _write_report(out_dir: Path, rows: int = 1) -> cli.CommandResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["name,spdx_id"]
    lines.extend(f"sentinel-lib-{index},MIT" for index in range(rows))
    (out_dir / "report.main.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "report.main.md").write_text("# report\n", encoding="utf-8")
    (out_dir / "report.main.docx").write_bytes(b"docx")
    return cli.CommandResult(cli.CommandStatus.SUCCESS, "wrote report")


def _set_mtime(path: Path, timestamp: float) -> None:
    os.utime(path, (timestamp, timestamp))


def _patch_common_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    work_root = tmp_path / "work"
    monkeypatch.setattr(
        cli, "load_config", lambda _root, _path, **_kwargs: cli.Config(values={}, sources=())
    )
    monkeypatch.setattr(cli, "run_discover", lambda **_kwargs: _discover_result(work_root))
    monkeypatch.setattr(
        cli,
        "_run_scan_stage",
        lambda _args: ScanReport((RepoScanOutcome("sentinel-alpha", "scanned"),)),
    )

    def resolve(args, summary):
        summary.repo_refs.add("sentinel-alpha")
        return {"sentinel-alpha"}

    monkeypatch.setattr(cli, "_run_resolve_stage", resolve)
    monkeypatch.setattr(
        cli,
        "_flag_stage",
        lambda _args: cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "flagged 0 open"),
    )
    monkeypatch.setattr(
        cli,
        "_shortlist_stage",
        lambda _args: cli.CommandResult(cli.CommandStatus.SUCCESS, "settled"),
    )
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: 0)
    monkeypatch.setattr(cli, "_report", lambda args: _write_report(Path(args.out_dir), rows=1))
    return work_root


def test_run_full_pipeline_writes_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert (out_dir / "report.main.csv").exists()


def test_run_defaults_out_dir_under_work_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--yes",
        ]
    )

    assert code == 0
    assert (work_root / "reports" / "report.main.csv").exists()


def test_report_command_defaults_out_dir_under_work_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    resolved_record: dict[str, object],
) -> None:
    from repolens.config import Config

    work_root = tmp_path / "work"
    store.write_resolved(
        work_root,
        "sentinel-alpha",
        [{**resolved_record, "repo": "sentinel-alpha"}],
    )
    monkeypatch.setattr(
        cli, "load_config", lambda _root, _path, **_kwargs: Config(values={}, sources=())
    )

    code = cli.main(["report", "--work-root", str(work_root)])

    assert code == 0
    assert (work_root / "reports" / "report.main.md").exists()
    assert (work_root / "reports" / "report.main.csv").exists()


def test_run_yes_no_header_skips_docx_via_report_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    resolved_record: dict[str, object],
) -> None:
    from repolens.config import Config

    work_root = tmp_path / "work"
    out_dir = tmp_path / "reports"
    config = Config(values={"report": {}}, sources=())
    store.write_resolved(
        work_root,
        "sentinel-alpha",
        [{**resolved_record, "repo": "sentinel-alpha"}],
    )
    captured: dict[str, object] = {}
    real_render_main_report = cli.render_main_report

    def render_main_report(*args: object, **kwargs: object) -> object:
        captured["owner"] = kwargs.get("owner")
        captured["interactive"] = kwargs.get("interactive")
        return real_render_main_report(*args, **kwargs)

    def flag(args: object) -> cli.CommandResult:
        del args
        (work_root / "inventory.json").write_text("{}\n", encoding="utf-8")
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "flagged 0 open")

    def shortlist(args: object) -> cli.CommandResult:
        del args
        store.atomic_write_json(
            work_root / "shortlist.json",
            {
                "schema_version": "1.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "open_count": 0,
                "items": [],
            },
        )
        (work_root / "shortlist.md").write_text("settled\n", encoding="utf-8")
        return cli.CommandResult(cli.CommandStatus.SUCCESS, "settled")

    stderr = io.StringIO()
    monkeypatch.setattr(cli, "load_config", lambda _root, _path, **_kwargs: config)
    monkeypatch.setattr(cli, "run_discover", lambda **_kwargs: _discover_result(work_root))
    monkeypatch.setattr(cli, "_run_scan_stage", lambda _args: None)
    monkeypatch.setattr(cli, "_run_resolve_stage", lambda _args, _summary: {"sentinel-alpha"})
    monkeypatch.setattr(cli, "_flag_stage", flag)
    monkeypatch.setattr(cli, "_shortlist_stage", shortlist)
    monkeypatch.setattr(cli, "render_main_report", render_main_report)
    monkeypatch.setattr("sys.stderr", stderr)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert captured == {"owner": "sentinel-owner", "interactive": False}
    assert "docx skipped (no report.header)" in stderr.getvalue()
    assert (out_dir / "report.main.md").exists()
    assert (out_dir / "report.main.csv").exists()
    assert not (out_dir / "report.main.docx").exists()


def test_run_resolve_stage_resolves_every_scanned_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sbom: dict[str, object]
) -> None:
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        store.write_sbom(tmp_path, repo_ref, {**sbom, "repo": repo_ref})
    calls: list[str] = []

    def fake_resolve(work_root: Path, repo_ref: str) -> Path:
        calls.append(repo_ref)
        store.write_resolved(
            work_root,
            repo_ref,
            [
                {
                    "name": f"{repo_ref}-lib",
                    "version": "1.0.0",
                    "repo": repo_ref,
                    "purl": f"pkg:pypi/{repo_ref}-lib@1.0.0",
                    "declared_license_raw": "MIT",
                    "spdx_id": "MIT",
                    "evidence": {
                        "source_layer": "syft",
                        "url": "https://example.invalid/sentinel-license",
                        "anchor": "MIT",
                    },
                    "tags": {
                        "origin": "third-party-oss",
                        "scope": "runtime",
                        "distribution": "server",
                    },
                    "modified": "unknown",
                }
            ],
        )
        return tmp_path / "work" / repo_ref / "resolved.ndjson"

    monkeypatch.setattr("repolens.resolve.run_resolve", fake_resolve)
    args = SimpleNamespace(work_root=tmp_path, quiet=True)
    summary = cli.RunSummary()

    resolved = cli._run_resolve_stage(args, summary)

    assert resolved == {"sentinel-alpha", "sentinel-beta"}
    assert calls == ["sentinel-alpha", "sentinel-beta"]


def test_run_resolve_stage_writes_scancode_record_from_stored_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo_ref = "sentinel-alpha"
    store.write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/sentinel-alpha",
            "artifacts": [
                {
                    "name": "fixture-lib",
                    "version": None,
                    "type": "unknown",
                    "licenses": [],
                    "locations": ["vendor/fixture-lib/package.json"],
                }
            ],
        },
    )
    staged = tmp_path / "staged-source"
    package_dir = staged / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text('{"name":"fixture-lib"}\n', encoding="utf-8")
    store.replace_source_snapshot(tmp_path, repo_ref, staged)

    def runner(argv: list[str], *, timeout: float):
        del argv, timeout
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"files":[{"license_expression_spdx":"Apache-2.0"}]}',
                "stderr": "",
            },
        )()

    monkeypatch.setattr(
        "repolens.resolve.stage.resolve_scancode_path",
        lambda work_root: Path(work_root) / "tools" / "scancode",
    )
    monkeypatch.setattr("repolens.resolve.scancode._default_command_runner", runner)
    summary = cli.RunSummary()

    resolved = cli._run_resolve_stage(SimpleNamespace(work_root=tmp_path, quiet=True), summary)

    records = list(store.iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert resolved == {repo_ref}
    assert records[0]["spdx_id"] == "Apache-2.0"
    assert records[0]["evidence"]["source_layer"] == "scancode"


def test_run_resolve_stage_prints_scancode_retry_notice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
) -> None:
    repo_ref = "sentinel-alpha"
    store.write_sbom(tmp_path, repo_ref, {**sbom, "repo": repo_ref})

    def fake_resolve(work_root: Path, current_repo_ref: str) -> Path:
        store.write_resolved(
            work_root,
            current_repo_ref,
            [
                {
                    **resolved_record,
                    "repo": current_repo_ref,
                    "evidence": {
                        "source_layer": "scancode",
                        "anchor": "unresolved:scancode_tool_unavailable",
                    },
                }
            ],
        )
        return store.repo_dir(work_root, current_repo_ref) / "resolved.ndjson"

    stderr = io.StringIO()
    monkeypatch.setattr("repolens.resolve.run_resolve", fake_resolve)
    monkeypatch.setattr("sys.stderr", stderr)

    resolved = cli._run_resolve_stage(
        SimpleNamespace(work_root=tmp_path, quiet=False),
        cli.RunSummary(),
    )

    assert resolved == {repo_ref}
    output = stderr.getvalue()
    assert "== Resolve Follow-Up ==" in output
    assert "unresolved:scancode_tool_unavailable" in output
    assert f"repolens resolve --work-root {tmp_path} --retry-scancode" in output
    assert f"repolens flag --work-root {tmp_path}" in output


def test_resolve_stage_prints_scancode_retry_guidance_when_needed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
) -> None:
    repo_ref = "sentinel-alpha"
    store.write_sbom(tmp_path, repo_ref, {**sbom, "repo": repo_ref})

    def fake_resolve(work_root: Path, current_repo_ref: str, **_kwargs: object) -> Path:
        store.write_resolved(
            work_root,
            current_repo_ref,
            [
                {
                    **resolved_record,
                    "repo": current_repo_ref,
                    "evidence": {
                        "source_layer": "scancode",
                        "anchor": "unresolved:scancode_tool_unavailable",
                    },
                }
            ],
        )
        return store.repo_dir(work_root, current_repo_ref) / "resolved.ndjson"

    monkeypatch.setattr("repolens.resolve.run_resolve", fake_resolve)

    result = cli._resolve_stage(
        SimpleNamespace(
            work_root=tmp_path,
            repo_ref=None,
            source_root=None,
            enable_mobile_native=False,
            detect_conflicts=False,
            retry_scancode=False,
        )
    )

    assert result.status == cli.CommandStatus.SUCCESS
    assert "ScanCode was unavailable during resolve" in result.message
    assert "unresolved:scancode_tool_unavailable" in result.message
    assert f"repolens resolve --work-root {tmp_path} --retry-scancode" in result.message
    assert f"repolens flag --work-root {tmp_path}" in result.message


def test_resolve_retry_scancode_only_reruns_matching_repos(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
) -> None:
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        store.write_sbom(tmp_path, repo_ref, {**sbom, "repo": repo_ref})

    retry_record = {
        **resolved_record,
        "repo": "sentinel-alpha",
        "name": "retry-lib",
        "evidence": {
            "source_layer": "scancode",
            "anchor": "unresolved:scancode_tool_unavailable",
        },
    }
    settled_record = {**resolved_record, "repo": "sentinel-beta", "name": "settled-lib"}
    store.write_resolved(tmp_path, "sentinel-alpha", [retry_record])
    store.write_resolved(tmp_path, "sentinel-beta", [settled_record])

    calls: list[str] = []

    def fake_resolve(work_root: Path, repo_ref: str, **_kwargs: object) -> Path:
        calls.append(repo_ref)
        store.write_resolved(work_root, repo_ref, [{**resolved_record, "repo": repo_ref}])
        return store.repo_dir(work_root, repo_ref) / "resolved.ndjson"

    monkeypatch.setattr("repolens.resolve.run_resolve", fake_resolve)

    result = cli._resolve_stage(
        SimpleNamespace(
            work_root=tmp_path,
            repo_ref=None,
            source_root=None,
            enable_mobile_native=False,
            detect_conflicts=False,
            retry_scancode=True,
        )
    )

    assert result.status == cli.CommandStatus.SUCCESS
    assert calls == ["sentinel-alpha"]
    assert "retried ScanCode; wrote resolved.ndjson" in result.message
    assert "repolens flag --work-root" in result.message


def test_resolve_retry_scancode_noops_when_no_prior_tool_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sbom: dict[str, object],
    resolved_record: dict[str, object],
) -> None:
    store.write_sbom(tmp_path, "sentinel-alpha", {**sbom, "repo": "sentinel-alpha"})
    store.write_resolved(tmp_path, "sentinel-alpha", [resolved_record])

    def fail_resolve(*_args: object, **_kwargs: object) -> Path:
        raise AssertionError("retry must not resolve repos without scancode-tool failures")

    monkeypatch.setattr("repolens.resolve.run_resolve", fail_resolve)

    result = cli._resolve_stage(
        SimpleNamespace(
            work_root=tmp_path,
            repo_ref=None,
            source_root=None,
            enable_mobile_native=False,
            detect_conflicts=False,
            retry_scancode=True,
        )
    )

    assert result.status == cli.CommandStatus.SUCCESS
    assert "No repos need ScanCode retry" in result.message
    assert "repolens flag --work-root" in result.message


def test_shortlist_open_message_explains_ai_proposal_workflow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shortlist_md = tmp_path / "shortlist.md"
    shortlist_json = tmp_path / "shortlist.json"

    def fake_shortlist(_work_root: Path, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            shortlist_json_path=shortlist_json,
            shortlist_md_path=shortlist_md,
            open_count=3,
            item_count=5,
            contexts_path=None,
        )

    monkeypatch.setattr("repolens.shortlist.run_shortlist", fake_shortlist)

    result = cli._shortlist_stage(
        SimpleNamespace(
            work_root=tmp_path,
            identity=None,
            emit_contexts=None,
            proposals=None,
        )
    )

    assert result.status == cli.CommandStatus.FINDINGS_OPEN
    assert "--emit-contexts" in result.message
    assert "$repolens review every row" in result.message
    assert "--proposals" in result.message
    assert "shortlist.review.md" in result.message
    assert "[x]" in result.message
    assert "[r]" in result.message


def test_shortlist_open_after_context_emit_points_to_skill_next(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    contexts_path = tmp_path / "shortlist.contexts.json"

    def fake_shortlist(_work_root: Path, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            shortlist_json_path=tmp_path / "shortlist.json",
            shortlist_md_path=tmp_path / "shortlist.md",
            open_count=3,
            item_count=5,
            contexts_path=contexts_path,
        )

    monkeypatch.setattr("repolens.shortlist.run_shortlist", fake_shortlist)

    result = cli._shortlist_stage(
        SimpleNamespace(
            work_root=tmp_path,
            identity=None,
            emit_contexts=contexts_path,
            proposals=None,
        )
    )

    assert result.status == cli.CommandStatus.FINDINGS_OPEN
    assert "contexts are ready" in result.message
    assert "$repolens review every row" in result.message
    assert str(contexts_path) in result.message
    assert f"--proposals {tmp_path / 'shortlist.proposals.json'}" in result.message


def test_resume_with_scan_artifact_does_not_regenerate_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    candidate = work_root / "repos.candidate.md"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("sentinel unticked state\n", encoding="utf-8")
    store.write_sbom(work_root, "sentinel-alpha", _empty_sbom("sentinel-alpha"))

    def fail_discover(**_kwargs):
        raise AssertionError("discover should not run on resume after scan artifacts")

    monkeypatch.setattr(cli, "run_discover", fail_discover)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 0
    assert candidate.read_text(encoding="utf-8") == "sentinel unticked state\n"


def test_resume_lists_persisted_scan_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    (work_root / "repos.candidate.md").parent.mkdir(parents=True)
    (work_root / "repos.candidate.md").write_text("sentinel state\n", encoding="utf-8")
    store.write_sbom(work_root, "sentinel-ok", _empty_sbom("sentinel-ok"))
    failed_dir = store.repo_dir(work_root, "sentinel-private")
    failed_dir.mkdir(parents=True)
    store.atomic_write_json(
        failed_dir / "scan.status.json",
        {"status": "failed", "error": "private repo needs auth"},
    )
    monkeypatch.setattr(cli, "_run_scan_stage", lambda _args: None)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 1


def test_run_scan_stage_passes_runtime_scan_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from repolens.scan import inputs as scan_inputs
    from repolens.scan import runner as scan_runner

    work_root = tmp_path / "work"
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        scan_inputs,
        "load_discover_approved_repo_specs",
        lambda _work_root, repo_spec_type: [
            repo_spec_type("sentinel-alpha", "https://example.invalid/sentinel-alpha")
        ],
    )
    monkeypatch.setattr(cli, "_ensure_syft_for_scan", lambda _args: tmp_path / "syft")

    def fake_scan_repos(work_root_arg: Path, repos: list[object], **kwargs: object) -> ScanReport:
        captured["work_root"] = work_root_arg
        captured["repos"] = repos
        captured.update(kwargs)
        return ScanReport((RepoScanOutcome("sentinel-alpha", "scanned"),))

    monkeypatch.setattr(scan_runner, "scan_repos", fake_scan_repos)
    args = SimpleNamespace(
        work_root=work_root,
        runtime_config=SimpleNamespace(
            values={
                "scan": {
                    "clone_timeout_seconds": 17.0,
                    "exclude_paths": ["local-only/"],
                    "syft": {"catalogers": ["python-package-cataloger"]},
                }
            }
        ),
        quiet=True,
        timeout=None,
        clone_timeout=None,
        yes=True,
    )

    report = cli._run_scan_stage(args)

    assert report is not None
    assert captured["work_root"] == work_root
    assert captured["exclude_paths"] == ("local-only",)
    assert captured["syft_catalogers"] == ("python-package-cataloger",)
    assert captured["clone_timeout_seconds"] == 17.0


def test_run_scan_stage_passes_clone_timeout_separately_from_syft_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from repolens.scan import inputs as scan_inputs
    from repolens.scan import runner as scan_runner

    work_root = tmp_path / "work"
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        scan_inputs,
        "load_discover_approved_repo_specs",
        lambda _work_root, repo_spec_type: [
            repo_spec_type("sentinel-alpha", "https://example.invalid/sentinel-alpha")
        ],
    )
    monkeypatch.setattr(cli, "_ensure_syft_for_scan", lambda _args: tmp_path / "syft")

    def fake_scan_repos(work_root_arg: Path, repos: list[object], **kwargs: object) -> ScanReport:
        del work_root_arg, repos
        captured.update(kwargs)
        return ScanReport((RepoScanOutcome("sentinel-alpha", "scanned"),))

    monkeypatch.setattr(scan_runner, "scan_repos", fake_scan_repos)
    args = SimpleNamespace(
        work_root=work_root,
        runtime_config=SimpleNamespace(values={"scan": {"clone_timeout_seconds": 17.0}}),
        quiet=True,
        timeout=5.0,
        clone_timeout=9.0,
        yes=True,
    )

    cli._run_scan_stage(args)

    assert captured["timeout_seconds"] == 5.0
    assert captured["clone_timeout_seconds"] == 9.0


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "--work-root", "work", "--clone-timeout", "0"],
        ["scan", "--work-root", "work", "--clone-timeout", "nan"],
        ["run", "--work-root", "work", "--owner", "sentinel-owner", "--clone-timeout", "-1"],
    ],
)
def test_clone_timeout_rejects_non_positive_or_non_finite_values(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(argv) == 2
    assert "--clone-timeout must be a positive number of seconds" in capsys.readouterr().err


def test_existing_report_with_persisted_scan_failure_stays_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"
    store.write_sbom(work_root, "sentinel-ok", _empty_sbom("sentinel-ok"))
    resolved_dir = store.repo_dir(work_root, "sentinel-ok")
    resolved_dir.mkdir(parents=True, exist_ok=True)
    (resolved_dir / "resolved.ndjson").write_text("{}\n", encoding="utf-8")
    failed_dir = store.repo_dir(work_root, "sentinel-private")
    failed_dir.mkdir(parents=True)
    store.atomic_write_json(
        failed_dir / "scan.status.json",
        {"status": "failed", "error": "private repo needs auth"},
    )
    _write_report(out_dir, rows=1)

    def fail_scan(_args):
        raise AssertionError("completed report resume should not rerun scan")

    monkeypatch.setattr(cli, "_run_scan_stage", fail_scan)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 1


def test_partial_report_artifact_does_not_short_circuit_fresh_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"
    out_dir.mkdir()
    (out_dir / "report.main.md").write_text("stale partial report\n", encoding="utf-8")
    calls: list[str] = []

    def discover(**_kwargs):
        calls.append("discover")
        return _discover_result(work_root)

    monkeypatch.setattr(cli, "run_discover", discover)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert calls == ["discover"]
    assert (out_dir / "report.main.csv").exists()


def test_complete_report_without_work_artifacts_does_not_short_circuit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"
    _write_report(out_dir, rows=1)
    calls: list[str] = []

    def discover(**_kwargs):
        calls.append("discover")
        return _discover_result(work_root)

    monkeypatch.setattr(cli, "run_discover", discover)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert calls == ["discover"]


def test_complete_report_without_shortlist_state_runs_flag_shortlist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"
    store.write_sbom(work_root, "sentinel-alpha", _empty_sbom("sentinel-alpha"))
    resolved_dir = store.repo_dir(work_root, "sentinel-alpha")
    resolved_dir.mkdir(parents=True, exist_ok=True)
    (resolved_dir / "resolved.ndjson").write_text("{}\n", encoding="utf-8")
    _write_report(out_dir, rows=1)
    calls: list[str] = []

    def flag(_args):
        calls.append("flag")
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "flagged")

    def shortlist(_args):
        calls.append("shortlist")
        return cli.CommandResult(cli.CommandStatus.SUCCESS, "settled")

    monkeypatch.setattr(cli, "_flag_stage", flag)
    monkeypatch.setattr(cli, "_shortlist_stage", shortlist)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert calls == ["flag", "shortlist"]


def test_stale_flag_outputs_rerun_after_new_resolved_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    store.write_sbom(work_root, "sentinel-alpha", _empty_sbom("sentinel-alpha"))
    resolved_dir = store.repo_dir(work_root, "sentinel-alpha")
    resolved_dir.mkdir(parents=True, exist_ok=True)
    resolved_path = resolved_dir / "resolved.ndjson"
    resolved_path.write_text("{}\n", encoding="utf-8")
    (work_root / "inventory.json").write_text("{}\n", encoding="utf-8")
    (work_root / "shortlist.json").write_text('{"open_count":0,"items":[]}\n', encoding="utf-8")
    (work_root / "shortlist.md").write_text("settled\n", encoding="utf-8")
    for stale_path in (
        work_root / "inventory.json",
        work_root / "shortlist.json",
        work_root / "shortlist.md",
    ):
        _set_mtime(stale_path, 10)
    _set_mtime(resolved_path, 20)
    calls: list[str] = []

    def flag(_args):
        calls.append("flag")
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "flagged")

    monkeypatch.setattr(cli, "_flag_stage", flag)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 0
    assert calls == ["flag"]


def test_report_resume_currency_is_config_aware_for_skipped_docx(tmp_path: Path) -> None:
    from repolens.config import Config

    work_root = tmp_path / "work"
    out_dir = tmp_path / "reports"
    resolved_dir = store.repo_dir(work_root, "sentinel-alpha")
    resolved_dir.mkdir(parents=True, exist_ok=True)
    resolved_path = resolved_dir / "resolved.ndjson"
    resolved_path.write_text("{}\n", encoding="utf-8")
    (work_root / "inventory.json").write_text("{}\n", encoding="utf-8")
    store.atomic_write_json(
        work_root / "shortlist.json",
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 0,
            "items": [],
        },
    )
    (work_root / "shortlist.md").write_text("settled\n", encoding="utf-8")
    out_dir.mkdir(parents=True, exist_ok=True)
    # A prior `--yes` run with no header skipped the docx: only md/csv exist.
    (out_dir / "report.main.md").write_text("# report\n", encoding="utf-8")
    (out_dir / "report.main.csv").write_text("name,spdx_id\n", encoding="utf-8")
    for input_path in (
        resolved_path,
        work_root / "inventory.json",
        work_root / "shortlist.json",
        work_root / "shortlist.md",
    ):
        _set_mtime(input_path, 10)
    for report_path in out_dir.iterdir():
        _set_mtime(report_path, 20)

    no_header = Config(values={"report": {}}, sources=())
    with_header = Config(
        values={"report": {"header": {"org_name": "Org", "legal_text": "Legal"}}},
        sources=(),
    )

    # No header configured: md/csv are sufficient, so resume short-circuits.
    assert cli._report_resume_complete(work_root, out_dir, {"sentinel-alpha"}, no_header) is True
    # Header now configured: the missing docx must force a re-run (no stranding).
    assert cli._report_resume_complete(work_root, out_dir, {"sentinel-alpha"}, with_header) is False


def test_stale_report_reruns_when_inputs_are_newer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    out_dir = tmp_path / "reports"
    store.write_sbom(work_root, "sentinel-alpha", _empty_sbom("sentinel-alpha"))
    resolved_dir = store.repo_dir(work_root, "sentinel-alpha")
    resolved_dir.mkdir(parents=True, exist_ok=True)
    resolved_path = resolved_dir / "resolved.ndjson"
    resolved_path.write_text("{}\n", encoding="utf-8")
    (work_root / "inventory.json").write_text("{}\n", encoding="utf-8")
    (work_root / "shortlist.json").write_text('{"open_count":0,"items":[]}\n', encoding="utf-8")
    (work_root / "shortlist.md").write_text("settled\n", encoding="utf-8")
    _write_report(out_dir, rows=1)
    _set_mtime(resolved_path, 20)
    for input_path in (
        work_root / "inventory.json",
        work_root / "shortlist.json",
        work_root / "shortlist.md",
    ):
        _set_mtime(input_path, 30)
    for report_path in out_dir.iterdir():
        _set_mtime(report_path, 25)
    calls: list[str] = []

    def report(args):
        calls.append("report")
        return _write_report(Path(args.out_dir), rows=1)

    monkeypatch.setattr(cli, "_report", report)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(out_dir),
            "--yes",
        ]
    )

    assert code == 0
    assert calls == ["report"]


def test_interactive_discover_pause_proceeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    stderr = _TtyStringIO()
    monkeypatch.setattr("sys.stdin", _TtyStringIO("\n"))
    monkeypatch.setattr("sys.stderr", stderr)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
        ]
    )

    assert code == 0
    assert "Review" in stderr.getvalue()


def test_yes_does_not_prompt_at_discover(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)

    def fail_readline() -> str:
        raise AssertionError("run --yes must not read stdin")

    monkeypatch.setattr("sys.stdin.readline", fail_readline)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 0


def test_no_tty_without_yes_does_not_prompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FailReadlineStringIO(io.StringIO):
        def readline(self, *_args: object, **_kwargs: object) -> str:
            raise AssertionError("non-interactive run without --yes must not read stdin")

    work_root = _patch_common_success(monkeypatch, tmp_path)
    monkeypatch.setattr("sys.stdin", FailReadlineStringIO())
    monkeypatch.setattr("sys.stderr", io.StringIO())

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
        ]
    )

    assert code == 0


def test_open_shortlist_noninteractive_exits_without_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: 1)

    def fail_report(_args):
        raise AssertionError("report must not run while shortlist is open")

    monkeypatch.setattr(cli, "_report", fail_report)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 1
    assert not (tmp_path / "reports" / "report.main.csv").exists()


def test_run_yes_open_shortlist_emits_contexts_without_proposal_or_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: 1)
    calls: list[tuple[Path | None, Path | None]] = []

    def shortlist(args):
        calls.append((args.emit_contexts, args.proposals))
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "open")

    def fail_report(_args):
        raise AssertionError("report must not run while shortlist is open")

    monkeypatch.setattr(cli, "_shortlist_stage", shortlist)
    monkeypatch.setattr(cli, "_report", fail_report)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 1
    assert calls == [(work_root / "shortlist.contexts.json", None)]


def test_open_shortlist_noninteractive_prints_instruction_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: 1)
    monkeypatch.setattr(
        cli,
        "_shortlist_stage",
        lambda _args: cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "open"),
    )
    monkeypatch.setattr("sys.stderr", io.StringIO())

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--yes",
        ]
    )

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out.count("Open shipped-license findings: 1") == 1
    assert "Open shipped-license findings: 1" not in captured.err


def test_run_yes_ingests_existing_shortlist_proposals_before_halt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work"
    work_root.mkdir()
    (work_root / "shortlist.proposals.json").write_text("[]\n", encoding="utf-8")
    calls: list[tuple[Path | None, Path | None]] = []
    open_counts = iter([1, 0])

    def shortlist(args):
        calls.append((args.emit_contexts, args.proposals))
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "open")

    monkeypatch.setattr(cli, "_shortlist_stage", shortlist)
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: next(open_counts))
    args = SimpleNamespace(runtime_config=object(), quiet=True, yes=True, timeout=None)

    result = cli._run_shortlist_loop(args, work_root, interactive=False)

    assert result is None
    assert calls == [
        (work_root / "shortlist.contexts.json", None),
        (None, work_root / "shortlist.proposals.json"),
    ]


def test_run_shortlist_loop_ingests_proposals_then_human_decisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = tmp_path / "work"
    work_root.mkdir()
    (work_root / "shortlist.proposals.json").write_text("[]\n", encoding="utf-8")
    calls: list[tuple[Path | None, Path | None]] = []
    open_counts = iter([1, 1, 0])

    def shortlist(args):
        calls.append((args.emit_contexts, args.proposals))
        return cli.CommandResult(cli.CommandStatus.FINDINGS_OPEN, "open")

    monkeypatch.setattr(cli, "_shortlist_stage", shortlist)
    monkeypatch.setattr(cli, "_shortlist_open_count", lambda _work_root: next(open_counts))
    monkeypatch.setattr("sys.stdin", _TtyStringIO("\n\n"))
    monkeypatch.setattr("sys.stderr", _TtyStringIO())
    args = SimpleNamespace(runtime_config=object(), quiet=True, yes=False, timeout=None)

    result = cli._run_shortlist_loop(args, work_root, interactive=True)

    assert result is None
    assert calls == [
        (work_root / "shortlist.contexts.json", None),
        (None, work_root / "shortlist.proposals.json"),
        (None, None),
    ]


def test_done_message_separates_resume_skips_failures_and_review_cues(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    main_md = reports_dir / "report.main.md"
    main_csv = reports_dir / "report.main.csv"
    appendix_md = reports_dir / "report.appendix.build-ci.md"
    appendix_csv = reports_dir / "report.appendix.build-ci.csv"
    for path in (main_md, main_csv, appendix_md, appendix_csv):
        path.write_text("x\n", encoding="utf-8")
    summary = cli.RunSummary(
        repo_refs={"sentinel-alpha"},
        report_rows=2,
        failures=[cli.RunFailure("scan", "sentinel-private", "needs auth")],
        skipped=1,
        reports_dir=reports_dir,
        report_paths=(main_md, main_csv),
        appendix_rows_by_label={"build-ci": 1},
        appendix_paths_by_label={"build-ci": (appendix_md, appendix_csv)},
        coverage_gaps_by_label={"build-ci": {"missing_spdx_id": 1, "missing_source_url": 1}},
        docx_skipped=True,
    )

    message = cli._run_done_message(summary)

    assert "skipped/failed" not in message
    assert "Resume skips: 1" in message
    assert "Failures: 1" in message
    assert "Appendix rows: build-ci=1" in message
    assert (
        "Coverage gaps to double-check: build-ci: missing_source_url=1, missing_spdx_id=1"
    ) in message
    assert "Docx skipped" in message


def test_step_ignored_when_noninteractive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)

    def fail_readline() -> str:
        raise AssertionError("--step must not read stdin in non-interactive mode")

    monkeypatch.setattr("sys.stdin.readline", fail_readline)

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
            "--step",
        ]
    )

    assert code == 0


def test_partial_scan_failure_reports_successes_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    work_root = _patch_common_success(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli,
        "_run_scan_stage",
        lambda _args: ScanReport(
            (
                RepoScanOutcome("sentinel-ok", "scanned"),
                RepoScanOutcome("sentinel-private", "failed", error="needs auth"),
            )
        ),
    )

    code = cli.main(
        [
            "run",
            "--work-root",
            str(work_root),
            "--owner",
            "sentinel-owner",
            "--out-dir",
            str(tmp_path / "reports"),
            "--yes",
        ]
    )

    assert code == 1
    assert (tmp_path / "reports" / "report.main.csv").exists()


def test_run_config_after_subcommand_is_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "repolens.local.json"
    config_path.write_text("", encoding="utf-8")
    seen: list[Path | None] = []

    monkeypatch.setattr(
        cli, "load_config", lambda _root, path, **_kwargs: seen.append(path) or object()
    )
    monkeypatch.setattr(
        cli,
        "_run_command",
        lambda _args: cli.CommandResult(cli.CommandStatus.SUCCESS, "ok"),
    )

    assert (
        cli.main(
            [
                "run",
                "--config",
                str(config_path),
                "--work-root",
                "work",
                "--owner",
                "sentinel-owner",
            ]
        )
        == 0
    )
    assert seen == [config_path]


def test_global_config_before_run_is_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "repolens.local.json"
    config_path.write_text("", encoding="utf-8")
    seen: list[Path | None] = []

    monkeypatch.setattr(
        cli, "load_config", lambda _root, path, **_kwargs: seen.append(path) or object()
    )
    monkeypatch.setattr(
        cli,
        "_run_command",
        lambda _args: cli.CommandResult(cli.CommandStatus.SUCCESS, "ok"),
    )

    assert (
        cli.main(
            [
                "--config",
                str(config_path),
                "run",
                "--work-root",
                "work",
                "--owner",
                "sentinel-owner",
            ]
        )
        == 0
    )
    assert seen == [config_path]


def test_run_help_and_stage_help_cross_reference_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    top = capsys.readouterr().out
    assert "repolens run --work-root work --owner <OWNER>" in top

    assert cli.main(["run", "--help"]) == 0
    run_help = capsys.readouterr().out
    assert "--yes never approves shortlist items" in run_help

    assert cli.main(["resolve", "--help"]) == 0
    stage_help = capsys.readouterr().out
    assert "repolens run --work-root <WORK> --owner <OWNER>" in stage_help


def _empty_sbom(repo_ref: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "repo": repo_ref,
        "generated_at": "2026-01-01T00:00:00Z",
        "tool": {"name": "syft", "version": "1.0.0"},
        "source": "https://example.invalid/sentinel-source",
        "artifacts": [],
    }
