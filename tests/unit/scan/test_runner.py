"""Unit tests for the P2 scan runner.

These exercise the runner against the *real* on-disk store (jsonschema is present
in the unit env), so the Syft->SBOM mapping is proven to validate against the
frozen ``sbom.schema.json``. The clone and Syft boundaries are injected.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repolens.data import store
from repolens.scan.runner import RepoSpec, ScanBatchError, scan_repos

CLONE_URL = "https://example.invalid/acme-alpha"


def _syft_document() -> dict:
    return {
        "descriptor": {"name": "syft", "version": "1.18.1"},
        "source": {"type": "directory", "target": "/scan/repo"},
        "artifacts": [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [{"value": "MIT", "spdxExpression": "MIT"}],
                "locations": [{"path": "requirements.txt"}],
            },
            {
                # Malformed entry (no type) must be dropped, not crash the mapping.
                "name": "acme-orphan",
            },
        ],
    }


def _clone_into(options):
    destination = Path(options.destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "README.md").write_text("acme\n", encoding="utf-8")
    return destination


def _syft_ok(document: dict):
    def runner(argv, *, timeout):
        return subprocess.CompletedProcess(list(argv), 0, stdout=json.dumps(document), stderr="")

    return runner


def test_maps_syft_output_to_valid_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    report = scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    assert [o.status for o in report.outcomes] == ["scanned"]
    # Persisted + schema-validated by the real store; read it back.
    sbom = store.read_sbom(work_root, "acme-alpha")
    assert sbom["schema_version"] == "1.0"
    assert sbom["repo"] == "acme-alpha"
    assert sbom["source"] == CLONE_URL
    assert sbom["tool"] == {"name": "syft", "version": "1.18.1"}
    assert len(sbom["artifacts"]) == 1  # malformed entry dropped
    artifact = sbom["artifacts"][0]
    assert artifact["name"] == "acme-lib"
    assert artifact["type"] == "python"
    assert artifact["licenses"] == ["MIT"]
    assert artifact["locations"] == ["requirements.txt"]


def test_resume_skips_already_scanned_repo(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    store.write_sbom(
        work_root,
        "acme-alpha",
        {
            "schema_version": "1.0",
            "repo": "acme-alpha",
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.18.1"},
            "source": CLONE_URL,
            "artifacts": [],
        },
    )
    clone_calls: list = []

    def clone_spy(options):
        clone_calls.append(options)
        return _clone_into(options)

    report = scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=clone_spy,
        command_runner=_syft_ok(_syft_document()),
    )

    assert [o.status for o in report.outcomes] == ["skipped"]
    assert report.outcomes[0].skipped_reason == "cached"
    assert clone_calls == []  # resume guard prevented re-clone


def test_mixed_run_returns_failure_report_and_persists_successes(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = _syft_document()

    def runner(argv, *, timeout):
        if "acme-bad" in argv[2]:
            return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="syft boom")
        return subprocess.CompletedProcess(list(argv), 0, stdout=json.dumps(document), stderr="")

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [
                RepoSpec("acme-ok", CLONE_URL),
                RepoSpec("acme-bad", "https://example.invalid/acme-bad"),
            ],
            syft_path=tmp_path / "tools" / "syft",
            clone=_clone_into,
            command_runner=runner,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["scanned", "failed"]
    assert {o.repo_ref for o in report.scanned} == {"acme-ok"}
    assert {o.repo_ref for o in report.failed} == {"acme-bad"}
    # The good repo's SBOM is persisted despite the sibling failure.
    assert store.is_repo_scanned(work_root, "acme-ok")
    assert not store.is_repo_scanned(work_root, "acme-bad")
    # The failed repo carries a status artifact.
    status = json.loads(
        (store.repo_dir(work_root, "acme-bad") / "scan.status.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "failed"


def test_progress_events_include_start_outcomes_and_dependency_counts(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    events = []

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
        progress=events.append,
    )

    assert [(event.kind, event.index, event.total, event.repo_ref) for event in events] == [
        ("start", 1, 1, "acme-alpha"),
        ("outcome", 1, 1, "acme-alpha"),
    ]
    assert events[1].status == "scanned"
    assert events[1].deps_count == 1
    assert events[1].elapsed_seconds is not None


def test_private_repo_fails_without_clone_when_auth_missing(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    clone_calls: list = []
    events = []

    def clone_spy(options):
        clone_calls.append(options)
        return _clone_into(options)

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-private", CLONE_URL, private=True)],
            syft_path=tmp_path / "tools" / "syft",
            clone=clone_spy,
            command_runner=_syft_ok(_syft_document()),
            progress=events.append,
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert "needs auth" in str(report.outcomes[0].error)
    assert clone_calls == []
    assert events[-1].status == "failed"
    assert "needs auth" in str(events[-1].error)


def test_ephemeral_workdir_cleaned_up(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )
    leftovers = list(store.repo_dir(work_root, "acme-alpha").glob(".scan-*"))
    assert leftovers == []


def test_status_file_redacts_token_in_error(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    token = "ghp_" + "Z" * 36

    def runner(argv, *, timeout):
        return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr=f"denied {token}")

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-alpha", CLONE_URL)],
            syft_path=tmp_path / "tools" / "syft",
            clone=_clone_into,
            command_runner=runner,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert {o.repo_ref for o in report.failed} == {"acme-alpha"}
    status_text = (store.repo_dir(work_root, "acme-alpha") / "scan.status.json").read_text(
        encoding="utf-8"
    )
    assert token not in status_text
    assert "[REDACTED_TOKEN]" in status_text


def test_timeout_records_failure_without_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    def slow(argv, *, timeout):
        raise subprocess.TimeoutExpired(list(argv), timeout)

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-alpha", CLONE_URL)],
            syft_path=tmp_path / "tools" / "syft",
            timeout_seconds=0.01,
            clone=_clone_into,
            command_runner=slow,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert {o.repo_ref for o in report.failed} == {"acme-alpha"}
    assert not store.is_repo_scanned(work_root, "acme-alpha")
