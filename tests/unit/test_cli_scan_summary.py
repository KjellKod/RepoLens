"""CLI scan summary + exit-code mapping (offline; scan_repos is stubbed)."""

from __future__ import annotations

from repolens.cli import CommandStatus, _scan_command_result
from repolens.githost import GH_NOT_INSTALLED_MESSAGE
from repolens.scan.runner import RepoScanOutcome, ScanReport


def _report(*outcomes: RepoScanOutcome) -> ScanReport:
    return ScanReport(tuple(outcomes))


def test_clean_run_exits_success_without_extra_summary(capsys) -> None:
    report = _report(
        RepoScanOutcome("sentinel-a", "scanned", tool_version="1.0"),
        RepoScanOutcome("sentinel-b", "skipped"),
    )

    result = _scan_command_result(report)

    assert result.status is CommandStatus.SUCCESS
    assert result.message == ""
    assert capsys.readouterr().err == ""


def test_mixed_run_prints_summary_and_failures_to_stderr_exit_one(capsys) -> None:
    report = _report(
        RepoScanOutcome("sentinel-ok", "scanned", tool_version="1.0"),
        RepoScanOutcome("sentinel-skip", "skipped"),
        RepoScanOutcome(
            "sentinel-priv",
            "failed",
            error="private repo sentinel-priv needs auth: run `gh auth login` or set GH_TOKEN.",
        ),
    )

    result = _scan_command_result(report)
    err = capsys.readouterr().err

    assert result.status is CommandStatus.FINDINGS_OPEN
    assert "3 repos - 1 scanned, 1 skipped, 1 failed" in err
    assert "  - sentinel-priv: private repo sentinel-priv needs auth" in err
    assert "Internal error" not in err


def test_failure_reasons_are_path_sanitized(capsys) -> None:
    report = _report(RepoScanOutcome("sentinel-path", "failed", error="boom at /tmp/acme/private"))

    result = _scan_command_result(report)
    err = capsys.readouterr().err

    assert result.status is CommandStatus.FINDINGS_OPEN
    assert "/tmp/acme/private" not in err
    assert "[REDACTED_PATH]" in err


def test_gh_not_installed_message_keeps_install_url(capsys) -> None:
    report = _report(RepoScanOutcome("sentinel-priv", "failed", error=GH_NOT_INSTALLED_MESSAGE))

    result = _scan_command_result(report)
    err = capsys.readouterr().err

    assert result.status is CommandStatus.FINDINGS_OPEN
    assert "https://cli.github.com" in err
    assert "https:[REDACTED_PATH]" not in err


def test_access_denied_and_no_auth_messages_surface_verbatim(capsys) -> None:
    report = _report(
        RepoScanOutcome(
            "sentinel-403",
            "failed",
            error="no access to sentinel-403 with the current GitHub credential.",
        ),
        RepoScanOutcome(
            "sentinel-noauth",
            "failed",
            error="private repo sentinel-noauth needs auth: run `gh auth login` or set GH_TOKEN.",
        ),
    )

    result = _scan_command_result(report)
    err = capsys.readouterr().err

    assert result.status is CommandStatus.FINDINGS_OPEN
    assert "no access to sentinel-403 with the current GitHub credential." in err
    assert "private repo sentinel-noauth needs auth" in err
    assert "Internal error" not in err
