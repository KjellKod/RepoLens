"""Scan-runner auth/transient matrix (offline, all boundaries injected)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repolens.exit_codes import InputError
from repolens.githost import (
    GH_NOT_AUTHENTICATED_MESSAGE,
    GH_NOT_INSTALLED_MESSAGE,
    CloneCredentialResolution,
)
from repolens.scan.runner import RepoSpec, ScanBatchError, ScanReport, scan_repos
from repolens.security.clone import CloneCredential, CloneOptions
from repolens.security.errors import (
    CloneAccessDenied,
    CloneRateLimited,
    CloneTimeout,
    CloneTransient,
)

TOKEN = "ghp_" + "A" * 36


def _syft_document() -> dict:
    return {
        "descriptor": {"name": "syft", "version": "1.18.1"},
        "artifacts": [
            {"name": "acme-lib", "version": "1.2.3", "type": "python"},
        ],
    }


def _syft_ok(argv, *, timeout):
    return subprocess.CompletedProcess(
        list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
    )


def _no_sleep(_delay: float) -> None:
    return None


def _scan(
    repos,
    *,
    tmp_path: Path,
    clone,
    command_runner=_syft_ok,
    credential_provider=None,
    **kwargs,
) -> ScanReport:
    sboms: list = []
    statuses: list = []
    write_status_fn = kwargs.pop("write_status_fn", lambda path, value: statuses.append(value))
    try:
        return scan_repos(
            tmp_path,
            repos,
            syft_path=Path("/tools/syft"),
            clone=clone,
            command_runner=command_runner,
            clock=lambda: "2026-01-01T00:00:00Z",
            credential_provider=credential_provider,
            sleep=_no_sleep,
            is_scanned_fn=lambda *_: False,
            repo_dir_fn=lambda root, ref: Path(root) / ref,
            write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
            write_status_fn=write_status_fn,
            **kwargs,
        )
    except ScanBatchError as exc:
        return exc.report


def test_private_with_credential_scans_and_injects_header(tmp_path: Path) -> None:
    seen: list[CloneOptions] = []

    def clone(options: CloneOptions) -> Path:
        seen.append(options)
        return Path(options.destination)

    report = _scan(
        [
            RepoSpec(
                "sentinel-priv", "https://github.com/acme-owner/sentinel-priv.git", private=True
            )
        ],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=lambda: CloneCredential(TOKEN),
    )

    assert [o.status for o in report.outcomes] == ["scanned"]
    # The clone seam received the credential; its injected env carries the header.
    env = seen[0].credential.extraheader_env()
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert "Authorization: Basic " in env["GIT_CONFIG_VALUE_0"]


def test_private_without_credential_fails_with_auth_message(tmp_path: Path) -> None:
    clone_calls: list = []

    def clone(options: CloneOptions) -> Path:
        clone_calls.append(options)
        return Path(options.destination)

    report = _scan(
        [
            RepoSpec(
                "sentinel-priv", "https://github.com/acme-owner/sentinel-priv.git", private=True
            )
        ],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=lambda: None,
    )

    assert clone_calls == []  # no clone attempted without a credential
    failed = report.failed
    assert len(failed) == 1
    assert failed[0].error == (
        "private repo sentinel-priv needs auth: run `gh auth login` or set GH_TOKEN."
    )


@pytest.mark.parametrize(
    "message",
    [GH_NOT_INSTALLED_MESSAGE, GH_NOT_AUTHENTICATED_MESSAGE],
)
def test_private_credential_resolution_reason_surfaces_in_scan(
    tmp_path: Path, message: str
) -> None:
    clone_calls: list = []

    def clone(options: CloneOptions) -> Path:
        clone_calls.append(options)
        return Path(options.destination)

    report = _scan(
        [
            RepoSpec(
                "sentinel-priv", "https://github.com/acme-owner/sentinel-priv.git", private=True
            )
        ],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=lambda: CloneCredentialResolution(None, message),
    )

    assert clone_calls == []
    assert report.failed[0].error == message


def test_public_repo_clones_without_credential(tmp_path: Path) -> None:
    seen: list[CloneOptions] = []
    resolved = {"n": 0}

    def clone(options: CloneOptions) -> Path:
        seen.append(options)
        return Path(options.destination)

    def provider() -> CloneCredential | None:
        resolved["n"] += 1
        return CloneCredential(TOKEN)

    report = _scan(
        [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git", private=False)],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=provider,
    )

    assert [o.status for o in report.outcomes] == ["scanned"]
    assert seen[0].credential is None
    assert resolved["n"] == 0  # public repos never trigger credential resolution


def test_transient_clone_retried_then_rate_limited_message(tmp_path: Path) -> None:
    attempts = {"n": 0}

    def clone(options: CloneOptions) -> Path:
        attempts["n"] += 1
        raise CloneRateLimited("HTTP 429")

    report = _scan(
        [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git")],
        tmp_path=tmp_path,
        clone=clone,
    )

    assert attempts["n"] == 2  # bounded clone attempt cap
    failed = report.failed
    assert len(failed) == 1
    assert failed[0].error == "rate-limited after 2 retries - try again later"


def test_clone_timeout_classified_transient_and_bounded(tmp_path: Path) -> None:
    attempts = {"n": 0}
    clock = {"t": 0.0}

    def fake_monotonic() -> float:
        return clock["t"]

    def clone(options: CloneOptions) -> Path:
        attempts["n"] += 1
        clock["t"] += options.limits.clone_timeout_seconds
        raise CloneTransient("git clone timed out")

    report = _scan(
        [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git")],
        tmp_path=tmp_path,
        clone=clone,
        monotonic=fake_monotonic,
    )

    # The hardened clone subprocess timeout bounds each attempt; the retry cap
    # therefore bounds the batch at roughly 2 * clone_timeout.
    assert attempts["n"] == 2
    assert report.failed[0].error == "rate-limited after 2 retries - try again later"


def test_clone_timeout_records_timeout_message_not_rate_limited(tmp_path: Path) -> None:
    attempts = {"n": 0}
    statuses: list[dict] = []

    def clone(options: CloneOptions) -> Path:
        attempts["n"] += 1
        raise CloneTimeout(
            configured_seconds=options.limits.clone_timeout_seconds,
            elapsed_seconds=12.25,
        )

    report = _scan(
        [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git")],
        tmp_path=tmp_path,
        clone=clone,
        clone_timeout_seconds=7.0,
        write_status_fn=lambda path, value: statuses.append(value),
    )

    assert attempts["n"] == 1
    expected = (
        "clone timed out after 7s "
        "(elapsed 12.2s; repo may be too large or network too slow; "
        "try a higher --clone-timeout)"
    )
    assert report.failed[0].error == expected
    assert statuses[0]["error"] == expected


def test_scan_repos_rejects_invalid_clone_timeout_directly(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="clone_timeout_seconds must be a positive"):
        _scan(
            [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git")],
            tmp_path=tmp_path,
            clone=lambda options: Path(options.destination),
            clone_timeout_seconds=0,
        )


def test_access_denied_not_retried_distinct_message(tmp_path: Path) -> None:
    attempts = {"n": 0}

    def clone(options: CloneOptions) -> Path:
        attempts["n"] += 1
        raise CloneAccessDenied("remote: HTTP 403 Forbidden")

    report = _scan(
        [
            RepoSpec(
                "sentinel-priv", "https://github.com/acme-owner/sentinel-priv.git", private=True
            )
        ],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=lambda: CloneCredential(TOKEN),
    )

    assert attempts["n"] == 1  # 403 is never retried
    assert report.failed[0].error == (
        "no access to sentinel-priv with the current GitHub credential."
    )


def test_mixed_run_exposes_report_on_batch_error(tmp_path: Path) -> None:
    def clone(options: CloneOptions) -> Path:
        if "sentinel-bad" in options.remote_url:
            raise CloneAccessDenied("403")
        return Path(options.destination)

    report = _scan(
        [
            RepoSpec("sentinel-ok", "https://github.com/acme-owner/sentinel-ok.git"),
            RepoSpec(
                "sentinel-bad", "https://github.com/acme-owner/sentinel-bad.git", private=True
            ),
        ],
        tmp_path=tmp_path,
        clone=clone,
        credential_provider=lambda: CloneCredential(TOKEN),
    )

    assert {o.repo_ref for o in report.scanned} == {"sentinel-ok"}
    assert {o.repo_ref for o in report.failed} == {"sentinel-bad"}


def test_unexpected_exception_propagates_as_crash(tmp_path: Path) -> None:
    def clone(options: CloneOptions) -> Path:
        raise TypeError("genuine programming bug")

    # A non-typed (programming) error is NOT swallowed into a per-repo failure:
    # it propagates so the CLI surfaces it as `Internal error` (brief §2).
    with pytest.raises(TypeError):
        _scan(
            [RepoSpec("sentinel-pub", "https://github.com/acme-owner/sentinel-pub.git")],
            tmp_path=tmp_path,
            clone=clone,
        )
