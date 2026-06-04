"""Authenticated-clone secret-handling canaries (offline, deterministic).

rpl_security.md §2 (auth model):
    A clone may carry an injected read-only credential for the FETCH only. The
    credential is present in the hook-disabled clone subprocess env, and absent
    from the Syft/tool-execution environment and from every artifact and log.

These two canaries gate that posture:

1. ``scan_auth_credential_scrubbed_after_clone`` — POSITIVE control: the env the
   clone subprocess receives DOES carry the ``Authorization: Basic …`` header
   (proving the test would catch a leak), while the Syft tool env carries neither
   the header, the raw token, nor ``GH_TOKEN``/``GITHUB_TOKEN`` (the realistic live
   leak vector). The token and its base64 header form are absent from the SBOM and
   ``scan.status.json``.
2. ``scan_auth_token_redaction`` — a token-shaped string fed through a successful
   (Syft → SBOM) and a failed credentialed (git stderr) path is absent from every
   persisted payload, and the redaction marker is present.

Self-contained: every store seam is injected, so importing the runner stays free
of ``jsonschema`` under the lock-only canary gate. The token is assembled by
concatenation so it never appears as a committed-surface token.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from repolens.scan.runner import RepoSpec, ScanBatchError, _scrubbed_tool_env, scan_repos
from repolens.security.clone import CloneCredential, CloneOptions, _scrubbed_git_env
from repolens.security.errors import CloneSecurityError
from repolens.security.redaction import REDACTION

TOKEN = "ghp_" + "Z" * 36
BASE64_HEADER = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode("ascii")


def _no_sleep(_delay: float) -> None:
    return None


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_scan_auth_credential_present_in_clone_env_absent_from_tool_env_and_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Tokens exist in the ambient environment — the Syft env must still exclude them.
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)

    clone_envs: list[dict[str, str]] = []

    def fake_clone(options: CloneOptions) -> Path:
        # The env hardened_clone WOULD pass to the child fetch process, given the
        # credential the runner injected onto CloneOptions.
        clone_envs.append(_scrubbed_git_env({"PATH": "/bin"}, credential=options.credential))
        destination = Path(options.destination)
        destination.mkdir(parents=True, exist_ok=True)
        return destination

    def fake_syft(argv, *, timeout):
        document = {
            "descriptor": {"name": "syft", "version": "1.18.1"},
            "artifacts": [{"name": "acme-lib", "version": "1.2.3", "type": "python"}],
        }
        return _completed(json.dumps(document))

    sboms: list[dict] = []
    statuses: list[dict] = []

    scan_repos(
        tmp_path / "work",
        [RepoSpec("acme-priv", "https://github.com/acme-owner/acme-priv.git", private=True)],
        syft_path=tmp_path / "tools" / "syft",
        clone=fake_clone,
        command_runner=fake_syft,
        clock=lambda: "2026-01-01T00:00:00Z",
        credential_provider=lambda: CloneCredential(TOKEN),
        sleep=_no_sleep,
        is_scanned_fn=lambda *_: False,
        repo_dir_fn=lambda root, ref: Path(root) / ref,
        write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
        write_status_fn=lambda path, value: statuses.append(value),
        write_first_party_fn=lambda *_: Path("first_party"),
    )

    # POSITIVE control: the credential genuinely reaches the clone subprocess env.
    assert clone_envs and clone_envs[0]["GIT_CONFIG_COUNT"] == "1"
    assert clone_envs[0]["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {BASE64_HEADER}"

    # The Syft tool env carries no header, no raw token, and not the GH_TOKEN/
    # GITHUB_TOKEN keys (the realistic live leak vector).
    tool_env = _scrubbed_tool_env()
    assert "GH_TOKEN" not in tool_env
    assert "GITHUB_TOKEN" not in tool_env
    tool_env_text = json.dumps(tool_env)
    assert TOKEN not in tool_env_text
    assert BASE64_HEADER not in tool_env_text

    # Neither the raw token nor the base64 header reaches any persisted artifact.
    payloads = json.dumps(sboms) + json.dumps(statuses)
    assert TOKEN not in payloads
    assert BASE64_HEADER not in payloads
    assert [s["status"] for s in statuses] == ["scanned"]


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_scan_auth_token_never_in_status_sbom_or_stderr(tmp_path: Path) -> None:
    syft_json = json.dumps(
        {
            "descriptor": {"name": "syft", "version": "1.18.1"},
            "artifacts": [
                {
                    "name": "acme-lib",
                    "version": "1.2.3",
                    "type": "python",
                    "purl": f"pkg:pypi/acme-lib@1.2.3?token={TOKEN}",
                }
            ],
        }
    )

    def fake_clone(options: CloneOptions) -> Path:
        # The failed credentialed repo's git stderr carries a token-shaped string;
        # _safe_git_error redacts it, but here we prove the runner redacts the
        # surfaced message even for a generic clone failure on the credential path.
        if "acme-bad" in options.remote_url:
            raise CloneSecurityError(f"fatal: unable to access using {TOKEN}")
        destination = Path(options.destination)
        destination.mkdir(parents=True, exist_ok=True)
        return destination

    def fake_syft(argv, *, timeout):
        return _completed(syft_json)

    sboms: list[dict] = []
    statuses: list[dict] = []

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            tmp_path / "work",
            [
                RepoSpec("acme-ok", "https://github.com/acme-owner/acme-ok.git", private=True),
                RepoSpec("acme-bad", "https://github.com/acme-owner/acme-bad.git", private=True),
            ],
            syft_path=tmp_path / "tools" / "syft",
            clone=fake_clone,
            command_runner=fake_syft,
            clock=lambda: "2026-01-01T00:00:00Z",
            credential_provider=lambda: CloneCredential(TOKEN),
            sleep=_no_sleep,
            is_scanned_fn=lambda *_: False,
            repo_dir_fn=lambda root, ref: Path(root) / ref,
            write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
            write_status_fn=lambda path, value: statuses.append(value),
            write_first_party_fn=lambda *_: Path("first_party"),
        )

    report = exc_info.value.report
    assert {o.repo_ref for o in report.failed} == {"acme-bad"}
    payloads = json.dumps(sboms) + json.dumps(statuses)
    assert TOKEN not in payloads
    assert BASE64_HEADER not in payloads
    assert REDACTION in payloads
    failed = [s for s in statuses if s.get("status") == "failed"]
    assert failed and REDACTION in failed[0]["error"]


def _completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")
