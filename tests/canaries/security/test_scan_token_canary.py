"""Scan output-token canary (milestone-gating, offline, deterministic).

rpl_security.md "Output/token handling":
    a GitHub token must be absent from every scan artifact AND from the per-repo
    ``scan.status.json`` (the latter is written via ``atomic_write_json``, which
    does NOT redact — so the runner must redact the status before the write).

This canary feeds a token-shaped string through both a successful scan (token in
Syft output -> SBOM) and a failed scan (token in Syft stderr -> status error) and
asserts neither persisted payload contains the raw token.

Self-contained: every store seam is injected, so importing the runner stays free
of ``jsonschema`` under the lock-only canary gate. The token literal is assembled
by concatenation so it never appears as a committed-surface token.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repolens.exit_codes import InternalError
from repolens.scan.runner import RepoSpec, scan_repos
from repolens.security.redaction import REDACTION

TOKEN = "ghp_" + "A" * 36


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scan_token_absent_from_artifacts(tmp_path: Path) -> None:
    syft_json = json.dumps(
        {
            "descriptor": {"name": "syft", "version": "1.18.1"},
            "artifacts": [
                {
                    "name": "acme-lib",
                    "version": "1.2.3",
                    "type": "python",
                    "purl": f"pkg:pypi/acme-lib@1.2.3?token={TOKEN}",
                    "locations": [{"path": f"creds/{TOKEN}.txt"}],
                }
            ],
        }
    )
    responses = [
        subprocess.CompletedProcess([], 0, stdout=syft_json, stderr=""),
        subprocess.CompletedProcess([], 1, stdout="", stderr=f"fatal: auth failed using {TOKEN}"),
    ]

    def fake_clone(options):
        destination = Path(options.destination)
        destination.mkdir(parents=True, exist_ok=True)
        return destination

    def fake_syft(argv, *, timeout):
        return responses.pop(0)

    sboms: list[dict] = []
    statuses: list[dict] = []

    with pytest.raises(InternalError):
        scan_repos(
            tmp_path / "work",
            [
                RepoSpec(repo_ref="acme-ok", clone_url="https://example.invalid/acme-ok"),
                RepoSpec(repo_ref="acme-bad", clone_url="https://example.invalid/acme-bad"),
            ],
            syft_path=tmp_path / "tools" / "syft",
            clone=fake_clone,
            command_runner=fake_syft,
            clock=lambda: "2026-01-01T00:00:00Z",
            is_scanned_fn=lambda *_: False,
            repo_dir_fn=lambda root, ref: Path(root) / ref,
            write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
            write_status_fn=lambda path, value: statuses.append(value),
        )

    # The successful repo produced an SBOM; the failed repo produced a status error.
    assert sboms and statuses
    payloads = json.dumps(sboms) + json.dumps(statuses)
    assert TOKEN not in payloads
    assert REDACTION in payloads
    # Specifically prove the failed-repo status error was redacted (finding #2).
    failed = [s for s in statuses if s.get("status") == "failed"]
    assert failed and TOKEN not in json.dumps(failed)
    assert REDACTION in failed[0]["error"]
