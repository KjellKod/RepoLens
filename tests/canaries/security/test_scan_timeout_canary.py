"""Slow-scan timeout canary (milestone-gating, offline, deterministic).

rpl_security.md "DoS limits":
    each per-repo scan has a wall-clock budget and is aborted (with guaranteed
    cleanup) when it exceeds it.

This canary makes the injected Syft boundary raise ``TimeoutExpired`` immediately
(no real sleep) and asserts the runner aborts that repo — recording a failure,
persisting no SBOM, removing the ephemeral workdir — rather than hanging.

Self-contained: every store seam is injected, so importing the runner stays free
of ``jsonschema`` under the lock-only canary gate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.scan.runner import RepoSpec, ScanBatchError, scan_repos


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scan_timeout_aborts(tmp_path: Path) -> None:
    work_root = tmp_path / "work"
    cloned: list[Path] = []

    def fake_clone(options):
        destination = Path(options.destination)
        destination.mkdir(parents=True, exist_ok=True)
        cloned.append(destination)
        return destination

    def slow_syft(argv, *, timeout):
        # Deterministic: the boundary reports the budget was exceeded without any
        # real wall-clock sleep.
        raise subprocess.TimeoutExpired(list(argv), timeout)

    sboms: list[dict] = []
    statuses: list[dict] = []

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec(repo_ref="acme-slow", clone_url="https://example.invalid/acme-slow")],
            syft_path=tmp_path / "tools" / "syft",
            timeout_seconds=0.01,
            clone=fake_clone,
            command_runner=slow_syft,
            clock=lambda: "2026-01-01T00:00:00Z",
            is_scanned_fn=lambda *_: False,
            repo_dir_fn=lambda root, ref: Path(root) / ref,
            write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
            write_status_fn=lambda path, value: statuses.append(value),
            write_first_party_fn=lambda *_: Path("first_party"),
        )

    report = exc_info.value.report
    # The timed-out repo is recorded as a failed outcome on the batch error.
    assert [o.status for o in report.outcomes] == ["failed"]
    # 1. no SBOM persisted for the timed-out repo.
    assert not sboms
    # 2. a redacted failure status was recorded.
    assert len(statuses) == 1
    assert statuses[0]["status"] == "failed"
    assert statuses[0]["error"]
    # 3. the scan-owned ephemeral workdir was cleaned up (rpl_security §7).
    assert cloned and not cloned[0].exists()
