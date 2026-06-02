"""RCE-lifecycle canary (milestone-gating, offline, deterministic).

rpl_security.md "No code execution from untrusted repositories":
    scanning a repo must never run its install/build scripts or git hooks.

The scan runner's only execution boundary is the injected Syft command over an
already-cloned local path; it never shells out to repository-supplied scripts.
This canary materializes a repo tree full of would-be-executed scripts and a
post-checkout hook, scans it, and asserts (a) no sentinel is written and (b) the
only command issued is the read-only Syft inventory invocation.

Self-contained: drives ``scan_repos`` with injected store seams so importing the
runner stays free of ``jsonschema`` under the lock-only canary gate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.scan.runner import RepoSpec, scan_repos

SOURCE = "https://example.invalid/acme-untrusted"


def _materialize_untrusted_tree(root: Path, sentinel: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = f"#!/bin/sh\nprintf fired > {sentinel}\n"
    for name in ("setup.py", "Makefile", "install.sh", "build.sh"):
        script = root / name
        script.write_text(payload, encoding="utf-8")
        script.chmod(0o755)
    hooks = root / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "post-checkout"
    hook.write_text(payload, encoding="utf-8")
    hook.chmod(0o755)


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_rce_lifecycle_no_execution(tmp_path: Path) -> None:
    sentinel = tmp_path / "acme-rce-fired"
    issued: list[list[str]] = []

    def fake_clone(options):
        destination = Path(options.destination)
        _materialize_untrusted_tree(destination, sentinel)
        return destination

    def static_syft_runner(argv, *, timeout):
        # A real RCE would require shelling out to a repo script; the runner must
        # only ever issue the read-only Syft inventory command over the path.
        issued.append(list(argv))
        return subprocess.CompletedProcess(list(argv), 0, stdout='{"artifacts": []}', stderr="")

    sboms: list[dict] = []
    statuses: list[dict] = []
    work_root = tmp_path / "work"

    report = scan_repos(
        work_root,
        [RepoSpec(repo_ref="acme-untrusted", clone_url=SOURCE)],
        syft_path=tmp_path / "tools" / "syft",
        clone=fake_clone,
        command_runner=static_syft_runner,
        clock=lambda: "2026-01-01T00:00:00Z",
        is_scanned_fn=lambda *_: False,
        repo_dir_fn=lambda root, ref: Path(root) / ref,
        write_sbom_fn=lambda root, ref, value: sboms.append(value) or Path("sbom"),
        write_status_fn=lambda path, value: statuses.append(value),
    )

    # 1. no install/build script or git hook ever executed.
    assert not sentinel.exists()
    # 2. exactly one read-only Syft inventory command was issued.
    assert len(issued) == 1
    argv = issued[0]
    assert argv[1] == "scan"
    assert argv[2].startswith("dir:")
    assert "-o" in argv and "syft-json" in argv
    # 3. no shell or repo-supplied script appears anywhere in the argv.
    flat = " ".join(argv)
    for forbidden in ("sh", "setup.py", "Makefile", "install.sh", "build.sh", "post-checkout"):
        assert f"/{forbidden}" not in flat
    assert report.scanned and not report.failed
