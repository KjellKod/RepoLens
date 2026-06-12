"""Supply-chain canary, gate-registered twin (offline, deterministic).

rpl_security.md "Supply chain":
    a tampered Syft binary fails the checksum gate BEFORE it is ever written,
    made executable, or executed.

``tests/bootstrap/test_supply_chain_canary.py`` covers the same property under the
``tests/bootstrap`` CI step; this is the copy registered in the security-canary
matrix and run under the lock-only ``security-canaries.yml`` gate. It is therefore
self-contained: it builds its pins/bytes inline and imports only
``repolens.bootstrap`` + stdlib — no ``tests/bootstrap`` conftest fixtures and no
``jsonschema``.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap import readiness
from repolens.bootstrap.errors import ChecksumMismatch
from repolens.bootstrap.pins import load_pins_data
from repolens.bootstrap.readiness import ToolPreflightOptions, ToolStatus, check_required_tools
from repolens.bootstrap.record import VERSIONS_SCHEMA
from repolens.bootstrap.scancode import (
    DEFAULT_REQUIREMENTS_PATH,
    build_pip_argv,
    build_scancode_hash_pinned_venv_wrapper,
    build_scancode_venv_wrapper,
    provision_scancode_work_root,
    requirements_sha256,
    scancode_hash_pinned_venv_source,
    scancode_venv_digest,
    scancode_venv_source,
)
from repolens.bootstrap.syft import bootstrap_syft

PLATFORM = "linux/amd64"
SYFT_ARTIFACT = "syft_1.18.1_linux_amd64.tar.gz"
GOOD_BINARY = b"ACME-SYFT-BINARY\n"


def _tar_gz_with_syft(binary: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        info = tarfile.TarInfo("syft")
        info.size = len(binary)
        info.mode = 0o755
        info.mtime = 0
        archive.addfile(info, io.BytesIO(binary))
    return out.getvalue()


def _pins_for(good_sha: str):
    data = {
        "schema": "repolens.pins/v1",
        "base_image": {"ref": "docker.io/library/python:3.13-slim@sha256:" + "0" * 63 + "1"},
        "tools": {
            "syft": {
                "version": "1.18.1",
                "source": "https://example.invalid/syft",
                "platforms": {PLATFORM: {"artifact": SYFT_ARTIFACT, "sha256": good_sha}},
                "signature": {
                    "mechanism": "cosign-keyless",
                    "checksums_file": "syft_1.18.1_checksums.txt",
                    "checksums_sig": "syft_1.18.1_checksums.txt.sig",
                    "checksums_cert": "syft_1.18.1_checksums.txt.pem",
                    "cert_identity_regex": "https://example.invalid/workflows/.*",
                    "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
                },
            },
            "cosign": {
                "version": "2.4.1",
                "platforms": {PLATFORM: {"artifact": "cosign-linux-amd64", "sha256": "c" * 64}},
            },
            "scancode": {"version": "32.3.1", "requirements": "scancode.requirements.txt"},
            "git": {
                "version": "2.47.1",
                "platforms": {PLATFORM: {"artifact": "git-2.47.1.tar.gz", "sha256": "a" * 64}},
            },
            "gh": {
                "version": "2.63.2",
                "platforms": {PLATFORM: {"artifact": "gh_2.63.2.tar.gz", "sha256": "b" * 64}},
            },
        },
    }
    return load_pins_data(data)


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_supply_chain_tamper_fails_closed(tmp_path: Path) -> None:
    good_sha = hashlib.sha256(_tar_gz_with_syft(GOOD_BINARY)).hexdigest()
    pins = _pins_for(good_sha)
    dest = tmp_path / "syft"

    make_executable = MagicMock()
    runner = MagicMock()
    verifier = MagicMock()  # never reached: GATE 1 (checksum) fires first.

    def acquire(name: str) -> bytes:
        # Tampered Syft bytes whose sha256 cannot match the pinned good digest.
        return b"TAMPERED-SYFT-PAYLOAD"

    with pytest.raises(ChecksumMismatch):
        bootstrap_syft(
            pins,
            dest,
            acquire=acquire,
            verifier=verifier,
            make_executable=make_executable,
            runner=runner,
            platform_key=PLATFORM,
            workdir=tmp_path,
        )

    # Fail-closed ordering: nothing was verified-onward, written, chmod-ed, or run.
    verifier.verify.assert_not_called()
    make_executable.assert_not_called()
    runner.assert_not_called()
    assert not dest.exists()


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scancode_auto_provision_pip_argv_is_closed_hash_pinned() -> None:
    argv = build_pip_argv(DEFAULT_REQUIREMENTS_PATH, python="/venv/bin/python")

    assert argv[:4] == ["/venv/bin/python", "-m", "pip", "install"]
    assert "--require-hashes" in argv
    assert "--no-deps" in argv
    assert "--only-binary=:all:" in argv
    assert argv[-2:] == ["--requirement", str(DEFAULT_REQUIREMENTS_PATH)]


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scancode_auto_provision_refuses_unverified_existing_binary(
    tmp_path: Path,
) -> None:
    _write_arbitrary_scancode_binary(tmp_path)

    options = ToolPreflightOptions(work_root=tmp_path, offline=True, auto_bootstrap=False)
    status = check_required_tools(("scancode",), options)[0]

    assert status.status is ToolStatus.MISSING_UNPROVISIONABLE
    assert status.path is None
    assert "tool_versions.json" in str(status.reason)


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scancode_real_provision_path_uses_closed_hash_pinned_pip_argv(
    tmp_path: Path,
) -> None:
    _write_arbitrary_scancode_binary(tmp_path)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            venv_python = Path(argv[-1]) / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    wrapper = provision_scancode_work_root(
        tmp_path,
        python="python-test",
        runner=runner,
        make_executable=lambda path: path.chmod(path.stat().st_mode | 0o755),
    )

    pip_calls = [argv for argv in calls if argv[1:4] == ["-m", "pip", "install"]]
    assert wrapper == tmp_path / "tools" / "scancode"
    assert len(pip_calls) == 1
    assert "--require-hashes" in pip_calls[0]
    assert "--no-deps" in pip_calls[0]
    assert "--only-binary=:all:" in pip_calls[0]
    assert pip_calls[0][-2:] == ["--requirement", str(DEFAULT_REQUIREMENTS_PATH)]
    assert "unverified" not in wrapper.read_text(encoding="utf-8")


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_scancode_auto_provision_uses_verified_bootstrap_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write_legacy_exact_venv_proof(tmp_path)
    calls: list[Path] = []

    def provision(work_root: Path) -> Path:
        calls.append(work_root)
        return _write_hash_pinned_venv_proof(work_root)

    monkeypatch.setattr(readiness, "provision_scancode_work_root", provision)

    paths = readiness.ensure_required_tools(
        ("scancode",),
        ToolPreflightOptions(work_root=tmp_path, offline=False, auto_bootstrap=True),
    )

    assert calls == [tmp_path]
    assert paths["scancode"] == tmp_path / "tools" / "scancode"


def _write_legacy_exact_venv_proof(root: Path) -> None:
    tools = root / "tools"
    venv_bin = tools / "scancode-venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    digest = scancode_venv_digest("32.4.1")
    wrapper = tools / "scancode"
    wrapper.write_text(build_scancode_venv_wrapper("32.4.1", digest), encoding="utf-8")
    wrapper.chmod(0o755)
    _write_scancode_record(
        root, version="32.4.1", digest=digest, source=scancode_venv_source("32.4.1")
    )


def _write_arbitrary_scancode_binary(root: Path) -> Path:
    tools = root / "tools"
    tools.mkdir(parents=True)
    wrapper = tools / "scancode"
    wrapper.write_text("#!/bin/sh\necho unverified\n", encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper


def _write_hash_pinned_venv_proof(root: Path) -> Path:
    tools = root / "tools"
    venv_bin = tools / "scancode-venv" / "bin"
    venv_bin.mkdir(parents=True, exist_ok=True)
    (venv_bin / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    digest = requirements_sha256(DEFAULT_REQUIREMENTS_PATH)
    source = scancode_hash_pinned_venv_source(DEFAULT_REQUIREMENTS_PATH)
    wrapper = tools / "scancode"
    wrapper.write_text(
        build_scancode_hash_pinned_venv_wrapper(
            "32.4.1",
            digest,
            requirements_source=source,
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    _write_scancode_record(root, version="32.4.1", digest=digest, source=source)
    return wrapper


def _write_scancode_record(root: Path, *, version: str, digest: str, source: str) -> None:
    (root / "tool_versions.json").write_text(
        json.dumps(
            {
                "schema": VERSIONS_SCHEMA,
                "generated_at": "2026-01-01T00:00:00Z",
                "base_image": "python@sha256:" + "d" * 64,
                "tools": {
                    "scancode": {
                        "version": version,
                        "digest": digest,
                        "source": source,
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
