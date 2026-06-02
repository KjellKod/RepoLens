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
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap.errors import ChecksumMismatch
from repolens.bootstrap.pins import load_pins_data
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
