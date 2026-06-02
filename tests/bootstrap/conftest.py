"""Shared offline fixtures for the bootstrap tests.

Everything here is deterministic and network-free. The test pins manifest is
built in-memory from the real sha256 of the fixture binaries so the checksum gate
and the signed-checksums provenance cross-check are consistent by construction.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from repolens.bootstrap.pins import Pins, load_pins_data
from repolens.bootstrap.verify import CommandRunner

FIXTURES = Path(__file__).parent / "fixtures"
PLATFORM = "linux/amd64"

SYFT_ARTIFACT = "syft_1.18.1_linux_amd64.tar.gz"
COSIGN_ARTIFACT = "cosign-linux-amd64"
CHECKSUMS_FILE = "syft_1.18.1_checksums.txt"
CHECKSUMS_SIG = "syft_1.18.1_checksums.txt.sig"
CHECKSUMS_CERT = "syft_1.18.1_checksums.txt.pem"
SYFT_BINARY_BYTES = b"ACME-SYFT-BINARY\n"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_gz_with_syft(binary: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        info = tarfile.TarInfo("syft")
        info.size = len(binary)
        info.mode = 0o755
        info.mtime = 0
        archive.addfile(info, io.BytesIO(binary))
    return out.getvalue()


@pytest.fixture
def syft_good_bytes() -> bytes:
    return _tar_gz_with_syft(SYFT_BINARY_BYTES)


@pytest.fixture
def syft_tampered_bytes() -> bytes:
    return (FIXTURES / "syft_tampered.txt").read_bytes()


@pytest.fixture
def cosign_good_bytes() -> bytes:
    return (FIXTURES / "cosign_good.txt").read_bytes()


@pytest.fixture
def test_pins(syft_good_bytes: bytes, cosign_good_bytes: bytes) -> Pins:
    """A valid Pins whose Syft/cosign digests match the good fixture bytes."""
    syft_sha = _sha256(syft_good_bytes)
    cosign_sha = _sha256(cosign_good_bytes)
    data = {
        "schema": "repolens.pins/v1",
        "base_image": {
            "ref": "docker.io/library/python:3.13-slim@sha256:" + "0" * 63 + "1",
        },
        "tools": {
            "syft": {
                "version": "1.18.1",
                "source": "https://example/syft/v1.18.1",
                "platforms": {
                    PLATFORM: {"artifact": SYFT_ARTIFACT, "sha256": syft_sha},
                },
                "signature": {
                    "mechanism": "cosign-keyless",
                    "checksums_file": CHECKSUMS_FILE,
                    "checksums_sig": CHECKSUMS_SIG,
                    "checksums_cert": CHECKSUMS_CERT,
                    "cert_identity_regex": "https://example/workflows/.*",
                    "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
                },
            },
            "cosign": {
                "version": "2.4.1",
                "platforms": {
                    PLATFORM: {"artifact": COSIGN_ARTIFACT, "sha256": cosign_sha},
                },
            },
            "scancode": {"version": "32.3.1", "requirements": "scancode.requirements.txt"},
            "git": {
                "version": "2.47.1",
                "platforms": {
                    PLATFORM: {"artifact": "git-2.47.1.tar.gz", "sha256": "a" * 64},
                },
            },
            "gh": {
                "version": "2.63.2",
                "platforms": {
                    PLATFORM: {"artifact": "gh_2.63.2.tar.gz", "sha256": "b" * 64},
                },
            },
        },
    }
    return load_pins_data(data)


@pytest.fixture
def signed_checksums_text(test_pins: Pins) -> str:
    """A checksums file whose Syft entry matches the manifest-pinned digest."""
    syft_sha = test_pins.tool("syft").artifact_for(PLATFORM).sha256
    return f"{syft_sha}  {SYFT_ARTIFACT}\ndeadbeef" * 8 + "  some_other_artifact\n"


@pytest.fixture
def acquire_factory(
    syft_good_bytes: bytes,
    cosign_good_bytes: bytes,
    signed_checksums_text: str,
):
    """Build an offline `acquire(name) -> bytes` over a name->bytes map.

    ``syft_override`` lets a test swap in tampered Syft bytes while keeping every
    other artifact valid.
    """

    def make(*, syft_override: bytes | None = None):
        table = {
            SYFT_ARTIFACT: syft_override if syft_override is not None else syft_good_bytes,
            COSIGN_ARTIFACT: cosign_good_bytes,
            CHECKSUMS_FILE: signed_checksums_text.encode("utf-8"),
            CHECKSUMS_SIG: b"FAKE-SIGNATURE-BYTES",
            CHECKSUMS_CERT: b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        }

        def acquire(name: str) -> bytes:
            try:
                return table[name]
            except KeyError as exc:  # pragma: no cover - guards test typos
                raise AssertionError(f"unexpected acquire({name!r})") from exc

        return acquire

    return make


@pytest.fixture
def accepting_cosign_runner() -> CommandRunner:
    """A cosign runner that always succeeds (exit 0). Does not run cosign."""

    def runner(argv: list[str]) -> int:
        return 0

    return runner


@pytest.fixture
def rejecting_cosign_runner() -> CommandRunner:
    """A cosign runner that always fails (exit 1). Does not run cosign."""

    def runner(argv: list[str]) -> int:
        return 1

    return runner
