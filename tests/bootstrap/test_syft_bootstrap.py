"""Tests for fail-closed Syft/cosign bootstrap ordering (AC #2, #3, P2 item 2)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap.errors import (
    ChecksumMismatch,
    ChecksumProvenanceError,
    SignatureVerificationError,
)
from repolens.bootstrap.syft import bootstrap_cosign, bootstrap_syft
from repolens.bootstrap.verify import CosignVerifier

from .conftest import PLATFORM, SYFT_ARTIFACT, SYFT_BINARY_BYTES


def _verifier(runner) -> CosignVerifier:
    return CosignVerifier(Path("/bin/cosign"), runner)


def test_cosign_checksum_gate_then_executable(test_pins, acquire_factory, tmp_path):
    make_exe = MagicMock()
    dest = tmp_path / "cosign"
    resolved = bootstrap_cosign(
        test_pins,
        dest,
        acquire=acquire_factory(),
        make_executable=make_exe,
        platform_key=PLATFORM,
    )
    assert dest.exists()
    make_exe.assert_called_once_with(dest)
    assert resolved.version == "2.4.1"


def test_cosign_tampered_fails_before_executable(test_pins, acquire_factory, tmp_path):
    make_exe = MagicMock()
    dest = tmp_path / "cosign"
    # Acquire returns wrong cosign bytes (use syft good bytes which differ).
    bad_acquire = lambda name: b"WRONG-COSIGN-BYTES"  # noqa: E731
    with pytest.raises(ChecksumMismatch):
        bootstrap_cosign(
            test_pins,
            dest,
            acquire=bad_acquire,
            make_executable=make_exe,
            platform_key=PLATFORM,
        )
    make_exe.assert_not_called()
    assert not dest.exists()


def test_happy_path_records_and_makes_executable(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path
):
    make_exe = MagicMock()
    runner = MagicMock()  # syft runner — must never be called by bootstrap
    dest = tmp_path / "syft"
    resolved = bootstrap_syft(
        test_pins,
        dest,
        acquire=acquire_factory(),
        verifier=_verifier(accepting_cosign_runner),
        make_executable=make_exe,
        runner=runner,
        platform_key=PLATFORM,
        workdir=tmp_path,
    )
    assert dest.exists()
    assert dest.read_bytes() == SYFT_BINARY_BYTES
    make_exe.assert_called_once_with(dest)
    runner.assert_not_called()  # bootstrap never executes syft
    assert resolved.name == "syft"
    assert resolved.version == "1.18.1"
    assert resolved.digest == test_pins.tool("syft").artifact_for(PLATFORM).sha256


def test_checksum_failure_skips_executable_and_runner(
    test_pins, acquire_factory, syft_tampered_bytes, accepting_cosign_runner, tmp_path
):
    make_exe = MagicMock()
    runner = MagicMock()
    dest = tmp_path / "syft"
    with pytest.raises(ChecksumMismatch):
        bootstrap_syft(
            test_pins,
            dest,
            acquire=acquire_factory(syft_override=syft_tampered_bytes),
            verifier=_verifier(accepting_cosign_runner),
            make_executable=make_exe,
            runner=runner,
            platform_key=PLATFORM,
            workdir=tmp_path,
        )
    make_exe.assert_not_called()
    runner.assert_not_called()
    assert not dest.exists()


def test_signature_failure_skips_executable(
    test_pins, acquire_factory, rejecting_cosign_runner, tmp_path
):
    make_exe = MagicMock()
    runner = MagicMock()
    dest = tmp_path / "syft"
    with pytest.raises(SignatureVerificationError):
        bootstrap_syft(
            test_pins,
            dest,
            acquire=acquire_factory(),
            verifier=_verifier(rejecting_cosign_runner),
            make_executable=make_exe,
            runner=runner,
            platform_key=PLATFORM,
            workdir=tmp_path,
        )
    make_exe.assert_not_called()
    runner.assert_not_called()
    assert not dest.exists()


def test_provenance_drift_skips_executable(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path, monkeypatch
):
    """If the cosign-verified checksums file disagrees with the manifest, fail closed."""
    make_exe = MagicMock()
    runner = MagicMock()
    dest = tmp_path / "syft"

    # Acquire a checksums file whose Syft entry does NOT match the manifest pin.
    from . import conftest

    def drifted_acquire(name: str) -> bytes:
        if name == conftest.CHECKSUMS_FILE:
            return f"{'9' * 64}  {SYFT_ARTIFACT}\n".encode()
        return acquire_factory()(name)

    with pytest.raises(ChecksumProvenanceError):
        bootstrap_syft(
            test_pins,
            dest,
            acquire=drifted_acquire,
            verifier=_verifier(accepting_cosign_runner),
            make_executable=make_exe,
            runner=runner,
            platform_key=PLATFORM,
            workdir=tmp_path,
        )
    make_exe.assert_not_called()
    runner.assert_not_called()
    assert not dest.exists()
