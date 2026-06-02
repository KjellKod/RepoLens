"""Supply-chain canary (milestone-gating, offline, deterministic).

rpl_security.md "Supply chain" row:
    tampered Syft binary -> checksum mismatch fails BEFORE execution.

This proves the integrity gate is strictly upstream of any write/chmod/execute.
The positive companion case ensures the canary cannot pass vacuously.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap.errors import ChecksumMismatch
from repolens.bootstrap.syft import bootstrap_syft
from repolens.bootstrap.verify import CosignVerifier

from .conftest import PLATFORM, SYFT_BINARY_BYTES


def _verifier(runner) -> CosignVerifier:
    return CosignVerifier(Path("/bin/cosign"), runner)


def test_tampered_syft_rejected_before_execution(
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

    # 1. raised ChecksumMismatch (above)
    # 2. binary never made executable
    make_exe.assert_not_called()
    # 3. binary never executed
    runner.assert_not_called()
    # 4. no file written to dest
    assert not dest.exists()


def test_canary_positive_good_binary_passes(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path
):
    """The good binary passes the checksum gate, so the canary fails for the
    right reason (tamper detected), not because nothing ever passes."""
    make_exe = MagicMock()
    dest = tmp_path / "syft"
    resolved = bootstrap_syft(
        test_pins,
        dest,
        acquire=acquire_factory(),
        verifier=_verifier(accepting_cosign_runner),
        make_executable=make_exe,
        platform_key=PLATFORM,
        workdir=tmp_path,
    )
    assert dest.exists()
    assert dest.read_bytes() == SYFT_BINARY_BYTES
    make_exe.assert_called_once_with(dest)
    assert resolved.digest == test_pins.tool("syft").artifact_for(PLATFORM).sha256
