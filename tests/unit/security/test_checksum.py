from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from repolens.security.checksum import compute_sha256, verify_sha256
from repolens.security.errors import ChecksumSecurityError


def test_checksum_match_and_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "acme.bin"
    target.write_bytes(b"acme")
    expected = hashlib.sha256(b"acme").hexdigest()
    assert compute_sha256(target) == expected
    assert verify_sha256(target, expected) == expected
    with pytest.raises(ChecksumSecurityError):
        verify_sha256(target, "0" * 64)
