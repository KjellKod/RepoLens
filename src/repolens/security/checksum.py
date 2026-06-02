"""Checksum helpers for downloaded tools and fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

from repolens.security.errors import ChecksumSecurityError


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> str:
    actual = compute_sha256(path)
    if actual.lower() != expected.lower():
        raise ChecksumSecurityError("SHA-256 checksum mismatch")
    return actual
