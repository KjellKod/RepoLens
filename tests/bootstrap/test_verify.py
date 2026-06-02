"""Tests for the integrity gates (AC #2, #3, P2 items 1 & 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from repolens.bootstrap.errors import (
    ChecksumMismatch,
    ChecksumProvenanceError,
    SignatureVerificationError,
)
from repolens.bootstrap.pins import SignatureSpec
from repolens.bootstrap.verify import (
    CosignVerifier,
    assert_manifest_hash_signed,
    build_cosign_argv,
    compute_sha256,
    parse_checksums_file,
    verify_checksum,
)


def _sig() -> SignatureSpec:
    return SignatureSpec(
        mechanism="cosign-keyless",
        checksums_file="c.txt",
        checksums_sig="c.txt.sig",
        checksums_cert="c.txt.pem",
        cert_identity_regex="https://example/workflows/.*",
        cert_oidc_issuer="https://token.actions.githubusercontent.com",
    )


def test_sha256_match_ok():
    data = b"hello"
    assert verify_checksum(data, compute_sha256(data)) == compute_sha256(data)


def test_sha256_mismatch_raises():
    with pytest.raises(ChecksumMismatch):
        verify_checksum(b"tampered", "0" * 64)


def test_parse_checksums_file():
    text = f"{'a' * 64}  syft.tar.gz\n{'b' * 64} *other.bin\n# comment\n\n"
    parsed = parse_checksums_file(text)
    assert parsed == {"syft.tar.gz": "a" * 64, "other.bin": "b" * 64}


def test_manifest_hash_must_match_signed_checksums_ok():
    sha = "a" * 64
    text = f"{sha}  syft.tar.gz\n"
    assert_manifest_hash_signed(
        artifact_name="syft.tar.gz", manifest_sha256=sha, trusted_checksums_text=text
    )


def test_manifest_hash_not_in_signed_checksums_raises():
    with pytest.raises(ChecksumProvenanceError, match="not listed"):
        assert_manifest_hash_signed(
            artifact_name="missing.tar.gz",
            manifest_sha256="a" * 64,
            trusted_checksums_text=f"{'a' * 64}  other.tar.gz\n",
        )


def test_manifest_hash_drifted_from_signed_checksums_raises():
    with pytest.raises(ChecksumProvenanceError, match="drifted"):
        assert_manifest_hash_signed(
            artifact_name="syft.tar.gz",
            manifest_sha256="a" * 64,
            trusted_checksums_text=f"{'b' * 64}  syft.tar.gz\n",
        )


def test_cosign_argv_pins_identity_and_issuer():
    argv = build_cosign_argv(
        _sig(),
        checksums_path=Path("/w/c.txt"),
        signature_path=Path("/w/c.txt.sig"),
        certificate_path=Path("/w/c.txt.pem"),
        cosign_bin=Path("/bin/cosign"),
    )
    assert argv[0] == "/bin/cosign"
    assert "verify-blob" in argv
    # The identity regexp and issuer flags MUST be present and carry the pinned
    # values; without them cosign would accept an attacker-issued cert.
    i = argv.index("--certificate-identity-regexp")
    assert argv[i + 1] == "https://example/workflows/.*"
    j = argv.index("--certificate-oidc-issuer")
    assert argv[j + 1] == "https://token.actions.githubusercontent.com"
    assert argv[-1] == "/w/c.txt"


def test_signature_accept_ok():
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    verifier = CosignVerifier(Path("/bin/cosign"), runner)
    verifier.verify(
        _sig(),
        checksums_path=Path("/w/c.txt"),
        signature_path=Path("/w/c.txt.sig"),
        certificate_path=Path("/w/c.txt.pem"),
    )
    assert calls and "--certificate-identity-regexp" in calls[0]


def test_signature_reject_raises():
    def runner(argv: list[str]) -> int:
        return 1

    verifier = CosignVerifier(Path("/bin/cosign"), runner)
    with pytest.raises(SignatureVerificationError):
        verifier.verify(
            _sig(),
            checksums_path=Path("/w/c.txt"),
            signature_path=Path("/w/c.txt.sig"),
            certificate_path=Path("/w/c.txt.pem"),
        )
