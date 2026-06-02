"""Integrity gates: checksum, cosign signature, and provenance cross-check.

Design for offline determinism:

* :func:`compute_sha256` / :func:`verify_checksum` are pure (GATE 1, the canary's
  primary anchor).
* The signature gate is split, mirroring the ScanCode approach, into a pure argv
  *builder* (:func:`build_cosign_argv`, unit-tested for the
  ``--certificate-identity-regexp`` / ``--certificate-oidc-issuer`` flags) and a
  thin injected *runner*. Tests never run real cosign or touch the network.
* :func:`assert_manifest_hash_signed` ties the manifest-pinned sha256 to the
  cosign-verified checksums file so a maintainer cannot edit the pin to a value
  the signature does not vouch for (P2 provenance fix).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Protocol

from .errors import (
    ChecksumMismatch,
    ChecksumProvenanceError,
    SignatureVerificationError,
)
from .pins import SignatureSpec

_CHUNK = 1 << 20


def compute_sha256(data: bytes) -> str:
    """Return the lowercase hex sha256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    """Return the lowercase hex sha256 of the file at ``path`` (streamed)."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_checksum(data: bytes, expected: str) -> str:
    """GATE 1 — raise :class:`ChecksumMismatch` unless ``data`` hashes to ``expected``.

    Returns the computed digest on success so callers can record it.
    """
    actual = compute_sha256(data)
    if actual != expected:
        raise ChecksumMismatch(f"checksum mismatch: expected {expected}, got {actual}")
    return actual


def parse_checksums_file(text: str) -> dict[str, str]:
    """Parse a ``sha256  filename`` checksums file into ``{filename: sha256}``.

    Accepts the GNU coreutils format produced by goreleaser/Syft: one entry per
    line, ``<64-hex><whitespace><filename>``. A leading ``*`` (binary marker) on
    the filename is stripped.
    """
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, name = parts
        digest = digest.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        out[name.lstrip("*").strip()] = digest
    return out


def assert_manifest_hash_signed(
    *,
    artifact_name: str,
    manifest_sha256: str,
    trusted_checksums_text: str,
) -> None:
    """Cross-check the manifest-pinned hash against the signed checksums file.

    Call this AFTER cosign has verified the checksums file's signature/cert, so
    ``trusted_checksums_text`` is trusted. Raises
    :class:`ChecksumProvenanceError` if the manifest's pinned sha256 for
    ``artifact_name`` is absent from, or disagrees with, the signed file.
    """
    entries = parse_checksums_file(trusted_checksums_text)
    signed = entries.get(artifact_name)
    if signed is None:
        raise ChecksumProvenanceError(
            f"artifact {artifact_name!r} is not listed in the signed checksums file"
        )
    if signed != manifest_sha256:
        raise ChecksumProvenanceError(
            f"manifest-pinned sha256 for {artifact_name!r} ({manifest_sha256}) does not "
            f"match the signed checksums entry ({signed}); the pin has drifted from the "
            f"signature"
        )


def build_cosign_argv(
    sig: SignatureSpec,
    *,
    checksums_path: Path,
    signature_path: Path,
    certificate_path: Path,
    cosign_bin: Path,
) -> list[str]:
    """Construct the exact ``cosign verify-blob`` argv (pure, unit-tested).

    The certificate-identity regexp and OIDC issuer are mandatory: without them
    cosign would accept any validly-signed blob, including one signed by an
    attacker-issued certificate. Keeping this pure lets a test assert the flags
    are present without invoking cosign.
    """
    return [
        str(cosign_bin),
        "verify-blob",
        "--certificate-identity-regexp",
        sig.cert_identity_regex,
        "--certificate-oidc-issuer",
        sig.cert_oidc_issuer,
        "--certificate",
        str(certificate_path),
        "--signature",
        str(signature_path),
        str(checksums_path),
    ]


class CommandRunner(Protocol):
    """Runs a command, returning its exit code. Injected so tests stay offline."""

    def __call__(self, argv: list[str]) -> int: ...


class SignatureVerifier(Protocol):
    """Verifies the checksums file's signature; raises on failure."""

    def verify(
        self,
        sig: SignatureSpec,
        *,
        checksums_path: Path,
        signature_path: Path,
        certificate_path: Path,
    ) -> None: ...


class CosignVerifier:
    """Real :class:`SignatureVerifier` that shells out to a verified cosign.

    ``cosign_bin`` MUST already be checksum-verified by the caller (see
    :func:`repolens.bootstrap.syft.bootstrap_cosign`) before being passed here —
    cosign is in the trusted computing base, so running an unverified cosign
    would move the supply-chain hole one tool upstream. The actual process
    execution is delegated to an injected ``runner`` so this class is testable
    offline.
    """

    def __init__(self, cosign_bin: Path, runner: CommandRunner) -> None:
        self.cosign_bin = Path(cosign_bin)
        self._runner = runner

    def verify(
        self,
        sig: SignatureSpec,
        *,
        checksums_path: Path,
        signature_path: Path,
        certificate_path: Path,
    ) -> None:
        argv = build_cosign_argv(
            sig,
            checksums_path=checksums_path,
            signature_path=signature_path,
            certificate_path=certificate_path,
            cosign_bin=self.cosign_bin,
        )
        code = self._runner(argv)
        if code != 0:
            raise SignatureVerificationError(
                f"cosign verify-blob failed (exit {code}) for {checksums_path.name}"
            )
