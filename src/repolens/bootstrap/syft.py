"""Fail-closed bootstrap of cosign and Syft.

Ordering invariant (the supply-chain canary asserts it):

    acquire -> checksum (GATE 1) -> signature (GATE 2) -> provenance cross-check
    -> write to dest + chmod +x -> record version -> expose path

A checksum/signature/provenance failure raises BEFORE the binary is ever written
to ``dest``, made executable, or invoked. ``make_executable`` and ``runner`` are
injected callables; on any integrity failure neither is called and no file lands
at ``dest``.
"""

from __future__ import annotations

import io
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import InvalidPin
from .pins import Pins, PlatformArtifact, current_platform
from .verify import (
    CommandRunner,
    SignatureVerifier,
    assert_manifest_hash_signed,
    verify_checksum,
)

#: Fetches the bytes of a named artifact. Real impl reads a download/cache dir;
#: tests pass a lambda returning fixture bytes. No network lives in this module.
Acquire = Callable[[str], bytes]
#: Marks a written file executable (chmod +x). Injected so tests can spy on it.
MakeExecutable = Callable[[Path], None]


@dataclass(frozen=True)
class ResolvedTool:
    """A tool that passed every gate and was written to disk."""

    name: str
    version: str
    digest: str
    path: Path
    source: str | None


def _write_executable(data: bytes, dest: Path, make_executable: MakeExecutable) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    make_executable(dest)


def _extract_syft_binary(data: bytes, artifact_name: str) -> bytes:
    """Return the Syft executable bytes from a release tarball."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                if PurePosixPath(member.name).name not in {"syft", "syft.exe"}:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    break
                return extracted.read()
    except tarfile.TarError as exc:
        raise InvalidPin(f"syft artifact {artifact_name!r} is not a readable tar archive") from exc

    raise InvalidPin(f"syft artifact {artifact_name!r} does not contain a syft executable")


def bootstrap_cosign(
    pins: Pins,
    dest: Path,
    *,
    acquire: Acquire,
    make_executable: MakeExecutable,
    platform_key: str | None = None,
) -> ResolvedTool:
    """Acquire + checksum-gate cosign, then make it executable.

    cosign is in the trusted computing base (it verifies Syft's signature), so
    its own bytes are checksum-verified under the same fail-closed gate before it
    is ever executed. There is no signature gate for cosign itself; trust is
    anchored by the pinned sha256.
    """
    plat = platform_key or current_platform()
    pin = pins.tool("cosign")
    artifact: PlatformArtifact = pin.artifact_for(plat)

    data = acquire(artifact.artifact)
    # GATE 1 — raises ChecksumMismatch before write/chmod/exec.
    digest = verify_checksum(data, artifact.sha256)

    _write_executable(data, Path(dest), make_executable)
    return ResolvedTool(
        name="cosign",
        version=pin.version,
        digest=digest,
        path=Path(dest),
        source=pin.source,
    )


def bootstrap_syft(
    pins: Pins,
    dest: Path,
    *,
    acquire: Acquire,
    verifier: SignatureVerifier,
    make_executable: MakeExecutable,
    runner: CommandRunner | None = None,
    platform_key: str | None = None,
    workdir: Path | None = None,
) -> ResolvedTool:
    """Bootstrap Syft with strict fail-closed ordering.

    ``runner`` is accepted only so the canary can assert it is NEVER called on a
    tampered input; this function does not invoke Syft itself.
    """
    plat = platform_key or current_platform()
    pin = pins.tool("syft")
    artifact = pin.artifact_for(plat)
    sig = pin.signature
    # Enforced (not merely asserted) so the invariant holds under `python -O`.
    if sig is None:
        raise InvalidPin("syft pin is missing its required signature block")

    base = Path(workdir) if workdir is not None else Path(dest).parent
    base.mkdir(parents=True, exist_ok=True)

    # 1. acquire the binary artifact + the signed checksums material (no network
    #    here; `acquire` is injected).
    data = acquire(artifact.artifact)

    # 2. GATE 1 — checksum. Raises ChecksumMismatch before anything is written
    #    or made executable.
    digest = verify_checksum(data, artifact.sha256)

    # 3. GATE 2 — signature. The cosign-signed checksums file + its signature +
    #    certificate are written to a dedicated temp dir that is ALWAYS removed
    #    (rpl_security.md §7), so no verification material lingers next to the
    #    installed binary in `dest`.
    with tempfile.TemporaryDirectory(dir=base, prefix=".syft-verify-") as tmp:
        work = Path(tmp)
        checksums_text = acquire(sig.checksums_file).decode("utf-8")
        checksums_path = work / sig.checksums_file
        signature_path = work / sig.checksums_sig
        certificate_path = work / sig.checksums_cert
        checksums_path.write_text(checksums_text, encoding="utf-8")
        signature_path.write_bytes(acquire(sig.checksums_sig))
        certificate_path.write_bytes(acquire(sig.checksums_cert))

        # Raises SignatureVerificationError on failure (before any write/chmod).
        verifier.verify(
            sig,
            checksums_path=checksums_path,
            signature_path=signature_path,
            certificate_path=certificate_path,
        )

        # 4. Provenance cross-check — the manifest-pinned hash MUST equal the
        #    entry in the now-trusted (cosign-verified) checksums file. Closes
        #    the "edit-the-pin" drift gap. Raises ChecksumProvenanceError.
        assert_manifest_hash_signed(
            artifact_name=artifact.artifact,
            manifest_sha256=artifact.sha256,
            trusted_checksums_text=checksums_text,
        )

    # 5. Only now — after BOTH gates and the provenance check, and after the
    #    verification temp dir is removed — extract, write, and chmod the binary.
    executable = _extract_syft_binary(data, artifact.artifact)
    _write_executable(executable, Path(dest), make_executable)

    return ResolvedTool(
        name="syft",
        version=pin.version,
        digest=digest,
        path=Path(dest),
        source=pin.source,
    )
