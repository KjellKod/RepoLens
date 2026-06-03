"""Shared cache for RepoLens-verified Syft.

The cache is keyed by RepoLens's own Syft pin: version plus the pinned release
artifact sha256. A cached executable is trusted only when its proof file matches
the current pin and the executable's own sha256 matches the proof.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .errors import IntegrityError, UsageError
from .orchestrate import default_make_executable
from .pins import DEFAULT_PINS_PATH, Pins, SignatureSpec, current_platform, load_pins
from .syft import Acquire, MakeExecutable, bootstrap_cosign, bootstrap_syft
from .verify import CommandRunner, CosignVerifier, compute_file_sha256

PROOF_SCHEMA = "repolens.syft-cache-proof/v1"
DOC_LINK = "docs/usage.md#tool-bootstrap"
MAX_PINNED_ARTIFACT_BYTES = 250 * 1024 * 1024


@dataclass(frozen=True)
class SyftPinSummary:
    """The current RepoLens-owned Syft pin for one platform."""

    version: str
    artifact: str
    artifact_sha256: str
    source: str | None
    platform_key: str
    signature: SignatureSpec

    @property
    def short_sha256(self) -> str:
        return self.artifact_sha256[:12]

    @property
    def cache_key(self) -> str:
        return f"{self.version}-{self.artifact_sha256}"

    @property
    def cosign_note(self) -> str:
        return (
            f"{self.signature.mechanism} identity {self.signature.cert_identity_regex} "
            f"issuer {self.signature.cert_oidc_issuer}"
        )


@dataclass(frozen=True)
class SyftCacheResult:
    """Result of resolving or acquiring the shared Syft cache entry."""

    path: Path
    pin: SyftPinSummary
    acquired: bool


def default_cache_home() -> Path:
    """Return the XDG cache root RepoLens should use."""

    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".cache"


def load_syft_pin(
    pins_path: Path | str = DEFAULT_PINS_PATH,
    *,
    platform_key: str | None = None,
) -> SyftPinSummary:
    """Read the current platform's RepoLens Syft pin from ``pins.toml``."""

    return _syft_pin_from_pins(load_pins(pins_path), platform_key=platform_key)


def syft_cache_dir(pin: SyftPinSummary, *, cache_home: Path | str | None = None) -> Path:
    """Return the content-addressed cache directory for a Syft pin."""

    root = Path(cache_home) if cache_home is not None else default_cache_home()
    return root / "repolens" / "tools" / pin.cache_key


def syft_cache_path(pin: SyftPinSummary, *, cache_home: Path | str | None = None) -> Path:
    """Return the executable path for a Syft pin."""

    return syft_cache_dir(pin, cache_home=cache_home) / "syft"


def syft_cache_proof_path(pin: SyftPinSummary, *, cache_home: Path | str | None = None) -> Path:
    """Return the proof path for a Syft pin."""

    return syft_cache_dir(pin, cache_home=cache_home) / "syft.proof.json"


def cached_syft_path(
    pin: SyftPinSummary,
    *,
    cache_home: Path | str | None = None,
    make_executable: MakeExecutable = default_make_executable,
) -> Path | None:
    """Return a valid cached Syft path, or ``None`` if the cache is absent/stale."""

    syft_path = syft_cache_path(pin, cache_home=cache_home)
    proof_path = syft_cache_proof_path(pin, cache_home=cache_home)
    if not syft_path.is_file() or not proof_path.is_file():
        return None

    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    expected = {
        "schema": PROOF_SCHEMA,
        "tool": "syft",
        "version": pin.version,
        "platform": pin.platform_key,
        "artifact": pin.artifact,
        "artifact_sha256": pin.artifact_sha256,
    }
    for key, value in expected.items():
        if proof.get(key) != value:
            return None

    binary_sha256 = proof.get("binary_sha256")
    if not isinstance(binary_sha256, str) or not binary_sha256:
        return None
    try:
        if compute_file_sha256(syft_path) != binary_sha256:
            return None
    except OSError:
        return None

    make_executable(syft_path)
    return syft_path


def ensure_syft_cached(
    *,
    pins_path: Path | str = DEFAULT_PINS_PATH,
    cache_home: Path | str | None = None,
    acquire: Acquire | None = None,
    cosign_runner: CommandRunner | None = None,
    make_executable: MakeExecutable = default_make_executable,
    platform_key: str | None = None,
    offline: bool = False,
) -> SyftCacheResult:
    """Return a verified shared-cache Syft path, acquiring it when allowed."""

    pins = load_pins(pins_path)
    pin = _syft_pin_from_pins(pins, platform_key=platform_key)
    cached = cached_syft_path(pin, cache_home=cache_home, make_executable=make_executable)
    if cached is not None:
        return SyftCacheResult(path=cached, pin=pin, acquired=False)

    if offline:
        raise UsageError(_cache_required_message(pin))

    acquirer = acquire or _url_acquire_for(pins)
    runner = cosign_runner or _default_command_runner
    target_dir = syft_cache_dir(pin, cache_home=cache_home)
    target_root = target_dir.parent
    target_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".syft-cache-", dir=target_root) as tmp:
        staging = Path(tmp)
        cosign_tool = bootstrap_cosign(
            pins,
            staging / "cosign",
            acquire=acquirer,
            make_executable=make_executable,
            platform_key=pin.platform_key,
        )
        resolved = bootstrap_syft(
            pins,
            staging / "syft",
            acquire=acquirer,
            verifier=CosignVerifier(cosign_tool.path, runner),
            make_executable=make_executable,
            platform_key=pin.platform_key,
            workdir=staging,
        )
        binary_sha256 = compute_file_sha256(resolved.path)
        (staging / "syft.proof.json").write_text(
            json.dumps(_proof_payload(pin, binary_sha256), indent=2) + "\n",
            encoding="utf-8",
        )

        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True)
        shutil.move(str(staging / "syft"), str(target_dir / "syft"))
        shutil.move(str(staging / "syft.proof.json"), str(target_dir / "syft.proof.json"))

    cached_after_write = cached_syft_path(
        pin,
        cache_home=cache_home,
        make_executable=make_executable,
    )
    if cached_after_write is None:
        raise IntegrityError("Syft cache proof failed after verified acquisition.")
    return SyftCacheResult(path=cached_after_write, pin=pin, acquired=True)


def _syft_pin_from_pins(pins: Pins, *, platform_key: str | None = None) -> SyftPinSummary:
    plat = platform_key or current_platform()
    syft = pins.tool("syft")
    artifact = syft.artifact_for(plat)
    if syft.signature is None:
        raise UsageError("Syft pin is missing its required signature block.")
    return SyftPinSummary(
        version=syft.version,
        artifact=artifact.artifact,
        artifact_sha256=artifact.sha256,
        source=syft.source,
        platform_key=plat,
        signature=syft.signature,
    )


def _proof_payload(pin: SyftPinSummary, binary_sha256: str) -> dict[str, str | None]:
    return {
        "schema": PROOF_SCHEMA,
        "tool": "syft",
        "version": pin.version,
        "platform": pin.platform_key,
        "artifact": pin.artifact,
        "artifact_sha256": pin.artifact_sha256,
        "binary_sha256": binary_sha256,
        "source": pin.source,
        "signature_mechanism": pin.signature.mechanism,
        "signature_identity": pin.signature.cert_identity_regex,
        "signature_issuer": pin.signature.cert_oidc_issuer,
    }


def _cache_required_message(pin: SyftPinSummary) -> str:
    return (
        f"RepoLens's validated Syft {pin.version} (sha256 {pin.short_sha256}...) "
        "is required but is not in the verified shared cache. Nothing was downloaded. "
        f"See {DOC_LINK}. Rerun with --yes or run `repolens bootstrap` before offline use."
    )


def _url_acquire_for(pins: Pins) -> Acquire:
    def acquire(name: str) -> bytes:
        url = _artifact_url(pins, name)
        request = urllib.request.Request(url, headers={"User-Agent": "repolens-bootstrap/0"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return _read_pinned_response(response, name)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IntegrityError(f"failed to acquire pinned artifact {name!r}") from exc

    return acquire


def _read_pinned_response(
    response: object,
    name: str,
    *,
    max_bytes: int = MAX_PINNED_ARTIFACT_BYTES,
) -> bytes:
    body = response.read(max_bytes + 1)  # type: ignore[attr-defined]
    if len(body) > max_bytes:
        raise IntegrityError(f"pinned artifact {name!r} is too large")
    return body


def _artifact_url(pins: Pins, name: str) -> str:
    for tool_name in ("syft", "cosign"):
        tool = pins.tool(tool_name)
        if tool.source is None:
            continue
        known_names = {artifact.artifact for artifact in tool.platforms.values()}
        if tool.signature is not None:
            known_names.update(
                {
                    tool.signature.checksums_file,
                    tool.signature.checksums_sig,
                    tool.signature.checksums_cert,
                }
            )
        if name not in known_names:
            continue
        source = tool.source.rstrip("/")
        parsed = urllib.parse.urlparse(source)
        if parsed.scheme != "https" or not parsed.netloc:
            raise IntegrityError(f"pinned source for {tool_name} must be https")
        return f"{source}/{urllib.parse.quote(name)}"
    raise IntegrityError(f"artifact {name!r} is not declared by RepoLens pins")


def _default_command_runner(argv: list[str]) -> int:
    return subprocess.run(list(argv), check=False).returncode
