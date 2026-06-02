"""Load and validate the pins manifest (``pins.toml``).

This module is the single gate that turns the raw TOML into typed, validated
data. The same validation primitives (:func:`assert_exact_version`,
:func:`assert_sha256`, :func:`assert_digest_ref`) are reused by
``tools/pins_lint.py`` so the CI gate and the runtime loader cannot drift.
"""

from __future__ import annotations

import platform
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import InvalidPin

SCHEMA = "repolens.pins/v1"

#: Default location of the manifest shipped with the package.
DEFAULT_PINS_PATH = Path(__file__).with_name("pins.toml")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
#: Version strings that indicate a floating / unpinned spec.
_FLOATING_TOKENS = ("latest", "*", "")
_FLOATING_PREFIXES = ("^", "~", ">=", "<=", ">", "<", "=>", "=<")


def assert_exact_version(value: object, where: str) -> str:
    """Return ``value`` if it is an exact, pinned version; else raise InvalidPin."""
    if not isinstance(value, str):
        raise InvalidPin(f"{where}: version must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if stripped.lower() in _FLOATING_TOKENS:
        raise InvalidPin(f"{where}: floating/unpinned version {value!r} is forbidden")
    if any(stripped.startswith(p) for p in _FLOATING_PREFIXES):
        raise InvalidPin(f"{where}: floating version range {value!r} is forbidden")
    return stripped


def assert_sha256(value: object, where: str) -> str:
    """Return ``value`` if it is a 64-hex sha256; else raise InvalidPin."""
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise InvalidPin(f"{where}: sha256 must be 64 lowercase hex chars, got {value!r}")
    return value


def assert_digest_ref(value: object, where: str) -> str:
    """Return ``value`` if it is an image ref pinned by ``@sha256:``; else raise."""
    if not isinstance(value, str) or not _DIGEST_RE.search(value):
        raise InvalidPin(f"{where}: image ref must be pinned by '@sha256:<64hex>', got {value!r}")
    # A bare tag with no digest, or 'latest', must not slip through.
    if ":latest" in value or value.strip().lower().endswith(":latest"):
        raise InvalidPin(f"{where}: image ref must not use the 'latest' tag")
    return value


@dataclass(frozen=True)
class PlatformArtifact:
    """A per-platform downloadable artifact with its trusted sha256."""

    artifact: str
    sha256: str


@dataclass(frozen=True)
class SignatureSpec:
    """cosign signature material for the Syft checksums file."""

    mechanism: str
    checksums_file: str
    checksums_sig: str
    checksums_cert: str
    cert_identity_regex: str
    cert_oidc_issuer: str


@dataclass(frozen=True)
class ToolPin:
    """A pinned tool: exact version + per-platform artifacts (+ optional signature)."""

    name: str
    version: str
    source: str | None = None
    platforms: dict[str, PlatformArtifact] = field(default_factory=dict)
    signature: SignatureSpec | None = None
    requirements: str | None = None

    def artifact_for(self, platform_key: str) -> PlatformArtifact:
        try:
            return self.platforms[platform_key]
        except KeyError as exc:
            available = ", ".join(sorted(self.platforms)) or "<none>"
            raise InvalidPin(
                f"tool {self.name!r}: no artifact pinned for platform {platform_key!r} "
                f"(have: {available})"
            ) from exc


@dataclass(frozen=True)
class Pins:
    """The fully-validated pins manifest."""

    schema: str
    base_image: str
    tools: dict[str, ToolPin]

    def tool(self, name: str) -> ToolPin:
        try:
            return self.tools[name]
        except KeyError as exc:
            raise InvalidPin(f"no pin for tool {name!r}") from exc


def current_platform() -> str:
    """Return the ``os/arch`` key for the host, e.g. ``linux/amd64``."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine, machine)
    return f"{system}/{arch}"


def _require(table: dict, key: str, where: str) -> object:
    if key not in table:
        raise InvalidPin(f"{where}: missing required field {key!r}")
    return table[key]


def _parse_platforms(raw: dict, where: str) -> dict[str, PlatformArtifact]:
    if not isinstance(raw, dict) or not raw:
        raise InvalidPin(f'{where}: at least one [platforms."os/arch"] entry is required')
    out: dict[str, PlatformArtifact] = {}
    for plat, spec in raw.items():
        ploc = f"{where}.platforms[{plat!r}]"
        if not isinstance(spec, dict):
            raise InvalidPin(f"{ploc}: must be a table")
        artifact = _require(spec, "artifact", ploc)
        if not isinstance(artifact, str) or not artifact:
            raise InvalidPin(f"{ploc}: artifact must be a non-empty string")
        sha = assert_sha256(_require(spec, "sha256", ploc), ploc)
        out[plat] = PlatformArtifact(artifact=artifact, sha256=sha)
    return out


def _parse_signature(raw: dict, where: str) -> SignatureSpec:
    if not isinstance(raw, dict):
        raise InvalidPin(f"{where}: signature must be a table")
    required = (
        "mechanism",
        "checksums_file",
        "checksums_sig",
        "checksums_cert",
        "cert_identity_regex",
        "cert_oidc_issuer",
    )
    values: dict[str, str] = {}
    for key in required:
        val = _require(raw, key, where)
        if not isinstance(val, str) or not val:
            raise InvalidPin(f"{where}.{key}: must be a non-empty string")
        values[key] = val
    return SignatureSpec(**values)


def _parse_tool(name: str, raw: dict) -> ToolPin:
    where = f"tools.{name}"
    if not isinstance(raw, dict):
        raise InvalidPin(f"{where}: must be a table")
    version = assert_exact_version(_require(raw, "version", where), where)
    source = raw.get("source")
    if source is not None and (not isinstance(source, str) or not source):
        raise InvalidPin(f"{where}.source: must be a non-empty string when present")

    platforms: dict[str, PlatformArtifact] = {}
    if "platforms" in raw:
        platforms = _parse_platforms(raw["platforms"], where)

    signature = None
    if "signature" in raw:
        signature = _parse_signature(raw["signature"], f"{where}.signature")

    requirements = raw.get("requirements")
    if requirements is not None and (not isinstance(requirements, str) or not requirements):
        raise InvalidPin(f"{where}.requirements: must be a non-empty string when present")

    # A tool with neither platform artifacts nor a requirements file is not
    # verifiable. ScanCode is requirements-pinned; everything else is artifact-
    # pinned.
    if not platforms and requirements is None:
        raise InvalidPin(
            f"{where}: must declare either [platforms.*] artifacts or a 'requirements' file"
        )

    return ToolPin(
        name=name,
        version=version,
        source=source,
        platforms=platforms,
        signature=signature,
        requirements=requirements,
    )


def load_pins_data(data: dict) -> Pins:
    """Validate an already-parsed manifest mapping and return typed :class:`Pins`."""
    schema = _require(data, "schema", "<root>")
    if schema != SCHEMA:
        raise InvalidPin(f"unsupported schema {schema!r}; expected {SCHEMA!r}")

    base = _require(data, "base_image", "<root>")
    if not isinstance(base, dict):
        raise InvalidPin("base_image: must be a table")
    base_ref = assert_digest_ref(_require(base, "ref", "base_image"), "base_image.ref")

    tools_raw = _require(data, "tools", "<root>")
    if not isinstance(tools_raw, dict) or not tools_raw:
        raise InvalidPin("tools: at least one [tools.*] entry is required")

    tools = {name: _parse_tool(name, spec) for name, spec in tools_raw.items()}

    required_tools = {"syft", "scancode", "git", "gh", "cosign"}
    missing = required_tools - tools.keys()
    if missing:
        raise InvalidPin(f"missing required tool pins: {', '.join(sorted(missing))}")

    if tools["syft"].signature is None:
        raise InvalidPin("tools.syft: a [signature] block is required (cosign verification)")

    return Pins(schema=schema, base_image=base_ref, tools=tools)


def load_pins(path: Path | str = DEFAULT_PINS_PATH) -> Pins:
    """Load and validate the pins manifest from ``path``."""
    p = Path(path)
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InvalidPin(f"pins manifest not found: {p}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InvalidPin(f"pins manifest is not valid TOML: {exc}") from exc
    return load_pins_data(raw)
