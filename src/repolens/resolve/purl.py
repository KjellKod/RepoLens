"""Small package-url parser for supported resolve adapters."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True, slots=True)
class ParsedPurl:
    package_type: str
    name: str
    namespace: str | None = None
    version: str | None = None


def parse_purl(value: str | None) -> ParsedPurl | None:
    """Parse only the package-url fields P3a needs.

    This intentionally avoids becoming a full package-url implementation. Unsupported or
    malformed values return ``None`` so callers can lower unresolved instead of guessing.
    """

    if not value or not value.startswith("pkg:"):
        return None

    body = value[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    package_type, rest = body.split("/", 1)
    package_type = unquote(package_type).lower()
    if not package_type or not rest:
        return None

    version: str | None = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version) or None
    parts = [unquote(part) for part in rest.split("/") if part]
    if not parts:
        return None

    name = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    if not name:
        return None
    return ParsedPurl(package_type=package_type, namespace=namespace, name=name, version=version)


def package_identity(package_type: str, name: str, purl: str | None) -> tuple[str, str]:
    """Return normalized ecosystem and package name from SBOM facts."""

    parsed = parse_purl(purl)
    if parsed is not None:
        full_name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
        return parsed.package_type, full_name
    return package_type.lower(), name
