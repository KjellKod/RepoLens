"""Positive-evidence scanner for JS bundle release artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from repolens.data.limits import max_bytes_for
from repolens.data.store import _check_bytes
from repolens.exit_codes import InputError
from repolens.presence.models import DeliveryArtifact
from repolens.resolve.purl import parse_purl


@dataclass(frozen=True, slots=True)
class BundleScanResult:
    artifact: DeliveryArtifact
    matched: Mapping[str, tuple[str, ...]]
    scanned: bool = True


def npm_package_name_from_purl(purl: object) -> str | None:
    parsed = parse_purl(str(purl) if purl is not None else None)
    if parsed is None or parsed.package_type != "npm":
        return None
    return f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name


def scan_js_bundle(
    artifact_path: Path,
    package_names: Iterable[str],
    *,
    target: str,
) -> BundleScanResult:
    artifact = Path(artifact_path)
    if not artifact.exists() or not artifact.is_file():
        raise InputError(f"release artifact must exist and be a regular file: {artifact}")
    raw = artifact.read_bytes()
    _check_bytes(raw, max_bytes_for("release_artifact"), artifact)
    texts = [raw.decode("utf-8", errors="replace")]
    source_map = artifact.with_name(f"{artifact.name}.map")
    if source_map.exists() and source_map.is_file():
        map_raw = source_map.read_bytes()
        _check_bytes(map_raw, max_bytes_for("release_artifact"), source_map)
        texts.append(map_raw.decode("utf-8", errors="replace"))

    digest = hashlib.sha256(raw).hexdigest()
    matched: dict[str, tuple[str, ...]] = {}
    for package_name in sorted(set(package_names)):
        marker = f"node_modules/{package_name}/"
        if any(marker in text for text in texts):
            matched[package_name] = (marker,)
    return BundleScanResult(
        artifact=DeliveryArtifact(
            kind=target,
            path=str(artifact),
            hash=f"sha256:{digest}",
        ),
        matched=matched,
    )
