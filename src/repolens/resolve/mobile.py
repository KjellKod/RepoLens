"""Mobile repository detection and native enrichment orchestration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from repolens.policy.config import load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.models import ApiCandidate, PackageFact
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.sandbox import (
    SandboxExecutionError,
    SandboxRunner,
    SandboxUnavailable,
    build_native_tool_sandbox_spec,
    unavailable_runner,
)

ANDROID_PLUGIN_MARKERS = (
    "com.android.application",
    "com.android.library",
    "com.android.tools.build:gradle",
)
ANDROID_MARKER_FILES = ("build.gradle", "settings.gradle")
IOS_MARKER_NAMES = ("Package.swift", "Podfile", "Cartfile")


@dataclass(frozen=True, slots=True)
class MobileDetection:
    """Detected mobile platforms and marker paths."""

    android: bool = False
    ios: bool = False
    markers: tuple[Path, ...] = ()

    @property
    def detected(self) -> bool:
        return self.android or self.ios


@dataclass(frozen=True, slots=True)
class MobileEnrichmentOutcome:
    """Result of a native mobile enrichment attempt."""

    candidate: ApiCandidate | None = None
    unresolved_anchor: str | None = None


def detect_mobile(
    source_root: str | Path | None, *, limits: SecurityLimits = DEFAULT_LIMITS
) -> MobileDetection:
    """Detect Android/iOS marker files under ``source_root``."""

    if source_root is None:
        return MobileDetection()
    root = Path(source_root)
    if not root.is_dir():
        return MobileDetection()
    root = root.resolve()
    markers: list[Path] = []
    android = False
    for name in ANDROID_MARKER_FILES:
        marker = root / name
        if not marker.is_file():
            continue
        with marker.open("rb") as handle:
            text = handle.read(limits.max_parse_bytes).decode("utf-8", errors="replace")
        if any(plugin in text for plugin in ANDROID_PLUGIN_MARKERS):
            android = True
            markers.append(marker)

    ios_markers: list[Path] = []
    for name in IOS_MARKER_NAMES:
        marker = root / name
        if marker.exists():
            ios_markers.append(marker)
    ios_markers.extend(root.glob("*.xcodeproj"))
    ios = bool(ios_markers)
    markers.extend(ios_markers)
    return MobileDetection(android=android, ios=ios, markers=tuple(markers))


def enrich_mobile_native(
    package: PackageFact,
    *,
    detection: MobileDetection,
    source_root: Path,
    sandbox_runner: SandboxRunner = unavailable_runner,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> MobileEnrichmentOutcome:
    """Try native mobile license enrichment through a sandbox runner."""

    if not detection.detected:
        return MobileEnrichmentOutcome()
    argv = _tool_argv(detection)
    if argv is None:
        return MobileEnrichmentOutcome(unresolved_anchor="unresolved:mobile_toolchain_unavailable")
    spec = build_native_tool_sandbox_spec(
        argv,
        source_root=source_root,
        timeout_seconds=limits.clone_timeout_seconds,
    )
    try:
        result = sandbox_runner(spec)
    except SandboxUnavailable:
        return MobileEnrichmentOutcome(unresolved_anchor="unresolved:mobile_sandbox_unavailable")
    except (SandboxExecutionError, TimeoutError):
        return MobileEnrichmentOutcome(unresolved_anchor="unresolved:mobile_tool_failed")
    if result.returncode != 0:
        return MobileEnrichmentOutcome(unresolved_anchor="unresolved:mobile_tool_failed")
    return MobileEnrichmentOutcome(candidate=_candidate_from_output(package, result.stdout))


def _tool_argv(detection: MobileDetection) -> tuple[str, ...] | None:
    if detection.android:
        return ("aboutlibraries", "--export-license-json", "/out/licenses.json")
    if detection.ios:
        return ("license-plist", "--output-path", "/dev/stdout")
    return None


def _candidate_from_output(package: PackageFact, text: str) -> ApiCandidate | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    candidates: dict[str, str] = {}
    for entry in _entries(payload):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("artifactId") or "").strip()
        if name and name != package.name:
            continue
        for key in ("spdx_id", "spdx", "license", "licenseName"):
            raw = entry.get(key)
            if not isinstance(raw, str) or not raw.strip():
                continue
            normalized = normalize_license(raw, load_default_policy())
            if normalized.spdx_id is not None:
                candidates.setdefault(normalized.spdx_id, raw.strip())
    if len(candidates) > 1:
        return ApiCandidate(
            spdx_id="CONFLICT",
            evidence_url="mobile-native://sandbox",
            evidence_anchor="conflict:mobile_disagreement",
        )
    if candidates:
        spdx_id, anchor = next(iter(candidates.items()))
        return ApiCandidate(
            spdx_id=spdx_id,
            evidence_url="mobile-native://sandbox",
            evidence_anchor=anchor,
        )
    return None


def _entries(payload: object) -> tuple[object, ...]:
    if isinstance(payload, list):
        return tuple(payload)
    if isinstance(payload, dict):
        for key in ("dependencies", "libraries", "licenses"):
            value = payload.get(key)
            if isinstance(value, list):
                return tuple(value)
    return ()
