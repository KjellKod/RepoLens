"""Metadata-only license resolution for mobile lockfile package facts."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import quote, urlparse

from repolens.policy.config import load_default_policy
from repolens.resolve.adapters import API_ALLOWED_HOSTS, target_license_candidates
from repolens.resolve.evidence import UNKNOWN_VERSION
from repolens.resolve.license_expression import license_resolution_id
from repolens.resolve.models import ApiCandidate, FetchFunction, PackageFact
from repolens.resolve.purl import package_identity, parse_purl
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits

MAX_LOCKFILE_CANDIDATES = 16
MAX_DISCOVERY_DIRS = 512
MAX_DISCOVERY_FILES = 4096

_GITHUB_SCP_RE = re.compile(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$")
_POD_VERSION_RE = re.compile(
    r"^\s*-\s+(?P<name>[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)?)"
    r"\s+\((?P<version>[^)]+)\)"
)
_GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def resolve_mobile_metadata(
    package: PackageFact,
    *,
    source_root: Path | None,
    fetcher: FetchFunction,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> ApiCandidate | None:
    """Resolve a SwiftPM or CocoaPods package from stored metadata only."""

    ecosystem, identity = package_identity(package.package_type, package.name, package.purl)
    if ecosystem == "swift":
        return _resolve_swiftpm(package, identity, source_root, fetcher=fetcher, limits=limits)
    if ecosystem == "cocoapods":
        return _resolve_cocoapods(package, identity, source_root, fetcher=fetcher, limits=limits)
    return None


def _resolve_swiftpm(
    package: PackageFact,
    identity: str,
    source_root: Path | None,
    *,
    fetcher: FetchFunction,
    limits: SecurityLimits,
) -> ApiCandidate | None:
    if source_root is None:
        return None
    names = _swift_identity_names(package, identity)
    for path in _candidate_lockfiles(
        source_root,
        package.locations,
        "Package.resolved",
        limits=limits,
    ):
        payload = _read_json_object(path, limits=limits)
        if payload is None:
            continue
        for pin in _swift_pins(payload):
            if not _pin_matches_package(pin, names, package.version):
                continue
            location = _string(pin.get("location"))
            state = pin.get("state")
            if not isinstance(state, dict):
                continue
            revision = _string(state.get("revision"))
            if location is None or revision is None:
                continue
            owner_repo = _github_owner_repo(location)
            if owner_repo is None:
                continue
            owner, repo = owner_repo
            url = (
                f"https://api.github.com/repos/{quote(owner, safe='')}/"
                f"{quote(repo, safe='')}/license?ref={quote(revision, safe='')}"
            )
            return _candidate_from_metadata(fetcher, url, headers=_GITHUB_API_HEADERS)
    return None


def _resolve_cocoapods(
    package: PackageFact,
    identity: str,
    source_root: Path | None,
    *,
    fetcher: FetchFunction,
    limits: SecurityLimits,
) -> ApiCandidate | None:
    root_pod = identity.split("/", 1)[0].strip()
    if not root_pod:
        return None
    version = package.version
    if version == UNKNOWN_VERSION and source_root is not None:
        version = _podfile_lock_version(source_root, package.locations, root_pod, limits=limits)
    if version == UNKNOWN_VERSION:
        return None
    url = (
        f"https://trunk.cocoapods.org/api/v1/pods/{quote(root_pod, safe='')}"
        f"/specs/{quote(version, safe='')}"
    )
    return _candidate_from_metadata(fetcher, url, max_redirects=1)


def _candidate_from_metadata(
    fetcher: FetchFunction,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    max_redirects: int = 0,
) -> ApiCandidate | None:
    try:
        result = fetcher(
            url,
            HttpFetchOptions(
                allowed_hosts=API_ALLOWED_HOSTS,
                headers=headers or {},
                max_redirects=max_redirects,
            ),
        )
    except FetchSecurityError:
        return None
    policy = load_default_policy()
    for license_text in target_license_candidates(result.body):
        spdx_id = license_resolution_id(license_text, policy)
        if spdx_id is not None:
            return ApiCandidate(
                spdx_id=spdx_id,
                evidence_url=result.url,
                evidence_anchor=license_text,
            )
    return None


def _candidate_lockfiles(
    source_root: Path,
    locations: tuple[str, ...],
    filename: str,
    *,
    limits: SecurityLimits,
) -> tuple[Path, ...]:
    root = source_root.resolve()
    location_candidates = _location_lockfiles(root, locations, filename)
    if location_candidates:
        return location_candidates
    return _discover_lockfiles(root, filename, limits=limits)


def _location_lockfiles(root: Path, locations: tuple[str, ...], filename: str) -> tuple[Path, ...]:
    found: list[Path] = []
    for location in locations:
        normalized = location.strip().replace("\\", "/").lstrip("/")
        if not normalized:
            continue
        candidate = root / normalized
        if candidate.name != filename:
            candidate = candidate.parent / filename
        if _safe_file_under_root(root, candidate) and candidate not in found:
            found.append(candidate)
        if len(found) > MAX_LOCKFILE_CANDIDATES:
            return ()
    return tuple(found)


def _discover_lockfiles(root: Path, filename: str, *, limits: SecurityLimits) -> tuple[Path, ...]:
    found: list[Path] = []
    visited_dirs = 0
    visited_files = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_dir = Path(dirpath)
        visited_dirs += 1
        if visited_dirs > MAX_DISCOVERY_DIRS:
            return ()
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if not (current_dir / dirname).is_symlink()
        ]
        for item in filenames:
            visited_files += 1
            if visited_files > MAX_DISCOVERY_FILES:
                return ()
            if item != filename:
                continue
            candidate = current_dir / item
            if not _safe_file_under_root(root, candidate):
                continue
            found.append(candidate)
            if len(found) > MAX_LOCKFILE_CANDIDATES:
                return ()
    del limits
    return tuple(found)


def _safe_file_under_root(root: Path, path: Path) -> bool:
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return False
    current = root
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return False
    return path.is_file()


def _read_json_object(path: Path, *, limits: SecurityLimits) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(limits.max_parse_bytes + 1)
    except OSError:
        return None
    if len(data) > limits.max_parse_bytes:
        return None
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _swift_pins(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    pins = payload.get("pins")
    if not isinstance(pins, list):
        return ()
    return tuple(pin for pin in pins if isinstance(pin, dict))


def _pin_matches_package(
    pin: dict[str, object],
    names: frozenset[str],
    package_version: str,
) -> bool:
    kind = _string(pin.get("kind"))
    if kind is not None and kind != "remoteSourceControl":
        return False
    identity = _string(pin.get("identity"))
    if identity is None or identity.lower() not in names:
        return False
    state = pin.get("state")
    if not isinstance(state, dict):
        return False
    pin_version = _string(state.get("version"))
    return not (
        package_version != UNKNOWN_VERSION
        and pin_version is not None
        and pin_version != package_version
    )


def _swift_identity_names(package: PackageFact, identity: str) -> frozenset[str]:
    parsed = parse_purl(package.purl)
    names = {package.name.lower(), identity.rsplit("/", 1)[-1].lower()}
    if parsed is not None:
        names.add(parsed.name.lower())
    return frozenset(name for name in names if name)


def _github_owner_repo(location: str) -> tuple[str, str] | None:
    scp = _GITHUB_SCP_RE.match(location)
    if scp is not None:
        return scp.group("owner"), _strip_git_suffix(scp.group("repo"))
    parsed = urlparse(location)
    if parsed.scheme not in {"https", "ssh"} or parsed.hostname != "github.com":
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], _strip_git_suffix(parts[1])


def _strip_git_suffix(value: str) -> str:
    return value[:-4] if value.endswith(".git") else value


def _podfile_lock_version(
    source_root: Path,
    locations: tuple[str, ...],
    root_pod: str,
    *,
    limits: SecurityLimits,
) -> str:
    root_lower = root_pod.lower()
    for path in _candidate_lockfiles(
        source_root,
        locations,
        "Podfile.lock",
        limits=limits,
    ):
        try:
            with path.open("rb") as handle:
                data = handle.read(limits.max_parse_bytes + 1)
        except OSError:
            continue
        if len(data) > limits.max_parse_bytes:
            continue
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            match = _POD_VERSION_RE.match(line)
            if match is None:
                continue
            name = match.group("name").split("/", 1)[0].lower()
            if name == root_lower:
                return match.group("version").strip()
    return UNKNOWN_VERSION


def _string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
