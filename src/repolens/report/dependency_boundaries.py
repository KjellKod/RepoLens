"""Dependency-boundary summaries derived from stored SBOM evidence."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from repolens.data import store
from repolens.data.errors import ArtifactError, LimitExceeded
from repolens.security.errors import ParseSecurityError
from repolens.security.parsers import parse_yaml_bytes
from repolens.security.sanitize import render_code_span, sanitize_markdown, serialize_csv_rows

DEPENDABOT_COVERED = "dependabot_covered"
DEPENDABOT_UNCOVERED = "dependabot_uncovered"
DEPENDABOT_UNKNOWN = "dependabot_unknown"

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
_HOST_ABSOLUTE_ROOTS = frozenset(
    {
        "Applications",
        "Library",
        "System",
        "Users",
        "Volumes",
        "bin",
        "dev",
        "etc",
        "home",
        "opt",
        "private",
        "proc",
        "sbin",
        "tmp",
        "usr",
        "var",
    }
)


@dataclass(frozen=True)
class DependencyBoundaryRow:
    """One manifest/location boundary and its derived counts."""

    repo: str
    manifest_path: str
    ecosystem: str
    row_count: int
    unique_purl_count: int
    unique_package_name_count: int
    top_level_area: str
    helper_path: bool
    dependabot_status: str
    repeated_package_count: int
    drift_package_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "repo": self.repo,
            "manifest_path": self.manifest_path,
            "ecosystem": self.ecosystem,
            "row_count": self.row_count,
            "unique_purl_count": self.unique_purl_count,
            "unique_package_name_count": self.unique_package_name_count,
            "top_level_area": self.top_level_area,
            "helper_path": self.helper_path,
            "dependabot_status": self.dependabot_status,
            "repeated_package_count": self.repeated_package_count,
            "drift_package_count": self.drift_package_count,
        }


@dataclass(frozen=True)
class RepeatedPackage:
    """One package/version identity repeated across boundaries."""

    purl: str
    manifest_path_count: int
    row_count: int
    sample_manifest_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "purl": self.purl,
            "manifest_path_count": self.manifest_path_count,
            "row_count": self.row_count,
            "sample_manifest_paths": list(self.sample_manifest_paths),
        }


@dataclass(frozen=True)
class VersionDrift:
    """One package name with multiple versions across boundaries."""

    package_name: str
    versions: tuple[str, ...]
    manifest_path_count: int
    sample_manifest_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "package_name": self.package_name,
            "versions": list(self.versions),
            "manifest_path_count": self.manifest_path_count,
            "sample_manifest_paths": list(self.sample_manifest_paths),
        }


@dataclass(frozen=True)
class DependencyBoundarySummary:
    """Complete dependency-boundary report data."""

    total_component_rows: int
    boundary_attributed_row_count: int
    unique_purl_count: int
    unique_package_name_count: int
    unique_manifest_path_count: int
    helper_path_row_count: int
    dependabot_covered_manifest_count: int
    dependabot_uncovered_manifest_count: int
    dependabot_unknown_manifest_count: int
    rows_by_top_level_area: tuple[tuple[str, int], ...]
    top_repeated_packages: tuple[RepeatedPackage, ...]
    version_drift: tuple[VersionDrift, ...]
    dropped_path_count: int
    dropped_path_reasons: tuple[tuple[str, int], ...]
    boundaries: tuple[DependencyBoundaryRow, ...]

    @property
    def has_data(self) -> bool:
        return self.total_component_rows > 0 or self.boundary_attributed_row_count > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "total_component_rows": self.total_component_rows,
            "boundary_attributed_row_count": self.boundary_attributed_row_count,
            "unique_purl_count": self.unique_purl_count,
            "unique_package_name_count": self.unique_package_name_count,
            "unique_manifest_path_count": self.unique_manifest_path_count,
            "helper_path_row_count": self.helper_path_row_count,
            "dependabot_covered_manifest_count": self.dependabot_covered_manifest_count,
            "dependabot_uncovered_manifest_count": self.dependabot_uncovered_manifest_count,
            "dependabot_unknown_manifest_count": self.dependabot_unknown_manifest_count,
            "rows_by_top_level_area": dict(self.rows_by_top_level_area),
            "top_repeated_packages": [item.to_dict() for item in self.top_repeated_packages],
            "version_drift": [item.to_dict() for item in self.version_drift],
            "dropped_path_count": self.dropped_path_count,
            "dropped_path_reasons": dict(self.dropped_path_reasons),
            "boundaries": [row.to_dict() for row in self.boundaries],
        }


@dataclass
class _BoundaryAccumulator:
    repo: str
    manifest_path: str
    row_count: int = 0
    ecosystems: set[str] = field(default_factory=set)
    purls: set[str] = field(default_factory=set)
    package_names: set[str] = field(default_factory=set)
    repeated_packages: set[str] = field(default_factory=set)
    drift_packages: set[str] = field(default_factory=set)
    dependabot_status: str = DEPENDABOT_UNKNOWN

    def to_row(self) -> DependencyBoundaryRow:
        return DependencyBoundaryRow(
            repo=self.repo,
            manifest_path=self.manifest_path,
            ecosystem=_join_sorted(self.ecosystems),
            row_count=self.row_count,
            unique_purl_count=len(self.purls),
            unique_package_name_count=len(self.package_names),
            top_level_area=_top_level_area(self.manifest_path),
            helper_path=_is_helper_path(self.manifest_path),
            dependabot_status=self.dependabot_status,
            repeated_package_count=len(self.repeated_packages),
            drift_package_count=len(self.drift_packages),
        )


@dataclass(frozen=True)
class _DependabotEntry:
    ecosystem: str
    directory: str


@dataclass(frozen=True)
class _NormalizedPath:
    path: str | None
    dropped_reason: str | None = None


def build_dependency_boundary_summary(work_root: str | Path) -> DependencyBoundarySummary | None:
    """Build a dependency-boundary summary from stored SBOM artifacts."""

    root = Path(work_root)
    work_dir = root / "work"
    if not work_dir.is_dir():
        return None

    boundaries: dict[tuple[str, str], _BoundaryAccumulator] = {}
    all_purls: set[str] = set()
    all_package_names: set[str] = set()
    total_component_rows = 0
    boundary_attributed_row_count = 0
    dropped_reasons: Counter[str] = Counter()
    purl_boundaries: dict[str, set[tuple[str, str]]] = defaultdict(set)
    purl_row_counts: Counter[str] = Counter()
    package_versions: dict[str, set[str]] = defaultdict(set)
    package_boundaries: dict[str, set[tuple[str, str]]] = defaultdict(set)

    for repo_dir in sorted((path for path in work_dir.iterdir() if path.is_dir()), key=_path_key):
        repo_ref = unquote(repo_dir.name)
        sbom_path = repo_dir / "sbom.syft.json"
        if not sbom_path.exists():
            continue
        try:
            sbom = store.read_sbom(root, repo_ref)
        except (ArtifactError, LimitExceeded, OSError):
            dropped_reasons["unreadable_sbom"] += 1
            continue
        raw_artifacts = sbom.get("artifacts")
        if not isinstance(raw_artifacts, list):
            continue

        dependabot_entries = _dependabot_entries(root, repo_ref)
        repo_boundary_paths: set[str] = set()

        for artifact in raw_artifacts:
            if not isinstance(artifact, Mapping):
                continue
            total_component_rows += 1
            name = _text(artifact.get("name"), "unknown")
            ecosystem = _text(artifact.get("type"), "unknown")
            version = _text(artifact.get("version"), "unknown")
            purl = _purl_identity(artifact, name=name, ecosystem=ecosystem, version=version)
            all_purls.add(purl)
            all_package_names.add(name)

            safe_locations = []
            for raw_location in _raw_locations(artifact.get("locations")):
                normalized = _normalize_boundary_path(raw_location)
                if normalized.path is None:
                    dropped_reasons[normalized.dropped_reason or "unsafe_path"] += 1
                    continue
                safe_locations.append(normalized.path)

            for manifest_path in sorted(set(safe_locations), key=_string_key):
                key = (repo_ref, manifest_path)
                repo_boundary_paths.add(manifest_path)
                boundary = boundaries.setdefault(
                    key,
                    _BoundaryAccumulator(repo=repo_ref, manifest_path=manifest_path),
                )
                boundary.row_count += 1
                boundary.ecosystems.add(ecosystem)
                boundary.purls.add(purl)
                boundary.package_names.add(name)
                boundary_attributed_row_count += 1
                purl_boundaries[purl].add(key)
                purl_row_counts[purl] += 1
                package_versions[name].add(version)
                package_boundaries[name].add(key)

        for manifest_path in repo_boundary_paths:
            key = (repo_ref, manifest_path)
            boundaries[key].dependabot_status = _dependabot_status(
                manifest_path,
                dependabot_entries,
            )

    repeated_purls = {
        purl for purl, manifest_paths in purl_boundaries.items() if len(manifest_paths) > 1
    }
    drift_names = {
        name
        for name, versions in package_versions.items()
        if len(versions) > 1 and len(package_boundaries[name]) > 1
    }

    for purl in repeated_purls:
        for key in purl_boundaries[purl]:
            boundaries[key].repeated_packages.add(purl)
    for name in drift_names:
        for key in package_boundaries[name]:
            boundaries[key].drift_packages.add(name)

    rows = tuple(
        sorted(
            (boundary.to_row() for boundary in boundaries.values()),
            key=lambda row: (
                row.repo.casefold(),
                row.manifest_path.casefold(),
                row.repo,
                row.manifest_path,
            ),
        )
    )
    status_counts = Counter(row.dependabot_status for row in rows)
    rows_by_area = Counter[str]()
    helper_path_row_count = 0
    for row in rows:
        rows_by_area[row.top_level_area] += row.row_count
        if row.helper_path:
            helper_path_row_count += row.row_count

    summary = DependencyBoundarySummary(
        total_component_rows=total_component_rows,
        boundary_attributed_row_count=boundary_attributed_row_count,
        unique_purl_count=len(all_purls),
        unique_package_name_count=len(all_package_names),
        unique_manifest_path_count=len(rows),
        helper_path_row_count=helper_path_row_count,
        dependabot_covered_manifest_count=status_counts[DEPENDABOT_COVERED],
        dependabot_uncovered_manifest_count=status_counts[DEPENDABOT_UNCOVERED],
        dependabot_unknown_manifest_count=status_counts[DEPENDABOT_UNKNOWN],
        rows_by_top_level_area=tuple(
            sorted(rows_by_area.items(), key=lambda item: (-item[1], item[0].casefold(), item[0]))
        ),
        top_repeated_packages=_top_repeated_packages(
            repeated_purls, purl_boundaries, purl_row_counts
        ),
        version_drift=_version_drift(drift_names, package_versions, package_boundaries),
        dropped_path_count=sum(dropped_reasons.values()),
        dropped_path_reasons=tuple(
            sorted(dropped_reasons.items(), key=lambda item: (item[0].casefold(), item[0]))
        ),
        boundaries=rows,
    )
    return summary if summary.has_data else None


def write_dependency_boundary_artifacts(
    output_dir: str | Path,
    summary: DependencyBoundarySummary,
) -> tuple[Path, Path, Path]:
    """Write JSON, CSV, and Markdown dependency-boundary artifacts."""

    out = Path(output_dir)
    json_path = out / "dependency-boundaries.json"
    csv_path = out / "report.dependency-boundaries.csv"
    markdown_path = out / "report.dependency-boundaries.md"

    store.atomic_write_json(json_path, summary.to_dict())
    store.atomic_write_bytes(csv_path, render_dependency_boundaries_csv(summary).encode("utf-8"))
    store.atomic_write_bytes(
        markdown_path,
        render_dependency_boundaries_markdown(summary).encode("utf-8"),
    )
    return json_path, csv_path, markdown_path


def render_dependency_boundaries_csv(summary: DependencyBoundarySummary) -> str:
    rows: list[tuple[object, ...]] = [
        (
            "repo",
            "manifest_path",
            "ecosystem",
            "row_count",
            "unique_purl_count",
            "unique_package_name_count",
            "top_level_area",
            "helper_path",
            "dependabot_status",
            "repeated_package_count",
            "drift_package_count",
        )
    ]
    rows.extend(
        (
            row.repo,
            row.manifest_path,
            row.ecosystem,
            row.row_count,
            row.unique_purl_count,
            row.unique_package_name_count,
            row.top_level_area,
            str(row.helper_path).lower(),
            row.dependabot_status,
            row.repeated_package_count,
            row.drift_package_count,
        )
        for row in summary.boundaries
    )
    return serialize_csv_rows(rows)


def render_dependency_boundaries_markdown(
    summary: DependencyBoundarySummary,
    *,
    title: str = "RepoLens Dependency Boundaries",
    heading_level: int = 1,
    top_n: int = 10,
) -> str:
    heading = "#" * heading_level
    lines = [
        f"{heading} {title}",
        "",
        "High component counts can reflect repeated transitive dependencies across intentional "
        "subprojects. Boundary-attributed rows can exceed raw component rows when one component "
        "has multiple safe locations.",
        "",
        "## Summary" if heading_level == 1 else f"{heading}# Summary",
        "",
        f"- Total component rows: {summary.total_component_rows}",
        f"- Boundary-attributed rows: {summary.boundary_attributed_row_count}",
        f"- Unique package/version purls: {summary.unique_purl_count}",
        f"- Unique package names: {summary.unique_package_name_count}",
        f"- Unique manifest paths: {summary.unique_manifest_path_count}",
        f"- Helper/script path rows: {summary.helper_path_row_count}",
        (
            "- Dependabot status: "
            f"{summary.dependabot_covered_manifest_count} covered, "
            f"{summary.dependabot_uncovered_manifest_count} uncovered, "
            f"{summary.dependabot_unknown_manifest_count} unknown"
        ),
    ]
    if summary.dropped_path_count:
        reasons = ", ".join(f"{reason}={count}" for reason, count in summary.dropped_path_reasons)
        lines.append(f"- Dropped unsafe path locations: {summary.dropped_path_count} ({reasons})")

    if summary.rows_by_top_level_area:
        lines.extend(
            [
                "",
                "## Rows By Top-Level Area"
                if heading_level == 1
                else f"{heading}# Rows By Top-Level Area",
                "",
            ]
        )
        for area, count in summary.rows_by_top_level_area[:top_n]:
            lines.append(f"- {render_code_span(area)}: {count}")

    if summary.boundaries:
        lines.extend(
            [
                "",
                "## Top Boundary Rows" if heading_level == 1 else f"{heading}# Top Boundary Rows",
                "",
            ]
        )
        for row in sorted(
            summary.boundaries,
            key=lambda item: (-item.row_count, item.repo.casefold(), item.manifest_path.casefold()),
        )[:top_n]:
            lines.append(
                f"- {render_code_span(row.repo)} {render_code_span(row.manifest_path)}: "
                f"{row.row_count} rows, {row.dependabot_status}"
            )

    uncovered = [row for row in summary.boundaries if row.dependabot_status == DEPENDABOT_UNCOVERED]
    if uncovered:
        lines.extend(
            [
                "",
                "## Dependabot-Uncovered Boundaries"
                if heading_level == 1
                else f"{heading}# Dependabot-Uncovered Boundaries",
                "",
            ]
        )
        for row in uncovered[:top_n]:
            lines.append(
                f"- {render_code_span(row.repo)} {render_code_span(row.manifest_path)} "
                f"({row.row_count} rows)"
            )

    if summary.top_repeated_packages:
        lines.extend(
            [
                "",
                "## Top Repeated Package/Version Purls"
                if heading_level == 1
                else f"{heading}# Top Repeated Package/Version Purls",
                "",
            ]
        )
        for item in summary.top_repeated_packages[:top_n]:
            lines.append(
                f"- {render_code_span(item.purl)} appears in "
                f"{item.manifest_path_count} manifest paths ({item.row_count} rows)"
            )

    if summary.version_drift:
        lines.extend(
            ["", "## Version Drift" if heading_level == 1 else f"{heading}# Version Drift", ""]
        )
        for item in summary.version_drift[:top_n]:
            versions = ", ".join(render_code_span(version) for version in item.versions)
            lines.append(
                f"- {render_code_span(item.package_name)} has {len(item.versions)} versions "
                f"across {item.manifest_path_count} manifest paths: {versions}"
            )

    lines.append("")
    return sanitize_markdown("\n".join(lines))


def _dependabot_entries(work_root: Path, repo_ref: str) -> tuple[_DependabotEntry, ...] | None:
    snapshot = store.read_source_snapshot(work_root, repo_ref)
    if snapshot is None:
        return None
    path = snapshot / ".github" / "dependabot.yml"
    if not path.exists():
        path = snapshot / ".github" / "dependabot.yaml"
    if not path.exists():
        return None
    try:
        parsed = parse_yaml_bytes(path.read_bytes())
    except (OSError, ParseSecurityError, ValueError):
        return None
    if not isinstance(parsed, Mapping):
        return None
    updates = parsed.get("updates")
    if not isinstance(updates, list):
        return None
    entries: list[_DependabotEntry] = []
    for raw in updates:
        if not isinstance(raw, Mapping):
            continue
        ecosystem = _optional_text(raw.get("package-ecosystem"))
        directory = _normalize_dependabot_directory(raw.get("directory"))
        if ecosystem is None or directory is None:
            continue
        entries.append(_DependabotEntry(ecosystem=ecosystem, directory=directory))
    return tuple(entries) if entries else None


def _dependabot_status(
    manifest_path: str,
    entries: tuple[_DependabotEntry, ...] | None,
) -> str:
    if entries is None:
        return DEPENDABOT_UNKNOWN
    for entry in entries:
        if not entry.directory:
            return DEPENDABOT_COVERED
        if manifest_path == entry.directory or manifest_path.startswith(f"{entry.directory}/"):
            return DEPENDABOT_COVERED
    return DEPENDABOT_UNCOVERED


def _normalize_dependabot_directory(value: object) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    text = text.replace("\\", "/").strip()
    if text in {"", "/"}:
        return ""
    text = text.strip("/")
    normalized = _normalize_boundary_path(text)
    return normalized.path


def _raw_locations(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    locations: list[str] = []
    for item in value:
        if isinstance(item, str):
            locations.append(item)
        elif isinstance(item, Mapping):
            path = item.get("path")
            if isinstance(path, str):
                locations.append(path)
    return tuple(locations)


def _normalize_boundary_path(value: str) -> _NormalizedPath:
    text = value.strip()
    if not text:
        return _NormalizedPath(None, "empty_path")
    text = text.replace("\\", "/")
    if _CONTROL_CHAR_RE.search(text):
        return _NormalizedPath(None, "control_character")
    if text.startswith("~/") or _WINDOWS_DRIVE_RE.match(text):
        return _NormalizedPath(None, "absolute_path")
    if text.startswith("/"):
        text = text.lstrip("/")
        first = text.split("/", 1)[0]
        if first in _HOST_ABSOLUTE_ROOTS:
            return _NormalizedPath(None, "absolute_path")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        return _NormalizedPath(None, "traversal_path")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if not parts:
        return _NormalizedPath(None, "empty_path")
    return _NormalizedPath("/".join(parts))


def _purl_identity(
    artifact: Mapping[str, object],
    *,
    name: str,
    ecosystem: str,
    version: str,
) -> str:
    purl = _optional_text(artifact.get("purl"))
    if purl is not None:
        return purl
    return f"{ecosystem}:{name}@{version}"


def _top_repeated_packages(
    repeated_purls: set[str],
    purl_boundaries: Mapping[str, set[tuple[str, str]]],
    purl_row_counts: Counter[str],
) -> tuple[RepeatedPackage, ...]:
    items = [
        RepeatedPackage(
            purl=purl,
            manifest_path_count=len(purl_boundaries[purl]),
            row_count=purl_row_counts[purl],
            sample_manifest_paths=tuple(
                f"{repo}:{path}"
                for repo, path in sorted(
                    purl_boundaries[purl],
                    key=lambda item: (item[0].casefold(), item[1].casefold(), item[0], item[1]),
                )[:5]
            ),
        )
        for purl in repeated_purls
    ]
    return tuple(
        sorted(
            items,
            key=lambda item: (-item.manifest_path_count, -item.row_count, item.purl.casefold()),
        )
    )


def _version_drift(
    drift_names: set[str],
    package_versions: Mapping[str, set[str]],
    package_boundaries: Mapping[str, set[tuple[str, str]]],
) -> tuple[VersionDrift, ...]:
    items = [
        VersionDrift(
            package_name=name,
            versions=tuple(sorted(package_versions[name], key=_string_key)),
            manifest_path_count=len(package_boundaries[name]),
            sample_manifest_paths=tuple(
                f"{repo}:{path}"
                for repo, path in sorted(
                    package_boundaries[name],
                    key=lambda item: (item[0].casefold(), item[1].casefold(), item[0], item[1]),
                )[:5]
            ),
        )
        for name in drift_names
    ]
    return tuple(
        sorted(
            items,
            key=lambda item: (-len(item.versions), -item.manifest_path_count, item.package_name),
        )
    )


def _is_helper_path(path: str) -> bool:
    return "scripts" in PurePosixPath(path).parts


def _top_level_area(path: str) -> str:
    parts = PurePosixPath(path).parts
    if len(parts) <= 1:
        return "."
    return parts[0]


def _join_sorted(values: Iterable[str]) -> str:
    return "; ".join(sorted(values, key=_string_key))


def _text(value: object, default: str) -> str:
    text = _optional_text(value)
    return text if text is not None else default


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _path_key(path: Path) -> tuple[str, str]:
    text = path.as_posix()
    return (text.casefold(), text)


def _string_key(value: str) -> tuple[str, str]:
    return (value.casefold(), value)
