"""Render the R1 main disclosure report from resolved records."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from repolens.config import Config
from repolens.data import store
from repolens.data.limits import max_bytes_for
from repolens.discovery.taxonomy import DEFAULT_CATEGORY
from repolens.exit_codes import InputError
from repolens.report.categories import RoutedRecord, build_category_index, route_occurrences
from repolens.report.docx import render_docx
from repolens.report.gate import ReportGateOpen, run_report_gate
from repolens.report.selection import report_header_from_config, report_selection_from_config
from repolens.security.redaction import redact_tokens
from repolens.security.sanitize import (
    markdown_link,
    render_code_span,
    sanitize_markdown,
    serialize_csv_rows,
)

COLUMNS = (
    "name",
    "spdx_id",
    "version",
    "source_url",
    "modified?",
    "origin",
    "scope",
    "distribution",
    "found_in",
    "evidence_source_layer",
    "coverage_gaps",
)

_NONE = "none"
_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DisclosureRow:
    """One deduplicated report row."""

    name: str
    spdx_id: str
    versions: tuple[str, ...]
    source_urls: tuple[str, ...]
    modified: tuple[str, ...]
    origins: tuple[str, ...]
    scopes: tuple[str, ...]
    distributions: tuple[str, ...]
    found_in: tuple[str, ...]
    evidence_source_layers: tuple[str, ...]
    coverage_gaps: tuple[str, ...]


@dataclass(frozen=True)
class ReportResult:
    """Paths and summary for emitted report artifacts."""

    markdown_path: Path
    csv_path: Path
    docx_path: Path
    row_count: int
    file_gaps: tuple[str, ...]
    appendix_paths: tuple[Path, ...] = ()


@dataclass
class _DisclosureAccumulator:
    name: str
    spdx_id: str
    versions: set[str] = field(default_factory=set)
    source_urls: set[str] = field(default_factory=set)
    modified: set[str] = field(default_factory=set)
    origins: set[str] = field(default_factory=set)
    scopes: set[str] = field(default_factory=set)
    distributions: set[str] = field(default_factory=set)
    found_in: set[str] = field(default_factory=set)
    evidence_source_layers: set[str] = field(default_factory=set)
    coverage_gaps: set[str] = field(default_factory=set)

    def to_row(self) -> DisclosureRow:
        gaps = set(self.coverage_gaps)
        if len(self.origins) > 1:
            gaps.add("mixed_origin")
        if len(self.scopes) > 1:
            gaps.add("mixed_scope")
        if len(self.distributions) > 1:
            gaps.add("mixed_distribution")
        if len(self.modified) > 1:
            gaps.add("mixed_modified")
        return DisclosureRow(
            name=self.name,
            spdx_id=self.spdx_id,
            versions=_sorted_values(self.versions),
            source_urls=_sorted_values(self.source_urls),
            modified=_sorted_values(self.modified),
            origins=_sorted_values(self.origins),
            scopes=_sorted_values(self.scopes),
            distributions=_sorted_values(self.distributions),
            found_in=_sorted_values(self.found_in),
            evidence_source_layers=_sorted_values(self.evidence_source_layers),
            coverage_gaps=_sorted_values(gaps),
        )


def render_main_report(
    work_root: Path,
    out_dir: Path | None = None,
    config: Config | None = None,
) -> ReportResult:
    """Render main and appendix report artifacts from resolved occurrences."""

    root = Path(work_root)
    output_dir = Path(out_dir) if out_dir is not None else root / "out"
    gate = run_report_gate(root)
    if not gate.clear:
        raise ReportGateOpen(gate.message)

    header = report_header_from_config(config)
    selection = report_selection_from_config(config)
    category_index = build_category_index(_read_discovered_or_empty(root))
    default_category = _default_category(config)

    records, file_gaps = collect_resolved_records(root)
    split = route_occurrences(records, category_index, selection.include, default_category)
    rows = aggregate_rows(split.main_records)

    csv_text = redact_tokens(render_csv(rows))
    markdown_text = redact_tokens(render_markdown(rows, file_gaps))
    docx_bytes = render_docx(header, COLUMNS, rows)

    csv_path = output_dir / "report.main.csv"
    markdown_path = output_dir / "report.main.md"
    docx_path = output_dir / "report.main.docx"
    store.atomic_write_bytes(csv_path, csv_text.encode("utf-8"))
    store.atomic_write_bytes(markdown_path, markdown_text.encode("utf-8"))
    store.atomic_write_bytes(docx_path, docx_bytes)

    appendix_paths: list[Path] = []
    for label, routed_records in split.appendix_records_by_label.items():
        appendix_rows = aggregate_rows(routed_records)
        stem = f"report.appendix.{quote(label, safe='')}"
        appendix_csv_path = output_dir / f"{stem}.csv"
        appendix_markdown_path = output_dir / f"{stem}.md"
        appendix_csv = redact_tokens(render_csv(appendix_rows))
        appendix_markdown = redact_tokens(
            render_markdown(
                appendix_rows,
                (),
                title=f"RepoLens Appendix: {label}",
            )
        )
        store.atomic_write_bytes(appendix_csv_path, appendix_csv.encode("utf-8"))
        store.atomic_write_bytes(appendix_markdown_path, appendix_markdown.encode("utf-8"))
        appendix_paths.extend((appendix_markdown_path, appendix_csv_path))

    return ReportResult(
        markdown_path=markdown_path,
        csv_path=csv_path,
        docx_path=docx_path,
        row_count=len(rows),
        file_gaps=tuple(file_gaps),
        appendix_paths=tuple(appendix_paths),
    )


def collect_resolved_records(work_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Collect records from ``work/*/resolved.ndjson`` using the store boundary."""

    work_dir = Path(work_root) / "work"
    if not work_dir.is_dir():
        raise InputError("report requires work/<repo>/resolved.ndjson input")

    repo_dirs = sorted((path for path in work_dir.iterdir() if path.is_dir()), key=_path_sort_key)
    if not repo_dirs:
        raise InputError("report requires at least one work/<repo>/resolved.ndjson input")

    records: list[dict[str, Any]] = []
    file_gaps: list[str] = []
    resolved_seen = False
    for repo_dir in repo_dirs:
        resolved_path = repo_dir / "resolved.ndjson"
        if not resolved_path.exists():
            if (repo_dir / "sbom.syft.json").exists():
                raise InputError(
                    f"incomplete R1 input: missing {resolved_path.relative_to(work_root)}"
                )
            continue

        resolved_seen = True
        before_count = len(records)
        records.extend(store.iter_resolved(resolved_path))
        if len(records) == before_count:
            file_gaps.append(f"empty_resolved_file: {resolved_path.relative_to(work_root)}")

    if not resolved_seen:
        raise InputError("report found no work/<repo>/resolved.ndjson input")
    return records, sorted(file_gaps, key=lambda value: (value.casefold(), value))


def aggregate_rows(records: Iterable[dict[str, Any] | RoutedRecord]) -> list[DisclosureRow]:
    """Deduplicate records by ``(name, spdx_id or UNKNOWN)`` and aggregate fields."""

    groups: dict[tuple[str, str], _DisclosureAccumulator] = {}
    for raw_record in records:
        record, extra_gaps = _record_and_extra_gaps(raw_record)
        name = str(record["name"])
        spdx_id = _normalized_spdx(record.get("spdx_id"))
        key = (name, spdx_id)
        group = groups.setdefault(key, _DisclosureAccumulator(name=name, spdx_id=spdx_id))
        if spdx_id == _UNKNOWN:
            group.coverage_gaps.add("missing_spdx_id")

        group.versions.add(str(record["version"]))
        group.found_in.add(str(record["repo"]))
        group.modified.add(_modified_value(record["modified"]))

        evidence = _object_mapping(record["evidence"], "evidence")
        group.evidence_source_layers.add(str(evidence["source_layer"]))
        source_url = _optional_text(evidence.get("url"))
        if source_url is None:
            group.coverage_gaps.add("missing_source_url")
        else:
            group.source_urls.add(source_url)

        tags = _object_mapping(record["tags"], "tags")
        group.origins.add(str(tags["origin"]))
        group.scopes.add(str(tags["scope"]))
        group.distributions.add(str(tags["distribution"]))
        group.coverage_gaps.update(extra_gaps)

    return sorted(
        (group.to_row() for group in groups.values()),
        key=lambda row: (row.name.casefold(), row.spdx_id.casefold(), row.name, row.spdx_id),
    )


def render_csv(rows: Sequence[DisclosureRow]) -> str:
    """Render report rows as neutralized CSV."""

    csv_rows: list[tuple[object, ...]] = [COLUMNS]
    csv_rows.extend(
        (
            row.name,
            row.spdx_id,
            _join(row.versions),
            _join(row.source_urls),
            _join(row.modified),
            _join(row.origins),
            _join(row.scopes),
            _join(row.distributions),
            _join(row.found_in),
            _join(row.evidence_source_layers),
            _coverage(row.coverage_gaps),
        )
        for row in rows
    )
    return serialize_csv_rows(csv_rows)


def render_markdown(
    rows: Sequence[DisclosureRow],
    file_gaps: Sequence[str],
    *,
    title: str = "RepoLens Main Report",
) -> str:
    """Render report rows as sanitized Markdown."""

    lines = [
        f"# {title.replace(chr(10), ' ')}",
        "",
        "| " + " | ".join(_markdown_table_cell(column) for column in COLUMNS) + " |",
        "| " + " | ".join("---" for _ in COLUMNS) + " |",
    ]

    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_table_cell(render_code_span(row.name)),
                    _markdown_table_cell(row.spdx_id),
                    _markdown_table_cell(_join(row.versions)),
                    _markdown_table_cell(_markdown_source_urls(row.source_urls)),
                    _markdown_table_cell(_join(row.modified)),
                    _markdown_table_cell(_join(row.origins)),
                    _markdown_table_cell(_join(row.scopes)),
                    _markdown_table_cell(_join(row.distributions)),
                    _markdown_table_cell(_join(row.found_in)),
                    _markdown_table_cell(_join(row.evidence_source_layers)),
                    _markdown_table_cell(_coverage(row.coverage_gaps)),
                )
            )
            + " |"
        )

    if file_gaps:
        lines.extend(["", "## Coverage Gaps", ""])
        lines.extend(f"- {render_code_span(gap)}" for gap in file_gaps)

    return sanitize_markdown("\n".join(lines) + "\n")


def _object_mapping(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"resolved record {field_name} must be an object")
    return value


def _normalized_spdx(value: object) -> str:
    text = "" if value is None else str(value).strip()
    return text or _UNKNOWN


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _modified_value(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _sorted_values(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(values, key=lambda value: (value.casefold(), value)))


def _join(values: Sequence[str]) -> str:
    return "; ".join(values)


def _coverage(gaps: Sequence[str]) -> str:
    return _join(gaps) if gaps else _NONE


def _markdown_source_urls(source_urls: Sequence[str]) -> str:
    return "; ".join(markdown_link(url, url) for url in source_urls)


def _markdown_table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _record_and_extra_gaps(
    raw_record: dict[str, Any] | RoutedRecord,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(raw_record, RoutedRecord):
        return raw_record.record, raw_record.extra_coverage_gaps
    return raw_record, ()


def _read_discovered_or_empty(work_root: Path) -> dict[str, object]:
    path = Path(work_root) / "discovered.json"
    if not path.exists():
        return {"repositories": []}
    value = store.load_json_capped(path, max_bytes=max_bytes_for("discovered"))
    if not isinstance(value, dict):
        raise InputError("discovered.json must be an object")
    return value


def _default_category(config: Config | None) -> str:
    if config is None:
        return DEFAULT_CATEGORY
    discover = config.values.get("discover", {})
    if discover is None:
        return DEFAULT_CATEGORY
    if not isinstance(discover, dict):
        raise InputError("config discover must be an object")
    taxonomy = discover.get("taxonomy", {})
    if taxonomy is None:
        return DEFAULT_CATEGORY
    if not isinstance(taxonomy, dict):
        raise InputError("config discover.taxonomy must be an object")
    raw_default = taxonomy.get("default_category")
    if raw_default is None:
        return DEFAULT_CATEGORY
    if not isinstance(raw_default, str) or not raw_default.strip():
        raise InputError("config discover.taxonomy.default_category must be a non-empty string")
    return raw_default.strip()


def _path_sort_key(path: Path) -> tuple[str, str]:
    text = path.as_posix()
    return (text.casefold(), text)
