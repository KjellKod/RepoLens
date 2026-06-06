"""Render presentation-focused disclosure report artifacts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse

from repolens.data import store
from repolens.report.docx import render_docx_sections
from repolens.report.main import DisclosureRow
from repolens.report.selection import ReportHeader
from repolens.security.redaction import redact_tokens
from repolens.security.sanitize import (
    markdown_link,
    render_code_span,
    sanitize_markdown,
    serialize_csv_rows,
)

PRESENTATION_COLUMNS = (
    "name",
    "software license (spdx)",
    "description",
    "version",
    "source url",
    "found_id",
    "evidence source",
)
DATA_LIMITATION_NOTE = (
    "Description and found_id are not durable resolved-report fields today; "
    "presentation rows show this as not available rather than inventing values."
)
UNAVAILABLE = "n/a"
_HTML_COLUMN_WIDTHS = (15, 12, 21, 10, 27, 8, 7)


@dataclass(frozen=True)
class PresentationRow:
    """One row in the sibling presentation report."""

    name: str
    spdx_id: str
    description: str
    version: str
    source_urls: tuple[str, ...]
    found_id: str
    evidence_source: str


@dataclass(frozen=True)
class PresentationResult:
    """Paths and summary for emitted presentation artifacts."""

    markdown_path: Path
    csv_path: Path
    html_path: Path
    row_count: int
    docx_path: Path | None = None
    docx_skipped: bool = False


def render_presentation_artifacts(
    rows: Sequence[DisclosureRow],
    out_dir: Path,
    *,
    header: ReportHeader | None = None,
) -> PresentationResult:
    """Write presentation markdown/csv/html and optional header-gated docx."""

    presentation_rows = presentation_rows_from_disclosure(rows)
    output_dir = Path(out_dir)
    csv_path = output_dir / "report.presentation.csv"
    markdown_path = output_dir / "report.presentation.md"
    html_path = output_dir / "report.presentation.html"
    docx_path = output_dir / "report.presentation.docx" if header is not None else None

    store.atomic_write_bytes(
        csv_path,
        redact_tokens(render_presentation_csv(presentation_rows)).encode("utf-8"),
    )
    store.atomic_write_bytes(
        markdown_path,
        redact_tokens(render_presentation_markdown(presentation_rows)).encode("utf-8"),
    )
    store.atomic_write_bytes(
        html_path,
        redact_tokens(render_presentation_html(presentation_rows)).encode("utf-8"),
    )
    if header is not None and docx_path is not None:
        store.atomic_write_bytes(docx_path, render_presentation_docx(header, presentation_rows))

    return PresentationResult(
        markdown_path=markdown_path,
        csv_path=csv_path,
        html_path=html_path,
        docx_path=docx_path,
        row_count=len(presentation_rows),
        docx_skipped=header is None,
    )


def presentation_rows_from_disclosure(rows: Sequence[DisclosureRow]) -> tuple[PresentationRow, ...]:
    """Map existing main-report rows into flat presentation rows."""

    return tuple(
        sorted(
            (
                PresentationRow(
                    name=row.name,
                    spdx_id=row.spdx_id,
                    description=UNAVAILABLE,
                    version=_join(row.versions),
                    source_urls=tuple(row.source_urls),
                    found_id=UNAVAILABLE,
                    evidence_source=_join(row.evidence_source_layers),
                )
                for row in rows
            ),
            key=lambda row: (
                row.spdx_id.casefold(),
                row.name.casefold(),
                row.version.casefold(),
                row.spdx_id,
                row.name,
                row.version,
            ),
        )
    )


def render_presentation_csv(rows: Sequence[PresentationRow]) -> str:
    """Render presentation rows as flat, neutralized CSV."""

    csv_rows: list[tuple[object, ...]] = [PRESENTATION_COLUMNS]
    csv_rows.extend(_row_values(row) for row in rows)
    return serialize_csv_rows(csv_rows)


def render_presentation_markdown(rows: Sequence[PresentationRow]) -> str:
    """Render presentation rows grouped by exact SPDX expression."""

    lines = [
        "# RepoLens Presentation Report",
        "",
        f"> {DATA_LIMITATION_NOTE}",
        "",
    ]
    grouped = _group_rows(rows)
    if not grouped:
        lines.append("No report rows.")
    for spdx_id, group_rows in grouped:
        lines.extend(
            [
                f"## {spdx_id} ({len(group_rows)})",
                "",
                "| " + " | ".join(_markdown_cell(column) for column in PRESENTATION_COLUMNS) + " |",
                "| " + " | ".join("---" for _ in PRESENTATION_COLUMNS) + " |",
            ]
        )
        for row in group_rows:
            lines.append(
                "| "
                + " | ".join(
                    (
                        _markdown_cell(render_code_span(row.name)),
                        _markdown_cell(row.spdx_id),
                        _markdown_cell(row.description),
                        _markdown_cell(row.version),
                        _markdown_cell(_markdown_source_urls(row.source_urls)),
                        _markdown_cell(row.found_id),
                        _markdown_cell(row.evidence_source),
                    )
                )
                + " |"
            )
        lines.append("")
    return sanitize_markdown("\n".join(lines).rstrip() + "\n")


def render_presentation_html(rows: Sequence[PresentationRow]) -> str:
    """Render presentation rows as a grouped, self-contained HTML report."""

    grouped = _group_rows(rows)
    colgroup = "".join(f'<col style="width: {width}%">' for width in _HTML_COLUMN_WIDTHS)
    header_cells = "".join(
        f'<th scope="col">{_html_text(column)}</th>' for column in PRESENTATION_COLUMNS
    )
    if not grouped:
        sections = '<p class="empty">No report rows.</p>'
    else:
        sections = "".join(
            _html_group_section(spdx_id, group_rows, colgroup, header_cells)
            for spdx_id, group_rows in grouped
        )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>RepoLens Presentation Report</title>\n"
        "<style>\n"
        ":root { color-scheme: light; }\n"
        "@page { size: letter landscape; margin: 0.35in; }\n"
        "body { margin: 24px; font: 14px/1.4 Arial, Helvetica, sans-serif; color: #111827; }\n"
        "h1 { margin: 0 0 10px; font-size: 24px; line-height: 1.2; }\n"
        "h2 { margin: 22px 0 8px; font-size: 17px; }\n"
        ".note { margin: 0 0 18px; color: #4b5563; }\n"
        ".table-wrap { width: 100%; border: 1px solid #d1d5db; }\n"
        "table { border-collapse: collapse; table-layout: fixed; width: 100%; }\n"
        "th, td { border: 1px solid #d1d5db; padding: 6px 8px; "
        "vertical-align: top; text-align: left; }\n"
        "th { background: #f3f4f6; font-weight: 700; }\n"
        "td { overflow-wrap: anywhere; word-break: break-word; }\n"
        "code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; "
        "font-size: 0.92em; }\n"
        "a { color: #0f4c81; text-decoration: underline; }\n"
        "@media print {\n"
        "  body { margin: 0; font-size: 8pt; }\n"
        "  h1 { font-size: 16pt; }\n"
        "  h2 { font-size: 11pt; }\n"
        "  .table-wrap { border: 0; }\n"
        "  th, td { padding: 3pt 4pt; }\n"
        "}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>RepoLens Presentation Report</h1>\n"
        f'<p class="note">{_html_text(DATA_LIMITATION_NOTE)}</p>\n'
        f"{sections}"
        "</body>\n"
        "</html>\n"
    )


def render_presentation_docx(
    header: ReportHeader,
    rows: Sequence[PresentationRow],
) -> bytes:
    """Render presentation rows as grouped DOCX tables."""

    sections = tuple(
        (
            f"{spdx_id} ({len(group_rows)})",
            PRESENTATION_COLUMNS,
            tuple(_row_values(row) for row in group_rows),
        )
        for spdx_id, group_rows in _group_rows(rows)
    )
    if not sections:
        sections = (("No report rows", PRESENTATION_COLUMNS, ()),)
    return render_docx_sections(
        header,
        "RepoLens Presentation Report",
        sections,
        preface=DATA_LIMITATION_NOTE,
    )


def _html_group_section(
    spdx_id: str,
    rows: Sequence[PresentationRow],
    colgroup: str,
    header_cells: str,
) -> str:
    body_rows = "".join(
        "<tr>"
        + "".join(
            (
                f"<td><code>{_html_text(row.name)}</code></td>",
                f"<td>{_html_text(row.spdx_id)}</td>",
                f"<td>{_html_text(row.description)}</td>",
                f"<td>{_html_text(row.version)}</td>",
                f"<td>{_html_source_urls(row.source_urls)}</td>",
                f"<td>{_html_text(row.found_id)}</td>",
                f"<td>{_html_text(row.evidence_source)}</td>",
            )
        )
        + "</tr>"
        for row in rows
    )
    return (
        "<section>\n"
        f"<h2>{_html_text(spdx_id)} ({len(rows)})</h2>\n"
        '<div class="table-wrap"><table>\n'
        f"{colgroup}\n"
        f"<thead><tr>{header_cells}</tr></thead>\n"
        f"<tbody>{body_rows}</tbody>\n"
        "</table></div>\n"
        "</section>\n"
    )


def _group_rows(
    rows: Sequence[PresentationRow],
) -> tuple[tuple[str, tuple[PresentationRow, ...]], ...]:
    groups: dict[str, list[PresentationRow]] = defaultdict(list)
    for row in rows:
        groups[row.spdx_id].append(row)
    return tuple(
        (spdx_id, tuple(sorted(group_rows, key=_row_sort_key)))
        for spdx_id, group_rows in sorted(
            groups.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    )


def _row_sort_key(row: PresentationRow) -> tuple[str, str, str, str, str, str]:
    return (
        row.name.casefold(),
        row.version.casefold(),
        row.spdx_id.casefold(),
        row.name,
        row.version,
        row.spdx_id,
    )


def _row_values(row: PresentationRow) -> tuple[str, ...]:
    return (
        row.name,
        row.spdx_id,
        row.description,
        row.version,
        _join(row.source_urls),
        row.found_id,
        row.evidence_source,
    )


def _markdown_source_urls(source_urls: Sequence[str]) -> str:
    return "; ".join(markdown_link(url, url) for url in source_urls if url.strip())


def _html_source_urls(source_urls: Sequence[str]) -> str:
    return "; ".join(_html_link(url) for url in source_urls if url.strip())


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _html_link(url: str) -> str:
    label = _html_text(url)
    if not _safe_html_url(url):
        return _html_inert_url_text(url)
    href = html_escape(url, quote=True)
    return f'<a href="{href}" rel="noopener noreferrer">{label}</a>'


def _safe_html_url(url: str) -> bool:
    stripped = url.strip()
    if not stripped:
        return False
    try:
        parsed = urlparse(stripped)
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https", "mailto"}


def _html_inert_url_text(url: str) -> str:
    label = _html_text(url)
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return label
    if parsed.scheme:
        colon_index = label.find(":")
        if colon_index != -1:
            return f"{label[:colon_index]}&#58;{label[colon_index + 1 :]}"
    return label


def _html_text(value: object) -> str:
    text = "" if value is None else str(value)
    return html_escape(text.replace("\n", " "), quote=False)


def _join(values: Sequence[str]) -> str:
    return "; ".join(values)
