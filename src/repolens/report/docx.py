"""Deterministic stdlib OOXML writer for disclosure reports."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Sequence
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from repolens.report.selection import ReportHeader
from repolens.security.redaction import redact_tokens

if TYPE_CHECKING:
    from repolens.report.main import DisclosureRow

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_LANDSCAPE_PAGE_WIDTH_DXA = 15840
_LANDSCAPE_PAGE_HEIGHT_DXA = 12240
_PAGE_MARGIN_DXA = 576
_TABLE_WIDTH_DXA = _LANDSCAPE_PAGE_WIDTH_DXA - (2 * _PAGE_MARGIN_DXA)
_BODY_FONT_HALF_POINTS = 16
_COLUMN_WIDTHS_DXA = {
    "name": 1500,
    "spdx_id": 900,
    "software license (spdx)": 1400,
    "description": 2700,
    "version": 950,
    "source_url": 3600,
    "source url": 3400,
    "modified?": 760,
    "origin": 1300,
    "scope": 850,
    "distribution": 1000,
    "found_in": 1200,
    "evidence_source_layer": 1000,
    "evidence source": 1200,
    "coverage_gaps": 1628,
}


def render_docx(
    header: ReportHeader,
    columns: Sequence[str],
    rows: Sequence[DisclosureRow],
) -> bytes:
    """Render a minimal valid docx package with escaped, redacted text fields."""

    document_xml = _document_xml(
        header,
        "RepoLens Main Report",
        (("", columns, tuple(_row_values(row) for row in rows)),),
    )
    return _docx_package(document_xml)


def render_docx_sections(
    header: ReportHeader,
    title: str,
    sections: Sequence[tuple[str, Sequence[str], Sequence[Sequence[object]]]],
    *,
    preface: str | None = None,
) -> bytes:
    """Render a minimal valid docx package with one table per section."""

    document_xml = _document_xml(header, title, sections, preface=preface)
    return _docx_package(document_xml)


def _docx_package(document_xml: str) -> bytes:
    parts = {
        "[Content_Types].xml": _CONTENT_TYPES,
        "_rels/.rels": _ROOT_RELS,
        "word/document.xml": document_xml,
        "word/_rels/document.xml.rels": _DOCUMENT_RELS,
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(parts):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, parts[name].encode("utf-8"))
    return output.getvalue()


def _document_xml(
    header: ReportHeader,
    title: str,
    sections: Sequence[tuple[str, Sequence[str], Sequence[Sequence[object]]]],
    *,
    preface: str | None = None,
) -> str:
    section_xml = []
    if preface:
        section_xml.append(_paragraph(preface))
    for section_title, columns, rows in sections:
        if section_title:
            section_xml.append(_paragraph(section_title, size_half_points=18, bold=True))
        column_widths = _column_widths(columns)
        table_rows = [_table_row(columns, column_widths, bold=True)]
        table_rows.extend(_table_row(row, column_widths) for row in rows)
        section_xml.append(
            "<w:tbl>" + _table_grid(column_widths) + "".join(table_rows) + "</w:tbl>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W_NS}"><w:body>'
        f"{_paragraph(title, size_half_points=24, bold=True)}"
        f"{_paragraph(header.org_name, size_half_points=20)}"
        f"{_paragraph(header.legal_text, size_half_points=18)}"
        + "".join(section_xml)
        + f"{_section_properties()}</w:body></w:document>"
    )


def _table_grid(column_widths: Sequence[int]) -> str:
    grid_cols = "".join(f'<w:gridCol w:w="{width}"/>' for width in column_widths)
    return (
        f'<w:tblPr><w:tblW w:w="{_TABLE_WIDTH_DXA}" w:type="dxa"/>'
        '<w:tblLayout w:type="fixed"/>'
        "<w:tblCellMar>"
        '<w:top w:w="80" w:type="dxa"/>'
        '<w:left w:w="80" w:type="dxa"/>'
        '<w:bottom w:w="80" w:type="dxa"/>'
        '<w:right w:w="80" w:type="dxa"/>'
        "</w:tblCellMar>"
        "</w:tblPr>"
        f"<w:tblGrid>{grid_cols}</w:tblGrid>"
    )


def _paragraph(
    value: object,
    *,
    size_half_points: int = _BODY_FONT_HALF_POINTS,
    bold: bool = False,
) -> str:
    bold_xml = "<w:b/>" if bold else ""
    return (
        "<w:p><w:pPr>"
        '<w:spacing w:after="0" w:line="240" w:lineRule="auto"/>'
        "</w:pPr><w:r><w:rPr>"
        f'{bold_xml}<w:sz w:val="{size_half_points}"/>'
        f"</w:rPr><w:t>{_xml_text(value)}</w:t></w:r></w:p>"
    )


def _table_row(
    values: Sequence[object],
    column_widths: Sequence[int],
    *,
    bold: bool = False,
) -> str:
    cells = "".join(
        (
            "<w:tc><w:tcPr>"
            f'<w:tcW w:w="{width}" w:type="dxa"/>'
            '<w:vAlign w:val="top"/>'
            "</w:tcPr>"
            f"{_paragraph(value, bold=bold)}</w:tc>"
        )
        for value, width in zip(values, column_widths, strict=True)
    )
    return f"<w:tr>{cells}</w:tr>"


def _section_properties() -> str:
    return (
        "<w:sectPr>"
        f'<w:pgSz w:w="{_LANDSCAPE_PAGE_WIDTH_DXA}" '
        f'w:h="{_LANDSCAPE_PAGE_HEIGHT_DXA}" w:orient="landscape"/>'
        f'<w:pgMar w:top="{_PAGE_MARGIN_DXA}" w:right="{_PAGE_MARGIN_DXA}" '
        f'w:bottom="{_PAGE_MARGIN_DXA}" w:left="{_PAGE_MARGIN_DXA}" '
        'w:header="360" w:footer="360" w:gutter="0"/>'
        "</w:sectPr>"
    )


def _column_widths(columns: Sequence[str]) -> tuple[int, ...]:
    fallback_width = _TABLE_WIDTH_DXA // len(columns)
    return tuple(_COLUMN_WIDTHS_DXA.get(column, fallback_width) for column in columns)


def _row_values(row: DisclosureRow) -> tuple[str, ...]:
    return (
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
        _join(row.coverage_gaps) if row.coverage_gaps else "none",
    )


def _xml_text(value: object) -> str:
    redacted = redact_tokens(value)
    return escape(_sanitize_xml_text(redacted))


def _sanitize_xml_text(value: str) -> str:
    return "".join(character for character in value if _is_xml_10_char(character))


def _is_xml_10_char(character: str) -> bool:
    codepoint = ord(character)
    return (
        codepoint in {0x09, 0x0A, 0x0D}
        or 0x20 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xFFFD
        or 0x10000 <= codepoint <= 0x10FFFF
    )


def _join(values: Sequence[str]) -> str:
    return "; ".join(values)


_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    "</Types>"
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    "</Relationships>"
)

_DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
)
