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


def render_docx(
    header: ReportHeader,
    columns: Sequence[str],
    rows: Sequence[DisclosureRow],
) -> bytes:
    """Render a minimal valid docx package with escaped, redacted text fields."""

    document_xml = _document_xml(header, columns, rows)
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
    columns: Sequence[str],
    rows: Sequence[DisclosureRow],
) -> str:
    table_rows = [_table_row(columns)]
    table_rows.extend(_table_row(_row_values(row)) for row in rows)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W_NS}"><w:body>'
        f"{_paragraph('RepoLens Main Report')}"
        f"{_paragraph(header.org_name)}"
        f"{_paragraph(header.legal_text)}"
        "<w:tbl>"
        + _table_grid(len(columns))
        + "".join(table_rows)
        + "</w:tbl><w:sectPr/></w:body></w:document>"
    )


def _table_grid(column_count: int) -> str:
    grid_cols = "<w:gridCol/>" * column_count
    return (
        '<w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>'
        f"<w:tblGrid>{grid_cols}</w:tblGrid>"
    )


def _paragraph(value: object) -> str:
    return f"<w:p><w:r><w:t>{_xml_text(value)}</w:t></w:r></w:p>"


def _table_row(values: Sequence[object]) -> str:
    cells = "".join(f"<w:tc>{_paragraph(value)}</w:tc>" for value in values)
    return f"<w:tr>{cells}</w:tr>"


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
