from __future__ import annotations

import zipfile
from io import BytesIO
from xml.etree import ElementTree

import pytest

from repolens.config import Config
from repolens.exit_codes import InputError
from repolens.report import COLUMNS, DisclosureRow
from repolens.report.docx import render_docx
from repolens.report.selection import ReportHeader, report_header_from_config


def test_docx_has_required_ooxml_parts() -> None:
    names = set(_zip(render_docx(_header(), COLUMNS, [_row()])).namelist())

    assert names == {
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/_rels/document.xml.rels",
    }


def test_docx_escapes_untrusted_text_and_urls() -> None:
    payload = render_docx(
        _header(org_name="Org <&>", legal_text="Legal ]]> & text"),
        COLUMNS,
        [_row(name="component <script/>", source_urls=("javascript:alert(1)&x=<y>",))],
    )
    xml = _document_xml(payload)

    ElementTree.fromstring(xml)
    assert b"<script/>" not in xml
    assert b"component &lt;script/&gt;" in xml
    assert b"javascript:alert(1)&amp;x=&lt;y&gt;" in xml


def test_docx_redacts_tokens_before_xml_serialization() -> None:
    token = "ghp_" + "A" * 24
    payload = render_docx(_header(org_name=f"Org {token}"), COLUMNS, [_row(name=token)])
    xml = _document_xml(payload)

    assert token.encode("utf-8") not in payload
    assert token.encode("utf-8") not in xml
    assert b"[REDACTED_TOKEN]" in xml


def test_docx_strips_invalid_xml_control_characters_before_escape() -> None:
    xml = _document_xml(render_docx(_header(legal_text="Legal\x00\x08ok"), COLUMNS, [_row()]))

    ElementTree.fromstring(xml)
    assert b"\x00" not in xml
    assert b"\x08" not in xml
    assert b"Legalok" in xml


def test_docx_injects_runtime_org_and_legal_header() -> None:
    xml = _document_xml(
        render_docx(
            _header(org_name="Runtime Org", legal_text="Runtime legal"),
            COLUMNS,
            [_row()],
        )
    )

    assert b"Runtime Org" in xml
    assert b"Runtime legal" in xml


def test_docx_table_emits_tblpr_and_grid_with_one_col_per_column() -> None:
    xml = _document_xml(render_docx(_header(), COLUMNS, [_row()]))

    root = ElementTree.fromstring(xml)
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    tbl = root.find(f".//{{{w}}}tbl")
    assert tbl is not None
    children = list(tbl)
    assert children[0].tag == f"{{{w}}}tblPr"
    grid = children[1]
    assert grid.tag == f"{{{w}}}tblGrid"
    grid_cols = grid.findall(f"{{{w}}}gridCol")
    assert len(grid_cols) == len(COLUMNS)
    assert [col.attrib[f"{{{w}}}w"] for col in grid_cols] == [
        "1500",
        "900",
        "950",
        "3600",
        "1000",
        "1000",
        "760",
        "1300",
        "850",
        "1000",
        "1200",
        "1000",
        "1628",
    ]


def test_docx_includes_delivery_and_install_columns() -> None:
    xml = _document_xml(
        render_docx(
            _header(),
            COLUMNS,
            [_row(deliveries=("delivery artifact not scanned",), installs=("installed",))],
        )
    )

    assert b"delivery" in xml
    assert b"install" in xml
    assert b"delivery artifact not scanned" in xml


def test_docx_uses_landscape_page_with_fixed_width_table() -> None:
    xml = _document_xml(render_docx(_header(), COLUMNS, [_row()]))

    root = ElementTree.fromstring(xml)
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    section = root.find(f".//{{{w}}}sectPr")
    assert section is not None
    page_size = section.find(f"{{{w}}}pgSz")
    margins = section.find(f"{{{w}}}pgMar")
    assert page_size is not None
    assert margins is not None
    assert page_size.attrib[f"{{{w}}}orient"] == "landscape"
    assert page_size.attrib[f"{{{w}}}w"] == "15840"
    assert page_size.attrib[f"{{{w}}}h"] == "12240"
    assert margins.attrib[f"{{{w}}}left"] == "576"
    assert margins.attrib[f"{{{w}}}right"] == "576"

    table_properties = root.find(f".//{{{w}}}tbl/{{{w}}}tblPr")
    assert table_properties is not None
    table_width = table_properties.find(f"{{{w}}}tblW")
    table_layout = table_properties.find(f"{{{w}}}tblLayout")
    assert table_width is not None
    assert table_width.attrib[f"{{{w}}}type"] == "dxa"
    assert table_width.attrib[f"{{{w}}}w"] == "14688"
    assert table_layout is not None
    assert table_layout.attrib[f"{{{w}}}type"] == "fixed"

    first_cell_width = root.find(f".//{{{w}}}tc/{{{w}}}tcPr/{{{w}}}tcW")
    assert first_cell_width is not None
    assert first_cell_width.attrib[f"{{{w}}}w"] == "1500"


def test_docx_is_byte_deterministic() -> None:
    first = render_docx(_header(), COLUMNS, [_row()])
    second = render_docx(_header(), COLUMNS, [_row()])

    assert first == second


def test_report_header_config_requires_org_name_and_legal_text() -> None:
    with pytest.raises(InputError, match="report.header.org_name"):
        report_header_from_config(
            Config(values={"report": {"header": {"legal_text": "x"}}}, sources=())
        )
    with pytest.raises(InputError, match="report.header.legal_text"):
        report_header_from_config(
            Config(values={"report": {"header": {"org_name": "x"}}}, sources=())
        )


def _zip(payload: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(BytesIO(payload))


def _document_xml(payload: bytes) -> bytes:
    with _zip(payload) as archive:
        return archive.read("word/document.xml")


def _header(org_name: str = "Example Org", legal_text: str = "Example legal") -> ReportHeader:
    return ReportHeader(org_name=org_name, legal_text=legal_text)


def _row(
    *,
    name: str = "acme-lib",
    source_urls: tuple[str, ...] = ("https://example.invalid/license",),
    deliveries: tuple[str, ...] = ("unknown",),
    installs: tuple[str, ...] = ("unknown",),
) -> DisclosureRow:
    return DisclosureRow(
        name=name,
        spdx_id="MIT",
        versions=("1.0.0",),
        source_urls=source_urls,
        modified=("unknown",),
        origins=("third-party-oss",),
        scopes=("runtime",),
        distributions=("server",),
        found_in=("acme-alpha",),
        evidence_source_layers=("syft",),
        coverage_gaps=(),
        deliveries=deliveries,
        installs=installs,
    )
