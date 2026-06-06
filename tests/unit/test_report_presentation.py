from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from repolens.config import Config
from repolens.data import store
from repolens.report import (
    DATA_LIMITATION_NOTE,
    PRESENTATION_COLUMNS,
    DisclosureRow,
    presentation_rows_from_disclosure,
    render_main_report,
    render_presentation_csv,
    render_presentation_docx,
    render_presentation_html,
    render_presentation_markdown,
)
from repolens.report.review import ReviewDecision, review_id_for_row
from repolens.report.selection import ReportHeader


def test_presentation_csv_is_flat_and_sorted_by_spdx_name_version() -> None:
    rows = presentation_rows_from_disclosure(
        (
            _row(name="zeta-lib", spdx_id="MIT", versions=("2.0.0",)),
            _row(name="alpha-lib", spdx_id="Apache-2.0", versions=("1.0.0",)),
            _row(name="alpha-lib", spdx_id="MIT", versions=("1.0.0",)),
        )
    )

    csv_rows = list(csv.reader(io.StringIO(render_presentation_csv(rows))))

    assert tuple(csv_rows[0]) == PRESENTATION_COLUMNS
    assert "found_id" not in csv_rows[0]
    assert [row[0] for row in csv_rows[1:]] == ["alpha-lib", "alpha-lib", "zeta-lib"]
    assert [row[1] for row in csv_rows[1:]] == ["Apache-2.0", "MIT", "MIT"]
    assert [row[2] for row in csv_rows[1:]] == ["Apache-2.0", "MIT", "MIT"]
    assert all(not row[0].startswith("##") for row in csv_rows[1:])


def test_presentation_markdown_groups_by_exact_spdx_and_states_data_limits() -> None:
    rows = presentation_rows_from_disclosure(
        (
            _row(name="mit-lib", spdx_id="MIT", descriptions=("Brief package summary",)),
            _row(name="apache-lib", spdx_id="Apache-2.0"),
            _row(name="mit-expression-lib", spdx_id="MIT OR Apache-2.0"),
        )
    )

    markdown = render_presentation_markdown(rows)

    assert DATA_LIMITATION_NOTE in markdown
    assert "## Apache-2.0 (1)" in markdown
    assert "## MIT (1)" in markdown
    assert "## MIT OR Apache-2.0 (1)" in markdown
    assert markdown.index("## Apache-2.0 (1)") < markdown.index("## MIT (1)")
    assert "Brief package summary" in markdown
    assert " n/a " in markdown
    assert "found_id" not in markdown


def test_presentation_uses_approved_review_decision_and_preserves_detected_spdx() -> None:
    disclosure_row = _row(spdx_id="MIT OR Apache-2.0")
    rows = presentation_rows_from_disclosure(
        (disclosure_row,),
        review_state={
            review_id_for_row(disclosure_row): ReviewDecision(
                review_id=review_id_for_row(disclosure_row),
                selected_spdx="MIT",
                review_note="Using permissive branch.",
            )
        },
    )

    csv_rows = list(csv.DictReader(io.StringIO(render_presentation_csv(rows))))
    markdown = render_presentation_markdown(rows)
    html = render_presentation_html(rows)
    docx_xml = _document_xml(render_presentation_docx(_header(), rows))

    assert csv_rows[0]["disclosure license (spdx)"] == "MIT"
    assert csv_rows[0]["detected license (spdx)"] == "MIT OR Apache-2.0"
    assert csv_rows[0]["notes"] == "Using permissive branch."
    assert "## MIT (1)" in markdown
    assert "MIT OR Apache-2.0" in markdown
    assert "Using permissive branch." in markdown
    assert "<summary>MIT (1)</summary>" in html
    assert "MIT OR Apache-2.0" in html
    assert b"MIT OR Apache-2.0" in docx_xml
    assert b"Using permissive branch." in docx_xml


def test_presentation_html_uses_grouped_tables_and_neutralizes_unsafe_urls() -> None:
    rows = presentation_rows_from_disclosure(
        (
            _row(name="acme <html>", source_urls=("javascript:alert(1)",)),
            _row(name="safe", spdx_id="Apache-2.0"),
        )
    )

    html = render_presentation_html(rows)

    assert "@page { size: letter landscape;" in html
    assert '<details class="license-group" open>' in html
    assert "<summary>Apache-2.0 (1)</summary>" in html
    assert "<summary>MIT (1)</summary>" in html
    assert "acme &lt;html&gt;" in html
    assert "javascript:" not in html
    assert "javascript&#58;alert(1)" in html
    assert 'href="javascript' not in html


def test_presentation_artifacts_accept_reviewed_title_and_preamble() -> None:
    rows = presentation_rows_from_disclosure((_row(),))

    markdown = render_presentation_markdown(
        rows,
        title="Acme Notices",
        preamble="Prepared for review.\nVerify before publishing.",
    )
    html = render_presentation_html(rows, title="Acme Notices", preamble="Prepared for review.")
    docx_xml = _document_xml(
        render_presentation_docx(
            _header(),
            rows,
            title="Acme Notices",
            preface="Prepared for review.",
        )
    )

    assert "# Acme Notices" in markdown
    assert "> Prepared for review.\n> Verify before publishing." in markdown
    assert "<title>Acme Notices</title>" in html
    assert "<h1>Acme Notices</h1>" in html
    assert "Prepared for review." in html
    assert b"Acme Notices" in docx_xml
    assert b"Prepared for review." in docx_xml


def test_presentation_markdown_and_html_preserve_semicolon_source_urls() -> None:
    url = "https://example.invalid/license?one=1;two=2"
    rows = presentation_rows_from_disclosure((_row(source_urls=(url,)),))

    markdown = render_presentation_markdown(rows)
    html = render_presentation_html(rows)

    assert f"[{url}]({url})" in markdown
    assert "[two=2](two=2)" not in markdown
    assert f'href="{url}"' in html
    assert ">two=2</a>" not in html


def test_presentation_csv_neutralizes_formula_fields() -> None:
    rows = presentation_rows_from_disclosure((_row(name="=formula", versions=("+1",)),))

    data = render_presentation_csv(rows)

    assert '"\t=formula"' in data
    assert '"\t+1"' in data


def test_presentation_docx_groups_rows_escapes_text_and_redacts_tokens() -> None:
    token = "ghp_" + "A" * 24
    rows = presentation_rows_from_disclosure(
        (
            _row(name=f"acme <xml> {token}", source_urls=("https://example.invalid/?x=<bad>",)),
            _row(name="apache-lib", spdx_id="Apache-2.0"),
        )
    )

    payload = render_presentation_docx(_header(), rows)
    xml = _document_xml(payload)

    ElementTree.fromstring(xml)
    assert b"RepoLens Presentation Report" in xml
    assert b"Apache-2.0 (1)" in xml
    assert b"MIT (1)" in xml
    assert b"acme &lt;xml&gt;" in xml
    assert token.encode("utf-8") not in xml
    assert b"[REDACTED_TOKEN]" in xml


def test_render_main_report_writes_header_gated_presentation_artifacts(
    tmp_path: Path, resolved_record: dict[str, object]
) -> None:
    store.write_resolved(tmp_path, "acme-alpha", [resolved_record])

    with_header = render_main_report(tmp_path, tmp_path / "with", _report_config())
    without_header = render_main_report(tmp_path, tmp_path / "without", _no_header_config())

    assert with_header.presentation_markdown_path == tmp_path / "with" / "report.presentation.md"
    assert with_header.presentation_csv_path == tmp_path / "with" / "report.presentation.csv"
    assert with_header.presentation_html_path == tmp_path / "with" / "report.presentation.html"
    assert with_header.presentation_docx_path == tmp_path / "with" / "report.presentation.docx"
    assert with_header.presentation_docx_path.exists()
    assert without_header.presentation_markdown_path is not None
    assert without_header.presentation_markdown_path.exists()
    assert without_header.presentation_docx_path is None
    assert without_header.presentation_docx_skipped is True
    assert not (tmp_path / "without" / "report.presentation.docx").exists()


def _row(
    *,
    name: str = "acme-lib",
    spdx_id: str = "MIT",
    versions: tuple[str, ...] = ("1.0.0",),
    source_urls: tuple[str, ...] = ("https://example.invalid/license",),
    descriptions: tuple[str, ...] = (),
) -> DisclosureRow:
    return DisclosureRow(
        name=name,
        spdx_id=spdx_id,
        versions=versions,
        source_urls=source_urls,
        modified=("unknown",),
        origins=("third-party-oss",),
        scopes=("runtime",),
        distributions=("server",),
        found_in=("acme-alpha",),
        evidence_source_layers=("syft",),
        coverage_gaps=(),
        descriptions=descriptions,
    )


def _header() -> ReportHeader:
    return ReportHeader(org_name="Example Org", legal_text="Example legal")


def _document_xml(payload: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return archive.read("word/document.xml")


def _report_config() -> Config:
    return Config(
        values={"report": {"header": {"org_name": "Example Org", "legal_text": "Legal"}}},
        sources=(),
    )


def _no_header_config() -> Config:
    return Config(values={"report": {}}, sources=())
