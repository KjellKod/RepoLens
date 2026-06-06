"""Report rendering entry points."""

from repolens.report.gate import ReportGateOpen
from repolens.report.main import (
    COLUMNS,
    DEFAULT_LEGAL_TEXT,
    DOCX_SKIPPED_NOTICE,
    DisclosureRow,
    ReportAppendixSummary,
    ReportResult,
    aggregate_rows,
    collect_resolved_records,
    render_csv,
    render_html,
    render_main_report,
    render_markdown,
)
from repolens.report.selection import (
    ReportHeader,
    ReportSelection,
    report_header_if_configured,
)

__all__ = [
    "COLUMNS",
    "DEFAULT_LEGAL_TEXT",
    "DOCX_SKIPPED_NOTICE",
    "DisclosureRow",
    "ReportGateOpen",
    "ReportHeader",
    "ReportAppendixSummary",
    "ReportResult",
    "ReportSelection",
    "aggregate_rows",
    "collect_resolved_records",
    "render_csv",
    "render_html",
    "render_main_report",
    "render_markdown",
    "report_header_if_configured",
]
