"""Runtime report selection and header config parsing."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from repolens.config import Config
from repolens.exit_codes import InputError


@dataclass(frozen=True)
class ReportSelection:
    """Category-selection settings for report assembly."""

    include: tuple[str, ...] | None


@dataclass(frozen=True)
class ReportHeader:
    """Runtime-only header text for docx report rendering."""

    org_name: str
    legal_text: str


def report_selection_from_config(config: Config | None) -> ReportSelection:
    """Load ``report.selection`` from runtime config."""

    report = _report_config(config)
    raw_selection = report.get("selection", {})
    if raw_selection is None:
        raw_selection = {}
    if not isinstance(raw_selection, Mapping):
        raise InputError("config report.selection must be an object")

    raw_include = raw_selection.get("include")
    if raw_include is None:
        return ReportSelection(include=None)
    if not isinstance(raw_include, list):
        raise InputError("config report.selection.include must be an array")

    include: list[str] = []
    for index, item in enumerate(raw_include):
        if not isinstance(item, str) or not item.strip():
            raise InputError(f"config report.selection.include[{index}] must be a non-empty string")
        include.append(item.strip())
    return ReportSelection(include=tuple(include))


def report_header_from_config(config: Config | None) -> ReportHeader:
    """Load required runtime docx header text from ``report.header``."""

    report = _report_config(config)
    raw_header = report.get("header")
    if not isinstance(raw_header, Mapping):
        raise InputError("config report.header must be an object")
    return ReportHeader(
        org_name=_required_text(raw_header.get("org_name"), "report.header.org_name"),
        legal_text=_required_text(raw_header.get("legal_text"), "report.header.legal_text"),
    )


def _report_config(config: Config | None) -> Mapping[str, object]:
    values = {} if config is None else config.values
    raw_report = values.get("report", {})
    if raw_report is None:
        raw_report = {}
    if not isinstance(raw_report, Mapping):
        raise InputError("config report must be an object")
    return raw_report


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"config {label} must be a non-empty string")
    return value.strip()
