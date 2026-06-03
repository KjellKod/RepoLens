"""Shortlist gate for report assembly."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from repolens.data import store
from repolens.data.limits import max_bytes_for
from repolens.exit_codes import InputError


@dataclass(frozen=True)
class GateStatus:
    """Result of evaluating whether report assembly may proceed."""

    clear: bool
    message: str


class ReportGateOpen(Exception):
    """Raised when report assembly is blocked by open shortlist items."""


def run_report_gate(work_root: Path) -> GateStatus:
    """Return open when an existing shortlist still has unresolved items."""

    shortlist_path = Path(work_root) / "shortlist.json"
    if not shortlist_path.exists():
        return GateStatus(clear=True, message="shortlist gate clear: no shortlist.json")

    raw = store.load_json_capped(shortlist_path, max_bytes=max_bytes_for("shortlist"))
    if not isinstance(raw, dict):
        raise InputError("shortlist.json must be an object")

    open_count = raw.get("open_count", 0)
    if not isinstance(open_count, int):
        raise InputError("shortlist.open_count must be an integer")

    raw_items = raw.get("items", [])
    if not isinstance(raw_items, list):
        raise InputError("shortlist.items must be an array")

    has_open_item = any(
        isinstance(item, dict) and item.get("status") == "open" for item in raw_items
    )
    if open_count > 0 or has_open_item:
        return GateStatus(
            clear=False,
            message="FINDINGS_OPEN: report requires a clear shortlist before assembly",
        )
    return GateStatus(clear=True, message="shortlist gate clear")
