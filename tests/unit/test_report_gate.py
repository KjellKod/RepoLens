from __future__ import annotations

from pathlib import Path

from repolens.data import store
from repolens.report.gate import run_report_gate


def test_report_gate_allows_missing_shortlist(tmp_path: Path) -> None:
    status = run_report_gate(tmp_path)

    assert status.clear is True


def test_report_gate_blocks_open_count(tmp_path: Path) -> None:
    _write_shortlist(tmp_path, open_count=1, statuses=("open",))

    status = run_report_gate(tmp_path)

    assert status.clear is False
    assert "FINDINGS_OPEN" in status.message


def test_report_gate_blocks_any_open_item(tmp_path: Path) -> None:
    store.atomic_write_json(
        tmp_path / "shortlist.json",
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 0,
            "items": [{"status": "open"}],
        },
    )

    status = run_report_gate(tmp_path)

    assert status.clear is False


def test_report_gate_allows_clear_shortlist(tmp_path: Path) -> None:
    _write_shortlist(tmp_path, open_count=0, statuses=("approved", "rejected"))

    status = run_report_gate(tmp_path)

    assert status.clear is True


def _write_shortlist(tmp_path: Path, *, open_count: int, statuses: tuple[str, ...]) -> None:
    store.atomic_write_json(
        tmp_path / "shortlist.json",
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": open_count,
            "items": [{"status": status} for status in statuses],
        },
    )
