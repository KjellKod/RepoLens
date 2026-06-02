"""Flag stage orchestration: collect resolved records, tag, classify, dedup, emit artifacts.

This is the home for the P4 ``flag`` stage. It owns its **own** resolved-record collector
(reusing only ``store.iter_resolved`` per file) and must **not** call
``report.collect_resolved_records``, which raises on an absent/empty ``work/`` — flag treats
both a missing and an empty ``work/`` as "no records -> empty artifacts -> exit 0" (plan S5).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.data.limits import SCHEMA_VERSION
from repolens.flag.dedup import CollectedRecord, GroupOutcome, build_group_outcomes
from repolens.flag.render import render_shortlist_markdown
from repolens.policy import PolicyTier, load_default_policy
from repolens.security.redaction import redact_tokens

# Tiers that need a human decision land in the shortlist; ALLOW groups produce no item.
_FLAG_TIERS = frozenset({PolicyTier.BLOCK, PolicyTier.REVIEW, PolicyTier.UNKNOWN})


@dataclass(frozen=True)
class FlagResult:
    """Paths and summary for the emitted flag artifacts."""

    inventory_path: Path
    shortlist_json_path: Path
    shortlist_md_path: Path
    open_count: int
    component_count: int


def run_flag(work_root: Path) -> FlagResult:
    """Build ``inventory.json`` + ``shortlist.json`` + ``shortlist.md`` from resolved records."""

    root = Path(work_root)
    records = _collect_resolved_records(root)
    policy = load_default_policy()
    outcomes = build_group_outcomes(records, policy)

    generated_at = _utc_now()
    inventory_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "components": [outcome.component.to_dict() for outcome in outcomes],
    }

    items = [_shortlist_item(outcome) for outcome in outcomes if _is_flagged(outcome)]
    open_count = sum(1 for item in items if item["status"] == "open")
    shortlist_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "open_count": open_count,
        "items": items,
    }

    inventory_path = store.write_inventory(root, inventory_doc)
    shortlist_json_path = store.write_shortlist(root, shortlist_doc)

    markdown = redact_tokens(render_shortlist_markdown(items))
    shortlist_md_path = root / "shortlist.md"
    store.atomic_write_bytes(shortlist_md_path, markdown.encode("utf-8"))

    return FlagResult(
        inventory_path=inventory_path,
        shortlist_json_path=shortlist_json_path,
        shortlist_md_path=shortlist_md_path,
        open_count=open_count,
        component_count=len(outcomes),
    )


def _collect_resolved_records(work_root: Path) -> list[CollectedRecord]:
    """Collect records from ``work/*/resolved.ndjson`` using flag's own collector.

    A missing ``work/`` directory or one with no ``resolved.ndjson`` files yields ``[]`` —
    flag writes valid empty artifacts and exits 0 instead of raising (plan AC10/S5).
    """

    work_dir = work_root / "work"
    if not work_dir.is_dir():
        return []

    records: list[CollectedRecord] = []
    for repo_dir in sorted(
        (path for path in work_dir.iterdir() if path.is_dir()), key=_path_sort_key
    ):
        resolved_path = repo_dir / "resolved.ndjson"
        if not resolved_path.exists():
            continue
        for ordinal, record in enumerate(store.iter_resolved(resolved_path), start=1):
            records.append(CollectedRecord(data=record, repo_dir=repo_dir.name, ordinal=ordinal))
    return records


def _is_flagged(outcome: GroupOutcome) -> bool:
    return outcome.decision.tier in _FLAG_TIERS


def _shortlist_item(outcome: GroupOutcome) -> dict[str, Any]:
    return {
        "component_ref": outcome.component_ref,
        "reason": outcome.decision.tier.value,
        "evidence": outcome.evidence,
        "candidate_spdx": outcome.candidate_spdx,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": outcome.reason_note,
    }


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _path_sort_key(path: Path) -> tuple[str, str]:
    text = path.as_posix()
    return (text.casefold(), text)


__all__: Sequence[str] = ("FlagResult", "run_flag")
