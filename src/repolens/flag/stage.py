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
from repolens.data.errors import CorruptArtifactError, LimitExceeded, SchemaValidationError
from repolens.data.limits import SCHEMA_VERSION
from repolens.flag.dedup import CollectedRecord, GroupOutcome, build_group_outcomes
from repolens.policy import PolicyTier, load_default_policy
from repolens.security.redaction import redact_tokens
from repolens.shortlist.contexts import ShortlistMetadata, load_shortlist_metadata
from repolens.shortlist.decisions import apply_decisions, parse_review_decisions
from repolens.shortlist.grouping import build_groups, group_membership_by_ref
from repolens.shortlist.render import render_shortlist_markdown

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
    preserved_decision_count: int = 0


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

    previous_decisions = _load_previous_decisions(root, now=generated_at)
    items = [_shortlist_item(outcome) for outcome in outcomes if _is_flagged(outcome)]
    items = [_carry_forward_decision(item, previous_decisions) for item in items]
    preserved_decision_count = sum(
        1
        for item in items
        if item.get("status") in {"approved", "rejected"}
        and str(item.get("component_ref")) in previous_decisions
    )
    open_count = sum(1 for item in items if item["status"] == "open")
    shortlist_doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "open_count": open_count,
        "items": items,
    }

    inventory_path = store.write_inventory(root, inventory_doc)
    shortlist_json_path = store.write_shortlist(root, shortlist_doc)

    metadata = _load_existing_metadata(root)
    markdown = redact_tokens(render_shortlist_markdown(items, metadata=metadata))
    shortlist_md_path = root / "shortlist.md"
    store.atomic_write_bytes(shortlist_md_path, markdown.encode("utf-8"))

    return FlagResult(
        inventory_path=inventory_path,
        shortlist_json_path=shortlist_json_path,
        shortlist_md_path=shortlist_md_path,
        open_count=open_count,
        component_count=len(outcomes),
        preserved_decision_count=preserved_decision_count,
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
    # A disclosure should never ask a maintainer to review their own code: the
    # repo's own workspace members are unpublished, so they can never resolve a
    # registry license and would otherwise sit in the open shortlist as UNKNOWN
    # noise. Drop them exactly as build/not-distributed CI items are dropped;
    # report routing still files them under the first-party appendix.
    if outcome.component.origin == "first-party":
        return False
    if outcome.component.scope == "build" and outcome.component.distribution == "not-distributed":
        return False
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


_DECISION_FIELDS = (
    "status",
    "decided_by",
    "decided_at",
    "decided_via",
    "decision_provenance",
)


def _load_previous_decisions(root: Path, *, now: str) -> dict[str, dict[str, Any]]:
    previous_path = root / "shortlist.json"
    if not previous_path.exists():
        return {}
    previous = store.read_shortlist(root)
    raw_items = previous.get("items")
    if not isinstance(raw_items, list):
        return {}

    items = [dict(item) for item in raw_items if isinstance(item, dict)]
    items = _apply_pending_markdown_decisions(root, items, now=now)
    return {
        str(item["component_ref"]): item
        for item in items
        if item.get("status") in {"approved", "rejected"} and item.get("component_ref")
    }


def _apply_pending_markdown_decisions(
    root: Path,
    items: list[dict[str, Any]],
    *,
    now: str,
) -> list[dict[str, Any]]:
    markdown_path = root / "shortlist.md"
    if not markdown_path.exists():
        return items
    markdown = markdown_path.read_text(encoding="utf-8")
    decisions = parse_review_decisions(markdown)
    if not decisions.item_decisions and not decisions.group_decisions:
        return items
    metadata = _load_existing_metadata(root)
    return apply_decisions(
        items,
        decisions.item_decisions,
        identity=None,
        now=now,
        group_decisions=decisions.group_decisions,
        group_membership=group_membership_by_ref(build_groups(items, metadata)),
    )


def _load_existing_metadata(root: Path) -> ShortlistMetadata:
    try:
        return load_shortlist_metadata(root)
    except (CorruptArtifactError, LimitExceeded, SchemaValidationError, OSError):
        return ShortlistMetadata(triage_by_ref={})


def _carry_forward_decision(
    item: dict[str, Any],
    previous_decisions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    previous = previous_decisions.get(str(item.get("component_ref")))
    if previous is None:
        return item
    carried = dict(item)
    for field in _DECISION_FIELDS:
        if field in previous:
            carried[field] = previous[field]
    if previous.get("status") in {"approved", "rejected"}:
        carried["note"] = previous.get("note") or carried.get("note")
    return carried


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _path_sort_key(path: Path) -> tuple[str, str]:
    text = path.as_posix()
    return (text.casefold(), text)


__all__: Sequence[str] = ("FlagResult", "run_flag")
