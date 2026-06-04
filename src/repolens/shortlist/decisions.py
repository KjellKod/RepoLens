"""Parse human checkbox decisions from ``shortlist.md`` and merge them into items.

The canonical state of record is ``shortlist.json``; ``shortlist.md`` is the editable human
view. A human ticks an item's checkbox (``[x]`` approve, ``[r]`` reject) and re-runs
``shortlist``; this module recovers each decision keyed by the stable ``rpl:ref`` line
marker that :mod:`repolens.shortlist.render` emits, then :func:`apply_decisions` records
``status`` / ``decided_by`` / ``decided_at`` on the matching item.

Recovery is conservative (Risk 5): a line whose key is missing or malformed yields no
decision (the item stays in its prior state), so a garbled edit can never silently flip an
approval. The key is read from the sanitized HTML-comment marker, never from the human-facing
label, so the round-trip survives ``sanitize_markdown`` (finding arb-it1-3).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from repolens.shortlist.grouping import GroupKey, GroupMembership, decode_group_key
from repolens.shortlist.render import decode_component_ref

# ``sanitize_markdown`` escapes the comment delimiters, so the rendered marker is
# ``&lt;!-- rpl:ref=ENCODED --&gt;``. Match that escaped form; the base64url alphabet
# (A-Z a-z 0-9 - _) passes through both sanitize_markdown and render_code_span untouched.
_REF_MARKER_RE = re.compile(r"&lt;!-- rpl:ref=([A-Za-z0-9_-]+) --&gt;")
_GROUP_MARKER_RE = re.compile(r"&lt;!-- rpl:group=([A-Za-z0-9_-]+) --&gt;")
# A checkbox at the start of a list item: ``- [x] …`` / ``- [r] …`` / ``- [ ] …``.
# ``sanitize_markdown`` does not alter the leading ``- [ ]`` token.
_CHECKBOX_RE = re.compile(r"^\s*[-*]\s*\[(?P<mark>[^\]])\]")

_APPROVE_MARKS = frozenset({"x", "X"})
_REJECT_MARKS = frozenset({"r", "R"})


@dataclass(frozen=True, slots=True)
class Decision:
    """A recovered human decision for one component."""

    component_ref: str
    status: str  # "approved" | "rejected"


@dataclass(frozen=True, slots=True)
class GroupDecision:
    """A recovered human decision for one rendered group."""

    key: GroupKey
    status: str  # "approved" | "rejected"


@dataclass(frozen=True, slots=True)
class ReviewDecisions:
    """All human decisions recovered from the rendered shortlist view."""

    item_decisions: dict[str, Decision] = field(default_factory=dict)
    group_decisions: dict[GroupKey, GroupDecision] = field(default_factory=dict)


def parse_checkbox_decisions(markdown: str) -> dict[str, Decision]:
    """Recover ``{component_ref: Decision}`` from a rendered ``shortlist.md`` string.

    Only ticked (``[x]``) or rejected (``[r]``) lines with a recoverable ``rpl:ref`` key
    produce a decision; unchecked (``[ ]``) lines and lines without a valid key are skipped.
    The last decision for a given ``component_ref`` wins (deterministic on duplicates).
    """

    return parse_review_decisions(markdown).item_decisions


def parse_review_decisions(markdown: str) -> ReviewDecisions:
    """Recover item and group decisions from a rendered ``shortlist.md`` string."""

    item_decisions: dict[str, Decision] = {}
    group_decisions: dict[GroupKey, GroupDecision] = {}
    for line in markdown.splitlines():
        checkbox = _CHECKBOX_RE.match(line)
        if checkbox is None:
            continue
        mark = checkbox.group("mark")
        if mark in _APPROVE_MARKS:
            status = "approved"
        elif mark in _REJECT_MARKS:
            status = "rejected"
        else:
            continue  # unchecked or unknown mark -> no decision
        marker = _REF_MARKER_RE.search(line)
        if marker is not None:
            component_ref = decode_component_ref(marker.group(1))
            if component_ref is None:
                continue
            item_decisions[component_ref] = Decision(component_ref=component_ref, status=status)
            continue
        group_marker = _GROUP_MARKER_RE.search(line)
        if group_marker is None:
            continue
        group_key = decode_group_key(group_marker.group(1))
        if group_key is None:
            continue
        group_decisions[group_key] = GroupDecision(key=group_key, status=status)
    return ReviewDecisions(item_decisions=item_decisions, group_decisions=group_decisions)


def apply_decisions(
    items: Sequence[Mapping[str, Any]],
    decisions: Mapping[str, Decision],
    *,
    identity: str | None,
    now: str,
    group_decisions: Mapping[GroupKey, GroupDecision] | None = None,
    group_membership: Mapping[str, GroupMembership] | None = None,
) -> list[dict[str, Any]]:
    """Return a new item list with human decisions recorded on matching ``open`` items.

    A decision only takes effect on an item that is still ``open`` (a settled item is never
    silently re-flipped). ``decided_by`` comes from the runtime ``identity`` input (never an
    owner/repo literal — plan A2); ``decided_at`` is the caller-supplied UTC timestamp.
    """

    updated: list[dict[str, Any]] = []
    groups = group_decisions or {}
    memberships = group_membership or {}
    for item in items:
        record = dict(item)
        component_ref = str(record.get("component_ref"))
        decision = decisions.get(component_ref)
        decided_via = "item"
        membership = memberships.get(component_ref)
        if decision is None and membership is not None:
            decision = groups.get(membership.key)
            decided_via = "group"
        if decision is not None and record.get("status") == "open":
            record["status"] = decision.status
            record["decided_by"] = identity
            record["decided_at"] = now
            record["decided_via"] = decided_via
            if decided_via == "group" and membership is not None:
                record["decision_provenance"] = {
                    "component_refs": list(membership.component_refs),
                    "found_in": list(membership.found_in),
                    "group": {
                        "spdx_family": membership.key.spdx_family,
                        "distribution": membership.key.distribution,
                        "scope": membership.key.scope,
                    },
                }
            else:
                record.pop("decision_provenance", None)
        updated.append(record)
    return updated


__all__ = [
    "Decision",
    "GroupDecision",
    "ReviewDecisions",
    "apply_decisions",
    "parse_checkbox_decisions",
    "parse_review_decisions",
]
