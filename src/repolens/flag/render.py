"""Render ``shortlist.md`` — the human-readable BLOCK / REVIEW / UNKNOWN queue view.

Untrusted text (component refs, evidence URLs/anchors) is made markdown-inert here via
``render_code_span``/``markdown_link`` and a final ``sanitize_markdown`` pass, mirroring
``report.render_markdown``. Token redaction is applied by the caller before the byte write.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from repolens.security.sanitize import markdown_link, render_code_span, sanitize_markdown

# Section order matches the shortlist ``reason`` enum values the flag stage emits.
_QUEUES = ("BLOCK", "REVIEW", "UNKNOWN")
_NO_EVIDENCE_URL = "no evidence url"


def render_shortlist_markdown(items: Sequence[Mapping[str, Any]]) -> str:
    """Render the shortlist items as a sanitized two-queue + unknown markdown document."""

    by_reason: dict[str, list[Mapping[str, Any]]] = {queue: [] for queue in _QUEUES}
    for item in items:
        reason = str(item["reason"])
        by_reason.setdefault(reason, []).append(item)

    lines = ["# RepoLens Shortlist", ""]
    for queue in _QUEUES:
        lines.append(f"## {queue}")
        lines.append("")
        queue_items = by_reason.get(queue, [])
        if not queue_items:
            lines.append("_none_")
        else:
            lines.extend(_render_item(item) for item in queue_items)
        lines.append("")

    return sanitize_markdown("\n".join(lines).rstrip() + "\n")


def _render_item(item: Mapping[str, Any]) -> str:
    component_ref = render_code_span(item["component_ref"])
    note = item.get("note") or str(item["reason"])
    evidence = item["evidence"] if isinstance(item.get("evidence"), Mapping) else {}
    return f"- {component_ref} — {note} — {_evidence_cell(evidence)}"


def _evidence_cell(evidence: Mapping[str, Any]) -> str:
    url = evidence.get("url")
    if url:
        return markdown_link(str(url), str(url))
    anchor = evidence.get("anchor")
    if anchor:
        return render_code_span(anchor)
    return _NO_EVIDENCE_URL
