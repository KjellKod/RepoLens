"""Render the human-facing ``shortlist.md`` with approval checkboxes and decided state.

This is a stage-specific *view* of the shortlist. It does not fork the sanitization concern:
component refs and evidence are made markdown-inert through the shared sanitizers
(:mod:`repolens.security.sanitize`), exactly as ``flag/render.py`` does. The flag renderer
stays behavior-stable (it still emits the plain BLOCK/REVIEW/UNKNOWN bullets); P5 adds the
checkbox/decided view here rather than complicating the flag call site (plan A3, second arm).

Round-trip key recovery (plan-review finding arb-it1-3): each item line carries a stable,
machine-parseable key embedded as an HTML comment with a base64url-encoded ``component_ref``.
The key is recovered by :func:`repolens.shortlist.decisions.parse_checkbox_decisions` *after*
``sanitize_markdown`` has escaped the comment delimiters, so the human-facing label is never
re-parsed. The key alphabet (base64url) survives both ``sanitize_markdown`` and
``render_code_span`` untouched.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from typing import Any

from repolens.security.sanitize import markdown_link, render_code_span, sanitize_markdown
from repolens.shortlist.contexts import ShortlistMetadata
from repolens.shortlist.grouping import (
    LOW_CONFIDENCE,
    TIER_ORDER,
    ShortlistGroup,
    build_groups,
    encode_group_key,
)

_NO_EVIDENCE_URL = "no evidence url"

#: Stable line-key markers. ``REF_PREFIX``/``REF_SUFFIX`` survive ``sanitize_markdown`` as
#: ``&lt;!-- … --&gt;`` (the ``<``/``>`` are escaped) — the decisions parser matches the
#: escaped form, so the encoded ``component_ref`` round-trips losslessly.
REF_PREFIX = "<!-- rpl:ref="
REF_SUFFIX = " -->"
GROUP_PREFIX = "<!-- rpl:group="
GROUP_SUFFIX = " -->"


def encode_component_ref(component_ref: str) -> str:
    """Encode a ``component_ref`` into a base64url line key (no padding, ascii-safe)."""

    raw = component_ref.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_component_ref(encoded: str) -> str | None:
    """Decode a base64url line key back to its ``component_ref``; ``None`` if malformed."""

    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def render_shortlist_markdown(
    items: Sequence[Mapping[str, Any]],
    *,
    metadata: ShortlistMetadata | None = None,
) -> str:
    """Render shortlist items as a sanitized grouped checkbox/decided Markdown view."""

    resolved_metadata = metadata or ShortlistMetadata(triage_by_ref={})
    groups = build_groups(items, resolved_metadata)
    by_tier: dict[str, list[ShortlistGroup]] = {tier: [] for tier in TIER_ORDER}
    for group in groups:
        by_tier.setdefault(group.tier, []).append(group)

    lines = [
        "# RepoLens Shortlist",
        "",
        "Tick an available group checkbox or an item checkbox to approve it, or write `[r]` "
        "to reject it, then re-run `repolens shortlist`. Item decisions override group "
        "decisions. Do not edit the `rpl:group` or `rpl:ref` markers.",
        "",
    ]
    for tier in TIER_ORDER:
        lines.append(f"## {tier}")
        lines.append("")
        tier_groups = by_tier.get(tier, [])
        if not tier_groups:
            lines.append("_none_")
        else:
            for group in tier_groups:
                lines.extend(_render_group(group))
                lines.append("")
        lines.append("")

    return sanitize_markdown("\n".join(lines).rstrip() + "\n")


def _render_group(group: ShortlistGroup) -> list[str]:
    label = (
        f"{group.key.spdx_family} / {group.key.distribution} / {group.key.scope} "
        f"({len(group.items)} item{'s' if len(group.items) != 1 else ''})"
    )
    found_in = ", ".join(group.found_in[:5]) if group.found_in else "unknown repo"
    if len(group.found_in) > 5:
        found_in = f"{found_in}, ..."
    marker = f"{GROUP_PREFIX}{encode_group_key(group.key)}{GROUP_SUFFIX}"
    lines: list[str] = []
    has_group_decision = group.tier != LOW_CONFIDENCE
    if has_group_decision:
        lines.append(f"- [ ] **{label}** — found in {render_code_span(found_in)} {marker}")
    else:
        lines.append(f"### {label} — found in {render_code_span(found_in)}")
    indent = "  " if has_group_decision else ""
    lines.extend(_render_item(item, indent=indent) for item in group.items)
    return lines


def _render_item(item: Mapping[str, Any], *, indent: str = "") -> str:
    component_ref = str(item["component_ref"])
    label = render_code_span(component_ref)
    note = item.get("note") or str(item["reason"])
    evidence = item["evidence"] if isinstance(item.get("evidence"), Mapping) else {}
    key = f"{REF_PREFIX}{encode_component_ref(component_ref)}{REF_SUFFIX}"
    status = str(item.get("status") or "open")
    checkbox = _checkbox_for_status(status)
    decided = _decided_suffix(item)
    return f"{indent}- {checkbox} {label} — {note} — {_evidence_cell(evidence)}{decided} {key}"


def _checkbox_for_status(status: str) -> str:
    if status == "approved":
        return "[x]"
    if status == "rejected":
        return "[r]"
    return "[ ]"


def _decided_suffix(item: Mapping[str, Any]) -> str:
    decided_by = item.get("decided_by")
    decided_at = item.get("decided_at")
    if not decided_by and not decided_at:
        return ""
    parts = [str(item.get("status") or "open")]
    if decided_by:
        parts.append(f"by {render_code_span(str(decided_by))}")
    if decided_at:
        parts.append(f"at {render_code_span(str(decided_at))}")
    return " — " + " ".join(parts)


def _evidence_cell(evidence: Mapping[str, Any]) -> str:
    url = evidence.get("url")
    if url:
        return markdown_link(str(url), str(url))
    anchor = evidence.get("anchor")
    if anchor:
        return render_code_span(anchor)
    return _NO_EVIDENCE_URL


__all__ = [
    "REF_PREFIX",
    "REF_SUFFIX",
    "GROUP_PREFIX",
    "GROUP_SUFFIX",
    "decode_component_ref",
    "encode_component_ref",
    "render_shortlist_markdown",
]
