from __future__ import annotations

from repolens.shortlist.decisions import apply_decisions, parse_checkbox_decisions
from repolens.shortlist.render import encode_component_ref, render_shortlist_markdown


def _tick(markdown: str, component_ref: str, mark: str) -> str:
    """Tick the rendered line carrying ``component_ref`` with ``mark`` (e.g. 'x' or 'r')."""

    key = f"rpl:ref={encode_component_ref(component_ref)}"
    out = []
    for line in markdown.splitlines():
        if key in line and "- [ ] " in line:
            line = line.replace("- [ ] ", f"- [{mark}] ", 1)
        out.append(line)
    return "\n".join(out) + "\n"


def _items() -> list[dict[str, object]]:
    return [
        {
            "component_ref": "acme-lib|MIT",
            "reason": "REVIEW",
            "evidence": {"source_layer": "agent", "url": "https://api.deps.dev/x", "anchor": "MIT"},
            "candidate_spdx": "MIT",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": "agent:verified_awaiting_human",
        },
        {
            "component_ref": "acme-tool|GPL-3.0-only",
            "reason": "BLOCK",
            "evidence": {"source_layer": "api", "anchor": "GPL-3.0-only"},
            "candidate_spdx": "GPL-3.0-only",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": None,
        },
    ]


def test_round_trip_recovers_component_ref_through_sanitize() -> None:
    # The key must survive the full render -> sanitize_markdown pipeline (finding arb-it1-3).
    markdown = render_shortlist_markdown(_items())
    # Simulate a human ticking the acme-lib item's checkbox in the *rendered* markdown.
    ticked = _tick(markdown, "acme-lib|MIT", "x")

    decisions = parse_checkbox_decisions(ticked)

    assert "acme-lib|MIT" in decisions
    assert decisions["acme-lib|MIT"].status == "approved"
    assert "acme-tool|GPL-3.0-only" not in decisions  # left unchecked


def test_reject_mark_recovered() -> None:
    markdown = render_shortlist_markdown(_items())
    rejected = _tick(markdown, "acme-lib|MIT", "r")

    decisions = parse_checkbox_decisions(rejected)

    assert decisions["acme-lib|MIT"].status == "rejected"


def test_garbled_key_yields_no_decision() -> None:
    markdown = render_shortlist_markdown(_items())
    ticked = _tick(markdown, "acme-lib|MIT", "x")
    # Corrupt the embedded ref marker on the ticked line.
    corrupted = ticked.replace("rpl:ref=", "rpl:ref=!!!")

    decisions = parse_checkbox_decisions(corrupted)

    # Conservative recovery: a garbled key never silently flips an approval (Risk 5).
    assert decisions == {}


def test_apply_decisions_records_decided_fields_only_on_open_items() -> None:
    items = _items()
    decisions = parse_checkbox_decisions(
        _tick(render_shortlist_markdown(items), "acme-lib|MIT", "x")
    )

    updated = apply_decisions(
        items, decisions, identity="reviewer-sentinel", now="2026-06-02T00:00:00Z"
    )

    approved = next(item for item in updated if item["component_ref"] == "acme-lib|MIT")
    assert approved["status"] == "approved"
    assert approved["decided_by"] == "reviewer-sentinel"
    assert approved["decided_at"] == "2026-06-02T00:00:00Z"
    untouched = next(item for item in updated if item["component_ref"] == "acme-tool|GPL-3.0-only")
    assert untouched["status"] == "open"
    assert untouched["decided_by"] is None
