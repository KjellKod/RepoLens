from __future__ import annotations

import pytest

from repolens.shortlist.contexts import ShortlistMetadata, TriageMetadata
from repolens.shortlist.decisions import (
    apply_decisions,
    parse_checkbox_decisions,
    parse_review_decisions,
)
from repolens.shortlist.grouping import build_groups, group_membership_by_ref
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


def _tick_first_group(markdown: str, mark: str) -> str:
    out = []
    for line in markdown.splitlines():
        if "rpl:group=" in line and "- [ ] " in line:
            line = line.replace("- [ ] ", f"- [{mark}] ", 1)
            out.append(line)
            out.extend(markdown.splitlines()[len(out) :])
            return "\n".join(out) + "\n"
        out.append(line)
    return markdown


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


def _needs_judgment_items() -> list[dict[str, object]]:
    return [
        {
            "component_ref": "acme-tool|GPL-3.0-only",
            "reason": "BLOCK",
            "evidence": {"source_layer": "api", "anchor": "GPL-3.0-only"},
            "candidate_spdx": "GPL-3.0-only",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": "agent:verified_awaiting_human",
            "ai_suggestion": {"disposition": "block", "confidence": 0.95},
        },
        {
            "component_ref": "acme-core|GPL-3.0-or-later",
            "reason": "BLOCK",
            "evidence": {"source_layer": "api", "anchor": "GPL-3.0-or-later"},
            "candidate_spdx": "GPL-3.0-or-later",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": "agent:verified_awaiting_human",
            "ai_suggestion": {"disposition": "block", "confidence": 0.95},
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


def test_empty_tiers_explain_when_they_fill() -> None:
    markdown = render_shortlist_markdown([])

    assert "this fills after RepoLens verifies low-risk allow proposals" in markdown
    assert "this fills for review/block items with enough evidence" in markdown
    assert "no unresolved, abstained, failed-verification" in markdown


def test_group_label_distinguishes_open_from_total_items() -> None:
    items = _needs_judgment_items()
    items[1] = {
        **items[1],
        "status": "approved",
        "decided_at": "2026-06-05T00:00:00Z",
    }

    markdown = render_shortlist_markdown(items, metadata=ShortlistMetadata(triage_by_ref={}))

    assert "(1 open / 2 total items)" in markdown
    assert "- [ ] `acme-tool|GPL-3.0-only`" in markdown
    assert "- [x] `acme-core|GPL-3.0-or-later`" in markdown


def test_group_header_reflects_settled_members() -> None:
    approved_items = [
        {**item, "status": "approved", "decided_at": "2026-06-05T00:00:00Z"}
        for item in _needs_judgment_items()
    ]
    rejected_items = [
        {**item, "status": "rejected", "decided_at": "2026-06-05T00:00:00Z"}
        for item in _needs_judgment_items()
    ]

    approved_markdown = render_shortlist_markdown(
        approved_items, metadata=ShortlistMetadata(triage_by_ref={})
    )
    rejected_markdown = render_shortlist_markdown(
        rejected_items, metadata=ShortlistMetadata(triage_by_ref={})
    )

    assert "- [x] **GPL-3.0 / unknown / unknown (0 open / 2 total items)**" in approved_markdown
    assert "- [r] **GPL-3.0 / unknown / unknown (0 open / 2 total items)**" in rejected_markdown


def test_item_rows_include_repo_provenance() -> None:
    item = {
        "component_ref": "zope-site|UNKNOWN",
        "reason": "UNKNOWN",
        "evidence": {
            "source_layer": "agent",
            "url": "https://pypi.org/pypi/zope-site/6.0/json",
            "anchor": "ZPL-2.1",
        },
        "candidate_spdx": "ZPL-2.1",
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": "agent:verified_awaiting_human",
    }
    metadata = ShortlistMetadata(
        triage_by_ref={
            "zope-site|UNKNOWN": TriageMetadata(
                spdx_id="UNKNOWN",
                tier="UNKNOWN",
                origin="third-party-oss",
                scope="runtime",
                distribution="server",
                evidence_url="pkg:pypi/zope-site@6.0",
                evidence_anchor="unresolved:scancode_no_target",
                found_in=("platform-sol", "web"),
            )
        }
    )

    markdown = render_shortlist_markdown([item], metadata=metadata)

    assert "`zope-site|UNKNOWN` -&gt; `ZPL-2.1` — found in `platform-sol, web`" in markdown


def test_verified_candidate_displays_correction_without_changing_ref_key() -> None:
    items = [
        {
            "component_ref": "zope-site|UNKNOWN",
            "reason": "UNKNOWN",
            "evidence": {
                "source_layer": "agent",
                "url": "https://pypi.org/pypi/zope-site/6.0/json",
                "anchor": "ZPL-2.1",
            },
            "candidate_spdx": "ZPL-2.1",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": "agent:verified_awaiting_human",
        }
    ]

    markdown = render_shortlist_markdown(items)

    assert "`zope-site|UNKNOWN` -&gt; `ZPL-2.1`" in markdown
    ticked = _tick(markdown, "zope-site|UNKNOWN", "x")
    decisions = parse_checkbox_decisions(ticked)
    assert decisions["zope-site|UNKNOWN"].status == "approved"


def test_verified_expression_candidate_displays_correction() -> None:
    items = [
        {
            "component_ref": "zodbpickle|UNKNOWN",
            "reason": "UNKNOWN",
            "evidence": {
                "source_layer": "agent",
                "url": "https://api.clearlydefined.io/definitions/pypi/pypi/-/zodbpickle/4.2",
                "anchor": "PSF-2.0 AND ZPL-2.1",
            },
            "candidate_spdx": "PSF-2.0 AND ZPL-2.1",
            "status": "open",
            "decided_by": None,
            "decided_at": None,
            "note": "agent:verified_awaiting_human",
        }
    ]

    markdown = render_shortlist_markdown(items)

    assert "`zodbpickle|UNKNOWN` -&gt; `PSF-2.0 AND ZPL-2.1`" in markdown


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


def test_apply_decisions_defaults_decided_by_to_logged_in_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("repolens.shortlist.decisions.getpass.getuser", lambda: "os-sentinel")
    items = _items()
    decisions = parse_checkbox_decisions(
        _tick(render_shortlist_markdown(items), "acme-lib|MIT", "x")
    )

    updated = apply_decisions(
        items, decisions, identity=None, now="2026-06-02T00:00:00Z"
    )

    approved = next(item for item in updated if item["component_ref"] == "acme-lib|MIT")
    assert approved["status"] == "approved"
    assert approved["decided_by"] == "os-sentinel"


def test_group_accept_applies_to_members_with_provenance() -> None:
    items = [_items()[0]]
    metadata = ShortlistMetadata(triage_by_ref={})
    markdown = _tick_first_group(render_shortlist_markdown(items, metadata=metadata), "x")
    parsed = parse_review_decisions(markdown)
    groups = build_groups(items, metadata)

    updated = apply_decisions(
        items,
        parsed.item_decisions,
        identity="reviewer-sentinel",
        now="2026-06-02T00:00:00Z",
        group_decisions=parsed.group_decisions,
        group_membership=group_membership_by_ref(groups),
    )

    item = updated[0]
    assert item["status"] == "approved"
    assert item["decided_via"] == "group"
    assert item["decision_provenance"]["component_refs"] == ["acme-lib|MIT"]


def test_item_ref_overrides_group_decision() -> None:
    items = [_items()[0]]
    metadata = ShortlistMetadata(triage_by_ref={})
    markdown = render_shortlist_markdown(items, metadata=metadata)
    markdown = _tick_first_group(markdown, "x")
    markdown = _tick(markdown, "acme-lib|MIT", "r")
    parsed = parse_review_decisions(markdown)
    groups = build_groups(items, metadata)

    updated = apply_decisions(
        items,
        parsed.item_decisions,
        identity="reviewer-sentinel",
        now="2026-06-02T00:00:00Z",
        group_decisions=parsed.group_decisions,
        group_membership=group_membership_by_ref(groups),
    )

    assert updated[0]["status"] == "rejected"
    assert updated[0]["decided_via"] == "item"
    assert "decision_provenance" not in updated[0]


def test_malformed_group_marker_is_ignored() -> None:
    items = [_items()[0]]
    metadata = ShortlistMetadata(triage_by_ref={})
    markdown = _tick_first_group(render_shortlist_markdown(items, metadata=metadata), "x")
    corrupted = markdown.replace("rpl:group=", "rpl:group=!!!")

    parsed = parse_review_decisions(corrupted)

    assert parsed.group_decisions == {}


def test_needs_judgment_group_decision_applies_to_members() -> None:
    items = _needs_judgment_items()
    metadata = ShortlistMetadata(triage_by_ref={})
    groups = build_groups(items, metadata)
    markdown = render_shortlist_markdown(items, metadata=metadata)

    approved = parse_review_decisions(_tick_first_group(markdown, "x"))
    approved_items = apply_decisions(
        items,
        approved.item_decisions,
        identity="reviewer-sentinel",
        now="2026-06-02T00:00:00Z",
        group_decisions=approved.group_decisions,
        group_membership=group_membership_by_ref(groups),
    )
    rejected = parse_review_decisions(_tick_first_group(markdown, "r"))
    rejected_items = apply_decisions(
        items,
        rejected.item_decisions,
        identity="reviewer-sentinel",
        now="2026-06-02T00:00:00Z",
        group_decisions=rejected.group_decisions,
        group_membership=group_membership_by_ref(groups),
    )

    assert {item["status"] for item in approved_items} == {"approved"}
    assert {item["decided_via"] for item in approved_items} == {"group"}
    assert {item["status"] for item in rejected_items} == {"rejected"}
    assert {item["decided_via"] for item in rejected_items} == {"group"}


def test_needs_judgment_item_ref_overrides_group_decision() -> None:
    items = _needs_judgment_items()
    metadata = ShortlistMetadata(triage_by_ref={})
    markdown = render_shortlist_markdown(items, metadata=metadata)
    markdown = _tick_first_group(markdown, "x")
    markdown = _tick(markdown, "acme-tool|GPL-3.0-only", "r")
    parsed = parse_review_decisions(markdown)
    groups = build_groups(items, metadata)

    updated = apply_decisions(
        items,
        parsed.item_decisions,
        identity="reviewer-sentinel",
        now="2026-06-02T00:00:00Z",
        group_decisions=parsed.group_decisions,
        group_membership=group_membership_by_ref(groups),
    )

    by_ref = {str(item["component_ref"]): item for item in updated}
    assert by_ref["acme-tool|GPL-3.0-only"]["status"] == "rejected"
    assert by_ref["acme-tool|GPL-3.0-only"]["decided_via"] == "item"
    assert by_ref["acme-core|GPL-3.0-or-later"]["status"] == "approved"
    assert by_ref["acme-core|GPL-3.0-or-later"]["decided_via"] == "group"
