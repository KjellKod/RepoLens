from __future__ import annotations

from typing import Any

from repolens.flag.render import render_shortlist_markdown


def _item(
    *,
    component_ref: str = "acme-lib|MIT",
    reason: str = "REVIEW",
    note: str = "REVIEW: canonical_id",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "component_ref": component_ref,
        "reason": reason,
        "note": note,
        "evidence": {"source_layer": "syft"} if evidence is None else evidence,
        "candidate_spdx": None,
        "status": "open",
    }


def test_two_queue_layout() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                component_ref="acme-block|AGPL-3.0-only",
                reason="BLOCK",
                note="BLOCK: canonical_id",
            ),
            _item(component_ref="acme-rev|MPL-2.0", reason="REVIEW"),
            _item(component_ref="acme-unk|UNKNOWN", reason="UNKNOWN", note="UNKNOWN: empty_input"),
        ]
    )

    assert "## BLOCK" in markdown
    assert "## REVIEW" in markdown
    assert "## UNKNOWN" in markdown
    assert markdown.index("## BLOCK") < markdown.index("## REVIEW") < markdown.index("## UNKNOWN")


def test_empty_queues_render_none() -> None:
    markdown = render_shortlist_markdown([])

    assert markdown.count("_none_") == 3


def test_stated_reason_text_appears_in_md() -> None:
    markdown = render_shortlist_markdown(
        [_item(reason="BLOCK", note="BLOCK: canonical_id")]
    )

    assert "BLOCK: canonical_id" in markdown


def test_evidence_url_renders_safe_link() -> None:
    markdown = render_shortlist_markdown(
        [_item(evidence={"source_layer": "syft", "url": "https://example.invalid/a"})]
    )

    assert "(https://example.invalid/a)" in markdown


def test_no_url_item_renders_anchor_or_placeholder() -> None:
    with_anchor = render_shortlist_markdown(
        [_item(evidence={"source_layer": "syft", "anchor": "MIT"})]
    )
    without_anything = render_shortlist_markdown([_item(evidence={"source_layer": "syft"})])

    assert "`MIT`" in with_anchor
    assert "](" not in with_anchor  # no link rendered for a url-less item
    assert "no evidence url" in without_anything
    assert "](" not in without_anything


def test_untrusted_name_and_url_are_inert() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                component_ref="acme|name",
                evidence={"source_layer": "syft", "url": "javascript:alert(1)"},
            )
        ]
    )

    # The untrusted ref is wrapped in an inert code span; the unsafe href is neutralized.
    assert "`acme|name`" in markdown
    assert "javascript:" not in markdown
    assert "](javascript" not in markdown
