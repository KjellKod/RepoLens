from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from repolens.data import store
from repolens.data.errors import LimitExceeded, SchemaValidationError
from repolens.data.validation import validate_artifact
from repolens.report.review import build_review_items, run_report_review
from repolens.security.redaction import REDACTION
from repolens.shortlist.render import decode_component_ref


def test_review_selects_policy_allowed_compound_license(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="Apache-2.0 OR LGPL-2.1-or-later OR MIT"))

    items = build_review_items(tmp_path)

    assert len(items) == 1
    assert items[0].raw_spdx == "Apache-2.0 OR LGPL-2.1-or-later OR MIT"
    assert [option.spdx for option in items[0].options[:3]] == [
        "Apache-2.0",
        "LGPL-2.1-or-later",
        "MIT",
    ]


def test_review_skips_simple_license(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT"))

    assert build_review_items(tmp_path) == ()


def test_review_selects_with_and_malformed_expressions_conservatively(tmp_path: Path) -> None:
    _write_resolved(
        tmp_path,
        _record(name="with-lib", spdx_id="GPL-3.0-only WITH Autoconf-exception-3.0"),
        _record(name="bad-lib", spdx_id="MIT OR (GPL-3.0-only"),
    )

    by_name = {item.component_key["name"]: item for item in build_review_items(tmp_path)}

    assert set(by_name) == {"bad-lib", "with-lib"}
    for item in by_name.values():
        assert [option.option_id for option in item.options] == [
            "keep-full",
            "needs-legal-follow-up",
        ]


def test_review_does_not_offer_branch_for_mixed_and_nested_or(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="Unicode-3.0 AND (Apache-2.0 OR MIT)"))

    item = build_review_items(tmp_path)[0]

    assert [option.option_id for option in item.options] == [
        "keep-full",
        "needs-legal-follow-up",
    ]


def test_review_does_not_offer_branch_for_parenthesized_or(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR (Apache-2.0 OR BSD-3-Clause)"))

    item = build_review_items(tmp_path)[0]

    assert [option.option_id for option in item.options] == [
        "keep-full",
        "needs-legal-follow-up",
    ]


def test_review_candidate_selection_matches_main_report_rows(tmp_path: Path) -> None:
    _write_resolved(
        tmp_path,
        _record(name="runtime-lib", spdx_id="MIT OR Apache-2.0"),
        _record(
            name="build-lib",
            spdx_id="MIT OR Apache-2.0",
            tags={"origin": "third-party-oss", "scope": "build", "distribution": "not-distributed"},
        ),
        _record(
            name="first-party-lib",
            spdx_id="MIT OR Apache-2.0",
            tags={"origin": "first-party", "scope": "runtime", "distribution": "server"},
        ),
        _record(name="rejected-lib", spdx_id="MIT OR Apache-2.0"),
    )
    _write_shortlist(
        tmp_path,
        [_shortlist_item("rejected-lib|MIT OR Apache-2.0", status="rejected")],
    )

    items = build_review_items(tmp_path)

    assert [item.component_key["name"] for item in items] == ["runtime-lib"]


def test_review_collapses_identical_disclosure_choices_and_renders_links(tmp_path: Path) -> None:
    _write_resolved(
        tmp_path,
        _record(name="acme-lib-a", spdx_id="MIT OR Apache-2.0"),
        _record(name="acme-lib-b", spdx_id="MIT OR Apache-2.0"),
    )

    items = build_review_items(tmp_path)
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    payload = _review_json(tmp_path)

    assert len(items) == 1
    assert items[0].components == ("acme-lib-a", "acme-lib-b")
    assert len(items[0].row_review_ids) == 2
    assert payload["open_count"] == 1
    assert len(payload["items"]) == 1
    assert payload["items"][0]["components"] == ["acme-lib-a", "acme-lib-b"]
    assert "### package: `acme-lib-a` + 1 more package (2 total), version: `1.2.3`" in markdown
    assert "- grouping reason: `same detected SPDX, same version set, and same policy tier`" in markdown
    assert "_review id: `license-review-group:MIT OR Apache-2.0|1.2.3|ALLOW`_" in markdown
    assert "### `license-review-group:" not in markdown
    assert "acme-lib-a" in markdown
    assert "acme-lib-b" in markdown
    assert "source links:" in markdown
    assert "[source1](https://example.invalid/licenses/acme-lib-a)" in markdown
    assert "https://example.invalid/licenses/acme-lib-a" in markdown
    assert "suggested choice: `Keep full expression: MIT OR Apache-2.0`" in markdown
    assert "avoids an arbitrary branch choice" in markdown
    assert markdown.count("rpl:license-review-item=") == 1
    assert "rpl:license-review=" not in markdown
    assert markdown.count("rpl:license-review-option=") == 4


def test_report_review_suggests_lower_risk_or_branch(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR GPL-3.0-only"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    assert "suggested choice: `MIT`" in markdown
    assert "MIT has policy tier ALLOW; lower risk than GPL-3.0-only (BLOCK)" in markdown
    assert "## ⚠️ High-Attention License Choices" in markdown
    assert "High-attention rules come from RepoLens policy tiers" in markdown
    assert (
        "https://github.com/KjellKod/RepoLens/blob/main/"
        "src/repolens/policy/data/license-policy.default.json"
    ) in markdown
    assert "marking `MIT` or `Unlicense` as high risk belongs in that policy file" in markdown
    assert (
        "- ⚠️ `acme-lib` (`MIT OR GPL-3.0-only`): GPL-3.0-only is policy tier BLOCK; "
        "suggested choice: `MIT`"
    ) in markdown
    assert "- ⚠️ high attention: `GPL-3.0-only is policy tier BLOCK`" in markdown


def test_report_review_skips_high_attention_section_for_permissive_choices(
    tmp_path: Path,
) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    assert "High-Attention License Choices" not in markdown
    assert "high attention:" not in markdown


def test_report_review_suggests_keep_full_for_non_branch_expression(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT AND Apache-2.0"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    assert "### package: `acme-lib`, version: `1.2.3`" in markdown
    assert "suggested choice: `Keep full expression: MIT AND Apache-2.0`" in markdown
    assert "not a simple OR branch choice" in markdown


def test_report_review_suggests_keep_full_when_lowest_risk_branch_ties(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="Apache-2.0 OR LGPL-2.1-or-later OR MIT"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    assert "suggested choice: `Keep full expression: Apache-2.0 OR LGPL-2.1-or-later OR MIT`" in markdown
    assert (
        "Apache-2.0 and MIT have policy tier ALLOW; "
        "lower risk than LGPL-2.1-or-later (REVIEW)"
    ) in markdown
    assert "LGPL-2.1-or-later is policy tier REVIEW" in markdown


def test_report_review_marks_non_branch_review_expression_high_attention(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="Unicode-3.0 AND MIT"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    assert "## ⚠️ High-Attention License Choices" in markdown
    assert "Unicode-3.0 AND MIT is policy tier REVIEW" in markdown


def test_checked_branch_records_selected_spdx_and_note(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("- [ ] `MIT`", "- [x] `MIT`", 1)
    text = text.replace("\n>\n", "\n> Using permissive branch for disclosure.\n", 1)
    path.write_text(text, encoding="utf-8")

    result = run_report_review(
        tmp_path,
        identity="reviewer-sentinel",
        now="2026-06-06T00:01:00Z",
    )

    payload = _review_json(tmp_path)
    item = payload["items"][0]
    assert result.open_count == 0
    assert item["selected_spdx"] == "MIT"
    assert item["decision"] == "selected_branch"
    assert item["review_status"] == "approved"
    assert item["review_note"] == "Using permissive branch for disclosure."
    assert item["decided_by"] == "reviewer-sentinel"


def test_report_review_markdown_redacts_token_shaped_notes(tmp_path: Path) -> None:
    token = "ghp_" + "A" * 24
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("- [ ] `MIT`", "- [x] `MIT`", 1)
    text = text.replace("\n>\n", f"\n> Using token {token} in note.\n", 1)
    path.write_text(text, encoding="utf-8")

    run_report_review(tmp_path, now="2026-06-06T00:01:00Z")

    markdown = path.read_text(encoding="utf-8")
    payload = _review_json(tmp_path)
    assert token not in markdown
    assert token not in json.dumps(payload)
    assert REDACTION in markdown


def test_report_review_markers_do_not_encode_token_shaped_names(tmp_path: Path) -> None:
    token = "ghp_" + "B" * 24
    _write_resolved(tmp_path, _record(name=f"acme-{token}", spdx_id="MIT OR Apache-2.0"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    payload = _review_json(tmp_path)
    assert token not in markdown
    assert token not in json.dumps(payload)
    assert REDACTION not in payload["items"][0]["review_id"]
    assert REDACTION in payload["items"][0]["row_review_ids"][0]


def test_report_review_option_markers_do_not_encode_token_shaped_spdx(tmp_path: Path) -> None:
    token = "ghp_" + "C" * 24
    _write_raw_resolved(tmp_path, _record(spdx_id=f"{token} OR MIT"))

    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    markdown = (tmp_path / "report.review.md").read_text(encoding="utf-8")
    payload = _review_json(tmp_path)
    decoded_markers: list[str] = []
    for option_id in re.findall(
        r"rpl:license-review-option=([A-Za-z0-9_-]+)",
        markdown,
    ):
        decoded_markers.append(decode_component_ref(option_id) or "")
    assert decoded_markers
    assert token not in markdown
    assert token not in json.dumps(payload)
    assert all(token not in marker for marker in decoded_markers)
    assert {option["option_id"] for option in payload["items"][0]["options"]} >= {
        "branch:1",
        "branch:2",
    }


def test_keep_full_records_raw_expression(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "- [ ] `Keep full expression: MIT OR Apache-2.0`",
            "- [x] `Keep full expression: MIT OR Apache-2.0`",
            1,
        ),
        encoding="utf-8",
    )

    run_report_review(tmp_path, now="2026-06-06T00:01:00Z")

    item = _review_json(tmp_path)["items"][0]
    assert item["selected_spdx"] == "MIT OR Apache-2.0"
    assert item["decision"] == "keep_full_expression"
    assert item["review_status"] == "approved"


def test_multiple_checked_options_leave_item_open(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("- [ ] `MIT`", "- [x] `MIT`", 1)
    text = text.replace("- [ ] `Apache-2.0`", "- [x] `Apache-2.0`", 1)
    path.write_text(text, encoding="utf-8")

    result = run_report_review(tmp_path, now="2026-06-06T00:01:00Z")

    item = _review_json(tmp_path)["items"][0]
    assert result.open_count == 1
    assert item["selected_spdx"] is None
    assert item["review_status"] == "open"
    assert item["warnings"] == ["multiple checked options; choose exactly one"]


def test_open_shortlist_overlap_blocks_selected_disclosure(tmp_path: Path) -> None:
    spdx_id = "MIT OR Apache-2.0"
    _write_resolved(tmp_path, _record(spdx_id=spdx_id))
    _write_shortlist(tmp_path, [_shortlist_item(f"acme-lib|{spdx_id}", status="open")])
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace("- [ ] `MIT`", "- [x] `MIT`", 1),
        encoding="utf-8",
    )

    result = run_report_review(tmp_path, now="2026-06-06T00:01:00Z")

    item = _review_json(tmp_path)["items"][0]
    assert result.open_count == 1
    assert item["selected_spdx"] is None
    assert item["decision"] == "blocked_by_shortlist"
    assert item["review_status"] == "open"
    assert item["warnings"] == ["matching shortlist item is still open"]


def test_approved_shortlist_overlap_allows_selected_disclosure(tmp_path: Path) -> None:
    spdx_id = "MIT OR Apache-2.0"
    _write_resolved(tmp_path, _record(spdx_id=spdx_id))
    _write_shortlist(tmp_path, [_shortlist_item(f"acme-lib|{spdx_id}", status="approved")])
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    path = tmp_path / "report.review.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace("- [ ] `MIT`", "- [x] `MIT`", 1),
        encoding="utf-8",
    )

    result = run_report_review(tmp_path, now="2026-06-06T00:01:00Z")

    item = _review_json(tmp_path)["items"][0]
    assert result.open_count == 0
    assert item["selected_spdx"] == "MIT"
    assert item["review_status"] == "approved"


def test_report_review_schema_rejects_unknown_field_and_bad_open_count(tmp_path: Path) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    run_report_review(tmp_path, now="2026-06-06T00:00:00Z")
    payload = _review_json(tmp_path)

    validate_artifact(payload, "report_review")

    bad_field = json.loads(json.dumps(payload))
    bad_field["items"][0]["unexpected"] = "drift"
    with pytest.raises(SchemaValidationError, match="unexpected"):
        validate_artifact(bad_field, "report_review")

    bad_count = json.loads(json.dumps(payload))
    bad_count["open_count"] = 0
    with pytest.raises(SchemaValidationError, match="open_count"):
        validate_artifact(bad_count, "report_review")


def test_report_review_json_byte_cap_is_enforced_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_resolved(tmp_path, _record(spdx_id="MIT OR Apache-2.0"))
    monkeypatch.setattr("repolens.report.review.max_bytes_for", lambda _artifact: 16)

    with pytest.raises(LimitExceeded, match="report.review.json"):
        run_report_review(tmp_path, now="2026-06-06T00:00:00Z")

    assert not (tmp_path / "report.review.json").exists()


def _write_resolved(tmp_path: Path, *records: dict[str, Any]) -> None:
    store.write_resolved(tmp_path, "acme-alpha", records)


def _write_raw_resolved(tmp_path: Path, *records: dict[str, Any]) -> None:
    path = store.repo_dir(tmp_path, "acme-alpha") / "resolved.ndjson"
    payload = "\n".join(json.dumps(record) for record in records) + "\n"
    store.atomic_write_bytes(path, payload.encode("utf-8"))


def _record(
    *,
    name: str = "acme-lib",
    spdx_id: str,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "name": name,
        "version": "1.2.3",
        "repo": "acme-alpha",
        "purl": f"pkg:pypi/{name}@1.2.3",
        "declared_license_raw": spdx_id,
        "spdx_id": spdx_id,
        "evidence": {
            "source_layer": "syft",
            "url": f"https://example.invalid/licenses/{name}",
            "anchor": spdx_id,
            "fetched_at": "2026-01-01T00:00:00Z",
        },
        "tags": tags
        or {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "modified": "unknown",
    }


def _write_shortlist(tmp_path: Path, items: list[dict[str, object]]) -> None:
    store.write_shortlist(
        tmp_path,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": sum(1 for item in items if item["status"] == "open"),
            "items": items,
        },
    )


def _shortlist_item(component_ref: str, *, status: str) -> dict[str, object]:
    return {
        "component_ref": component_ref,
        "reason": "REVIEW",
        "evidence": {"source_layer": "syft"},
        "candidate_spdx": None,
        "status": status,
        "decided_by": "reviewer" if status != "open" else None,
        "decided_at": "2026-01-01T00:00:00Z" if status != "open" else None,
    }


def _review_json(tmp_path: Path) -> dict[str, Any]:
    payload = json.loads((tmp_path / "report.review.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
