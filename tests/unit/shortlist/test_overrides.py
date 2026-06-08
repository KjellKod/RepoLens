from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.shortlist.agent import AgentRequest, AgentResponse
from repolens.shortlist.overrides import load_overrides
from repolens.shortlist.stage import run_shortlist


class _ExplodingAgent:
    def resolve(self, request: AgentRequest) -> AgentResponse:
        del request
        raise AssertionError("human overrides must not invoke an agent")


def _write_shortlist(work_root: Path, item: dict[str, object] | None = None) -> None:
    items = [item or _item()]
    store.write_shortlist(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": sum(1 for entry in items if entry["status"] == "open"),
            "items": items,
        },
    )


def _item(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "component_ref": "zope.site|UNKNOWN",
        "reason": "UNKNOWN",
        "evidence": {"source_layer": "api", "url": "https://pypi.org/project/zope.site/"},
        "candidate_spdx": None,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": None,
    }
    item.update(overrides)
    return item


def _override(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "component_ref": "zope.site|UNKNOWN",
        "spdx_id": "ZPL-2.1",
        "evidence_url": "https://pypi.org/project/zope.site/",
        "evidence_note": "PyPI identifies the package license as ZPL-2.1.",
        "reason": "Correcting stale UNKNOWN resolver output after manual review.",
        "decided_by": "kjell",
        "expires_at": "2099-12-31",
    }
    record.update(overrides)
    return record


def _write_overrides(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_valid_override_ingestion_sets_candidate_and_provenance_but_leaves_open(
    tmp_path: Path,
) -> None:
    _write_shortlist(tmp_path)
    overrides_path = _write_overrides(tmp_path / "shortlist.overrides.json", [_override()])

    result = run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        overrides_path=overrides_path,
        now="2026-06-08T12:00:00Z",
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert result.open_count == 1
    assert item["status"] == "open"
    assert item["candidate_spdx"] == "ZPL-2.1"
    assert item["research_evidence"]["machine_verification"] == "human_override_unverified"
    assert item["research_evidence"]["outcome"] == "human_override"
    assert isinstance(item["research_evidence"]["context_fingerprint"], str)
    assert item["research_evidence"]["override_evidence_verified"] is False
    assert item["research_evidence"]["override_decided_by"] == "kjell"
    markdown = (tmp_path / "shortlist.md").read_text(encoding="utf-8")
    assert "human override candidate (unverified)" in markdown
    assert "human override evidence (unverified)" in markdown


def test_risky_override_does_not_auto_approve(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    overrides_path = _write_overrides(
        tmp_path / "shortlist.overrides.json",
        [_override(spdx_id="GPL-3.0-only")],
    )

    run_shortlist(tmp_path, agent_client=_ExplodingAgent(), overrides_path=overrides_path)

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] == "GPL-3.0-only"
    assert item["research_evidence"]["override_policy_tier"] == "BLOCK"


def test_override_reopens_settled_item_when_candidate_changes(tmp_path: Path) -> None:
    _write_shortlist(
        tmp_path,
        _item(
            candidate_spdx="MIT",
            status="approved",
            decided_by="reviewer",
            decided_at="2026-01-01T00:00:00Z",
        ),
    )
    overrides_path = _write_overrides(tmp_path / "shortlist.overrides.json", [_override()])

    run_shortlist(tmp_path, agent_client=_ExplodingAgent(), overrides_path=overrides_path)

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["decided_by"] is None
    assert item["decided_at"] is None
    assert item["candidate_spdx"] == "ZPL-2.1"


def test_override_reopens_settled_item_when_candidate_is_same(tmp_path: Path) -> None:
    _write_shortlist(
        tmp_path,
        _item(
            candidate_spdx="ZPL-2.1",
            status="approved",
            decided_by="reviewer",
            decided_at="2026-01-01T00:00:00Z",
        ),
    )
    overrides_path = _write_overrides(tmp_path / "shortlist.overrides.json", [_override()])

    run_shortlist(tmp_path, agent_client=_ExplodingAgent(), overrides_path=overrides_path)

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["decided_by"] is None
    assert item["decided_at"] is None
    assert item["candidate_spdx"] == "ZPL-2.1"
    assert item["research_evidence"]["machine_verification"] == "human_override_unverified"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"component_ref": "zope.site|UNKNOWN"}, "expected array"),
        ([_override(unexpected="drift")], "unexpected"),
        ([_override(reason="")], "reason"),
        ([_override(decided_by="")], "decided_by"),
        ([_override(component_ref="missing|UNKNOWN")], "does not match shortlist item"),
        ([_override(spdx_id="LicenseRef-Not-Real")], "unsupported SPDX"),
        ([_override(evidence_url="pkg:pypi/zope.site@6.0")], "evidence_url"),
        ([_override(evidence_url="https://www.google.com/search?q=zope.site")], "placeholder"),
        ([_override(evidence_note="placeholder")], "meaningful"),
        ([_override(expires_at="2026/12/31")], "expires_at"),
        ([_override(expires_at="2000-01-01")], "expired"),
    ],
)
def test_override_validation_rejects_invalid_payloads(
    tmp_path: Path,
    payload: object,
    message: str,
) -> None:
    items = [_item()]
    overrides_path = _write_overrides(tmp_path / "shortlist.overrides.json", payload)

    with pytest.raises(SchemaValidationError, match=message):
        load_overrides(overrides_path, items=items)


def test_override_validation_rejects_duplicate_component_refs(tmp_path: Path) -> None:
    items = [_item()]
    overrides_path = _write_overrides(
        tmp_path / "shortlist.overrides.json",
        [_override(), _override(reason="second")],
    )

    with pytest.raises(SchemaValidationError, match="duplicate"):
        load_overrides(overrides_path, items=items)
