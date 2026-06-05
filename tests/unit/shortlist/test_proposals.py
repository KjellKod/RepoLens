from __future__ import annotations

from pathlib import Path

import pytest

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.agent import AgentRequest, AgentResponse
from repolens.shortlist.stage import run_shortlist

_DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3"


class _ExplodingAgent:
    def resolve(self, request: AgentRequest) -> AgentResponse:
        del request
        raise AssertionError("proposal artifact ingestion must not invoke an agent")


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def _fetcher(body: bytes):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=body)

    return fetch


def _write_shortlist(work_root: Path) -> None:
    store.write_shortlist(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [_item("acme-lib|MIT")],
        },
    )


def _item(component_ref: str) -> dict[str, object]:
    return {
        "component_ref": component_ref,
        "reason": "REVIEW",
        "evidence": {"source_layer": "api", "url": _DEPS_DEV_URL, "anchor": "MIT"},
        "candidate_spdx": None,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": None,
    }


def _proposal(**overrides: object) -> dict[str, object]:
    proposal: dict[str, object] = {
        "component_ref": "acme-lib|MIT",
        "spdx_id": "MIT",
        "evidence_url": _DEPS_DEV_URL,
        "evidence_anchor": "MIT",
        "disposition": "allow",
        "confidence": 0.95,
        "rationale": "Registry metadata anchors MIT.",
        "sanity_check": "No BLOCK terms found.",
    }
    proposal.update(overrides)
    return proposal


def _write_proposals(path: Path, proposals: list[dict[str, object]]) -> None:
    store.atomic_write_json(path, proposals)


def test_verified_proposal_records_candidate_but_keeps_open(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal()])

    result = run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert result.agent_invocations == 0
    assert item["status"] == "open"
    assert item["candidate_spdx"] == "MIT"
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["verify_reason"] == "verify:exact_anchor"
    assert item["ai_suggestion"]["disposition"] == "allow"


def test_verified_expression_proposal_records_candidate(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    expression = "PSF-2.0 AND ZPL-2.1"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                spdx_id=expression,
                evidence_anchor=expression,
                rationale="Registry metadata anchors a permissive expression.",
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"licensed":{"declared":"PSF-2.0 AND ZPL-2.1"}}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] == expression
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["verify_reason"] == "verify:exact_anchor"


def test_bad_anchor_keeps_open_with_verify_failed(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal()])

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"GPL-3.0-only"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:anchor_mismatch"


def test_off_allowlist_url_rejected(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [_proposal(evidence_url="https://attacker.example.invalid/license")],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["note"] == "verify_failed:verify:fetch_blocked_or_failed"


def test_abstention_records_reason_without_verification(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [{"component_ref": "acme-lib|MIT", "abstain": True, "reason": "ambiguous"}],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["note"] == "agent:abstained"
    assert item["ai_suggestion"]["reason"] == "ambiguous"


def test_proposal_artifact_schema_rejects_unknown_fields(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal(unexpected="drift")])

    with pytest.raises(SchemaValidationError, match="unexpected"):
        run_shortlist(
            tmp_path,
            agent_client=_ExplodingAgent(),
            proposals_path=proposals_path,
            fetcher=_fetcher(b'{"license":"MIT"}'),
            evidence_resolver=_public_resolver,
        )
