from __future__ import annotations

import json
from pathlib import Path

from repolens.data import store
from repolens.shortlist.agent import AgentRequest, AgentResponse
from repolens.shortlist.contexts import build_agent_request
from repolens.shortlist.prescreen import ItemContent
from repolens.shortlist.stage import run_shortlist

_DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3"


class _ExplodingAgent:
    def resolve(self, request: AgentRequest) -> AgentResponse:
        del request
        raise AssertionError("emit-contexts must not invoke an agent")


def _write_shortlist(work_root: Path, component_ref: str = "acme-lib|MIT") -> None:
    store.write_shortlist(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [
                {
                    "component_ref": component_ref,
                    "reason": "REVIEW",
                    "evidence": {"source_layer": "api", "url": _DEPS_DEV_URL, "anchor": "MIT"},
                    "candidate_spdx": None,
                    "status": "open",
                    "decided_by": None,
                    "decided_at": None,
                    "note": None,
                }
            ],
        },
    )


def _write_inventory(work_root: Path) -> None:
    store.write_inventory(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "name": "acme-lib",
                    "license": "MIT",
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                    "versions": ["1.2.3"],
                    "source_url": _DEPS_DEV_URL,
                    "modified": "unknown",
                    "found_in": ["acme-alpha"],
                    "policy_tier": "REVIEW",
                    "evidence_refs": ["acme-alpha/resolved.ndjson:1"],
                }
            ],
        },
    )
    store.write_resolved(
        work_root,
        "acme-alpha",
        [
            {
                "schema_version": "1.0",
                "name": "acme-lib",
                "version": "1.2.3",
                "repo": "acme-alpha",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "spdx_id": "MIT",
                "evidence": {"source_layer": "api", "url": _DEPS_DEV_URL, "anchor": "MIT"},
                "tags": {
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                },
                "modified": "unknown",
            }
        ],
    )


def test_emit_contexts_matches_agent_request_wrapped_context(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_inventory(tmp_path)
    contexts_path = tmp_path / "shortlist.contexts.json"

    def content_loader(_item: object) -> ItemContent:
        return ItemContent(license_text="MIT License text")

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        content_loader=content_loader,
        emit_contexts_path=contexts_path,
    )

    payload = json.loads(contexts_path.read_text(encoding="utf-8"))
    item = store.read_shortlist(tmp_path)["items"][0]
    request, reason = build_agent_request(item, content_loader=content_loader)

    assert reason is None
    assert len(payload) == 1
    assert payload[0]["component_ref"] == "acme-lib|MIT"
    assert payload[0]["wrapped_context"] == request.wrapped_context
    assert payload[0]["triage"] == {
        "spdx_id": "MIT",
        "tier": "REVIEW",
        "origin": "third-party-oss",
        "scope": "runtime",
        "distribution": "server",
        "presence_section": "DELIVERY ARTIFACT NOT SCANNED - UNKNOWN",
        "presence": None,
        "evidence_url": _DEPS_DEV_URL,
        "evidence_anchor": "MIT",
        "found_in": ["acme-alpha"],
    }
    assert payload[0]["package"] == "acme-lib"
    assert payload[0]["version"] == "1.2.3"
    assert payload[0]["ecosystem"] == "pypi"
    assert payload[0]["purl"] == "pkg:pypi/acme-lib@1.2.3"


def test_emit_contexts_omits_tokens_paths_and_callables(tmp_path: Path) -> None:
    token = "ghp_" + "C" * 30
    _write_shortlist(tmp_path, component_ref=f"acme-{token}|MIT")
    contexts_path = tmp_path / "shortlist.contexts.json"

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        content_loader=lambda _item: ItemContent(license_text=f"MIT License {token}"),
        emit_contexts_path=contexts_path,
    )

    text = contexts_path.read_text(encoding="utf-8")
    assert token not in text
    assert str(tmp_path) not in text
    assert "callable" not in text.lower()
    assert "[REDACTED_TOKEN]" in text
    assert json.loads(text)[0]["wrapped_context"] is not None
