from __future__ import annotations

import dataclasses

from repolens.shortlist.agent import (
    MAX_FETCHES_PER_ITEM,
    Abstain,
    AgentRequest,
    Resolution,
    parse_agent_payload,
)


def test_agent_request_carries_no_token_or_paths() -> None:
    request = AgentRequest(component_ref="acme-lib|MIT", wrapped_context="<untrusted_content/>")
    field_names = {field.name for field in dataclasses.fields(request)}

    # Capability minimization is enforced behaviorally on the request surface (plan B[5]):
    # no token, no filesystem path, and no callable reaches the agent.
    assert field_names == {"component_ref", "wrapped_context"}
    for value in (request.component_ref, request.wrapped_context):
        assert isinstance(value, str)
        assert not callable(value)
    assert all("token" not in name and "path" not in name for name in field_names)


def test_agent_response_rejects_non_schema_json() -> None:
    assert isinstance(parse_agent_payload({"spdx_id": "MIT"}), Abstain)
    empty_field = {"spdx_id": "", "evidence_url": "u", "evidence_anchor": "a"}
    assert isinstance(parse_agent_payload(empty_field), Abstain)
    assert isinstance(parse_agent_payload(["MIT"]), Abstain)
    assert isinstance(
        parse_agent_payload(
            {"spdx_id": "MIT", "evidence_url": "u", "evidence_anchor": "a", "extra": "x"}
        ),
        Abstain,
    )


def test_agent_response_accepts_exact_schema() -> None:
    response = parse_agent_payload(
        {
            "spdx_id": "MIT",
            "evidence_url": "https://api.deps.dev/v3alpha/x",
            "evidence_anchor": "MIT",
        }
    )

    assert isinstance(response, Resolution)
    assert response.spdx_id == "MIT"
    assert response.evidence_anchor == "MIT"


def test_agent_abstain_path() -> None:
    assert isinstance(parse_agent_payload({"abstain": True}), Abstain)
    assert isinstance(parse_agent_payload(None), Abstain)


def test_fetch_budget_constant_is_three() -> None:
    # AC 3 / rpl_security.md §1: max 3 fetches per item, owned at the agent boundary.
    assert MAX_FETCHES_PER_ITEM == 3
