"""The capability-minimized resolution-agent boundary.

This module defines the *only* surface the resolution agent gets. The agent receives an
:class:`AgentRequest` carrying a single screened-and-wrapped ``<untrusted_content>`` string
plus the item identity, and returns an :class:`AgentResponse` that is either a schema-shaped
:class:`Resolution` or an :class:`Abstain`.

Capability minimization is enforced *behaviorally* at this boundary (per the plan-review
note B[5]): :class:`AgentRequest` exposes no token, no filesystem paths, and no callables,
so the agent cannot reach the GitHub token, write files, spawn processes, or fetch an
arbitrary host. The structural "no shell / no file-write" claim is a documentation
invariant; the enforcing assertion is the request-surface shape, checked in
``tests/unit/shortlist/test_agent.py``.

The agent never re-fetches evidence itself — the orchestrator does the verify-don't-trust
re-fetch (see :mod:`repolens.shortlist.stage`). ``MAX_FETCHES_PER_ITEM`` documents the
per-item fetch budget the orchestrator enforces; it lives here so the boundary owns the
contract value (AC 3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from repolens.data.errors import SchemaValidationError

#: Max evidence re-fetches the orchestrator performs per item (AC 3 / rpl_security.md §1).
#: The agent itself performs no fetches; this caps the orchestrator's verify loop so a
#: crafted item with many candidate URLs cannot drive unbounded outbound requests.
MAX_FETCHES_PER_ITEM = 3


@dataclass(frozen=True, slots=True)
class AgentRequest:
    """The complete, minimal surface handed to the resolution agent.

    Only two fields, both plain strings:

    * ``component_ref`` — the opaque item identity (``name|license``), used solely for the
      agent to scope its single reply; it is *not* a path and is never opened.
    * ``wrapped_context`` — the screened, capped, ``<untrusted_content …>``-wrapped string
      with the output instruction appended *after* the block.

    There is deliberately **no** token field, **no** path field, and **no** callable field.
    The agent cannot fetch, read files, or reach secrets through this object.
    """

    component_ref: str
    wrapped_context: str


@dataclass(frozen=True, slots=True)
class Resolution:
    """A concrete SPDX claim the agent proposes for orchestrator verification."""

    spdx_id: str
    evidence_url: str
    evidence_anchor: str


@dataclass(frozen=True, slots=True)
class Abstain:
    """The agent declined to propose a resolution (abstains rather than guesses)."""

    reason: str = "abstained"


#: An agent reply is either a concrete proposal or an abstention.
AgentResponse = Resolution | Abstain


class AgentClient(Protocol):
    """The injectable resolution-agent boundary.

    Implementations receive only an :class:`AgentRequest` and must return an
    :class:`AgentResponse`. RepoLens does not ship a model client behind this protocol;
    the supported AI-assisted workflow emits request-shaped contexts as artifacts,
    receives external proposal artifacts, and verifies those citations locally.
    """

    def resolve(self, request: AgentRequest) -> AgentResponse:
        """Return a resolution proposal or an abstention for ``request``."""


def parse_agent_payload(payload: Any) -> AgentResponse:
    """Validate a raw agent JSON payload into a typed :class:`AgentResponse`.

    Older injected test clients and external tooling may produce raw JSON-like payloads;
    this is the schema gate for that shape. Anything that is not an exact
    ``{spdx_id, evidence_url, evidence_anchor}`` object with non-empty string fields is
    treated as an abstention rather than trusted (fail-closed; the proposal abstains
    rather than guesses). An explicit ``{"abstain": ...}`` object also maps to
    :class:`Abstain`.
    """

    if not isinstance(payload, dict):
        return Abstain(reason="non_object_payload")
    if payload.get("abstain"):
        return Abstain(reason="agent_abstained")
    try:
        return _resolution_from_dict(payload)
    except SchemaValidationError:
        return Abstain(reason="non_schema_payload")


def _resolution_from_dict(payload: dict[str, Any]) -> Resolution:
    required = ("spdx_id", "evidence_url", "evidence_anchor")
    allowed = set(required)
    if set(payload) - allowed:
        raise SchemaValidationError("agent payload has unexpected fields")
    values: dict[str, str] = {}
    for key in required:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise SchemaValidationError(f"agent payload field {key!r} must be a non-empty string")
        values[key] = value
    return Resolution(
        spdx_id=values["spdx_id"],
        evidence_url=values["evidence_url"],
        evidence_anchor=values["evidence_anchor"],
    )


__all__ = [
    "MAX_FETCHES_PER_ITEM",
    "Abstain",
    "AgentClient",
    "AgentRequest",
    "AgentResponse",
    "Resolution",
    "parse_agent_payload",
]
