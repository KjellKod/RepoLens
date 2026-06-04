"""Context emission for artifact-only shortlist proposal workflows."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.redaction import redact_tokens_from_structure
from repolens.shortlist.agent import AgentRequest
from repolens.shortlist.prescreen import ItemContent, prescreen_item

ContentLoader = Callable[[Mapping[str, Any]], ItemContent]


@dataclass(frozen=True, slots=True)
class TriageMetadata:
    """Read-only grouping context for one shortlist item."""

    spdx_id: str | None
    tier: str | None
    origin: str | None
    scope: str | None
    distribution: str | None
    evidence_url: str | None
    evidence_anchor: str | None
    found_in: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "spdx_id": self.spdx_id,
            "tier": self.tier,
            "origin": self.origin,
            "scope": self.scope,
            "distribution": self.distribution,
            "evidence_url": self.evidence_url,
            "evidence_anchor": self.evidence_anchor,
            "found_in": list(self.found_in),
        }


@dataclass(frozen=True, slots=True)
class ShortlistMetadata:
    """Safe inventory-derived metadata indexed by ``component_ref``."""

    triage_by_ref: Mapping[str, TriageMetadata]


def build_agent_request(
    item: Mapping[str, Any],
    *,
    content_loader: ContentLoader,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> tuple[AgentRequest | None, str | None]:
    """Build the exact request the in-process agent path would receive.

    ``None`` means the existing prescreen routed the item to humans before any agent
    request could exist. The returned reason is the same human-route note used by the
    stage.
    """

    component_ref = str(item.get("component_ref", ""))
    content = content_loader(item)
    outcome = prescreen_item(content, source="shortlist", path=component_ref, limits=limits)
    if not outcome.routed_to_agent:
        return None, outcome.human_reason
    assert outcome.wrapped_context is not None
    return AgentRequest(component_ref=component_ref, wrapped_context=outcome.wrapped_context), None


def emit_contexts(
    path: Path,
    items: Sequence[Mapping[str, Any]],
    *,
    metadata: ShortlistMetadata,
    content_loader: ContentLoader,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> Path:
    """Write deterministic model-free proposal contexts for still-open items."""

    rows: list[dict[str, Any]] = []
    for item in sorted(items, key=_item_sort_key):
        if item.get("status") != "open":
            continue
        component_ref = str(item.get("component_ref", ""))
        request, human_reason = build_agent_request(
            item, content_loader=content_loader, limits=limits
        )
        row: dict[str, Any] = {
            "component_ref": component_ref,
            "wrapped_context": request.wrapped_context if request is not None else None,
            "triage": triage_for_item(item, metadata).to_dict(),
        }
        if human_reason:
            row["human_reason"] = human_reason
        rows.append(row)
    store.atomic_write_json(path, redact_tokens_from_structure(rows))
    return path


def load_shortlist_metadata(work_root: Path) -> ShortlistMetadata:
    """Load safe triage metadata from ``inventory.json`` when it exists."""

    inventory_path = Path(work_root) / "inventory.json"
    if not inventory_path.exists():
        return ShortlistMetadata(triage_by_ref={})
    inventory = store.read_inventory(work_root)
    raw_components = inventory.get("components", [])
    if not isinstance(raw_components, list):
        return ShortlistMetadata(triage_by_ref={})

    triage_by_ref: dict[str, TriageMetadata] = {}
    for component in raw_components:
        if not isinstance(component, Mapping):
            continue
        name = _optional_str(component.get("name"))
        license_id = _optional_str(component.get("license"))
        if name is None or license_id is None:
            continue
        component_ref = f"{name}|{license_id}"
        triage_by_ref[component_ref] = TriageMetadata(
            spdx_id=license_id,
            tier=_optional_str(component.get("policy_tier")),
            origin=_optional_str(component.get("origin")),
            scope=_optional_str(component.get("scope")),
            distribution=_optional_str(component.get("distribution")),
            evidence_url=_optional_str(component.get("source_url")),
            evidence_anchor=None,
            found_in=_str_tuple(component.get("found_in")),
        )
    return ShortlistMetadata(triage_by_ref=triage_by_ref)


def triage_for_item(
    item: Mapping[str, Any],
    metadata: ShortlistMetadata,
) -> TriageMetadata:
    """Return safe metadata for ``item`` with shortlist evidence as the fallback."""

    component_ref = str(item.get("component_ref", ""))
    fallback = metadata.triage_by_ref.get(component_ref)
    evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
    spdx_id = _optional_str(item.get("candidate_spdx")) or _license_from_ref(component_ref)
    if fallback is None:
        return TriageMetadata(
            spdx_id=spdx_id,
            tier=_optional_str(item.get("reason")),
            origin=None,
            scope=None,
            distribution=None,
            evidence_url=_optional_str(evidence.get("url")),
            evidence_anchor=_optional_str(evidence.get("anchor")),
            found_in=(),
        )
    return TriageMetadata(
        spdx_id=spdx_id or fallback.spdx_id,
        tier=fallback.tier or _optional_str(item.get("reason")),
        origin=fallback.origin,
        scope=fallback.scope,
        distribution=fallback.distribution,
        evidence_url=_optional_str(evidence.get("url")) or fallback.evidence_url,
        evidence_anchor=_optional_str(evidence.get("anchor")) or fallback.evidence_anchor,
        found_in=fallback.found_in,
    )


def _license_from_ref(component_ref: str) -> str | None:
    if "|" not in component_ref:
        return None
    return _optional_str(component_ref.rsplit("|", 1)[1])


def _item_sort_key(item: Mapping[str, Any]) -> tuple[str, str]:
    value = str(item.get("component_ref", ""))
    return (value.casefold(), value)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted((str(item) for item in value), key=lambda item: (item.casefold(), item)))


__all__ = [
    "ShortlistMetadata",
    "TriageMetadata",
    "build_agent_request",
    "emit_contexts",
    "load_shortlist_metadata",
    "triage_for_item",
]
