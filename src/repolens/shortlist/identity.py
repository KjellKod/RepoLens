"""Stable shortlist decision identities."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from repolens.presence.sections import section_for_presence

_DECISION_REF_SEPARATOR = " :: presence="


def build_decision_ref(component_ref: str, presence_section: str | None) -> str:
    """Return the stable decision key for a component within one presence section."""

    section = _non_empty(presence_section)
    if section is None:
        return component_ref
    return f"{component_ref}{_DECISION_REF_SEPARATOR}{section}"


def decision_ref_for_item(item: Mapping[str, Any]) -> str:
    """Return an item's decision key, deriving one for older shortlist artifacts."""

    explicit = _non_empty(item.get("decision_ref"))
    if explicit is not None:
        return explicit
    component_ref = str(item.get("component_ref", ""))
    presence_section = _non_empty(item.get("presence_section"))
    if presence_section is None and isinstance(item.get("presence"), Mapping):
        presence_section = section_for_presence(item.get("presence"))
    return build_decision_ref(component_ref, presence_section)


def _non_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = ["build_decision_ref", "decision_ref_for_item"]
