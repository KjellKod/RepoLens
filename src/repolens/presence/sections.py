"""Presence section taxonomy shared by shortlist and report rendering."""

from __future__ import annotations

from collections.abc import Mapping

from repolens.presence.models import Presence

DELIVERED_SECTION = "DELIVERED / SHIPPED - ACTION REQUIRED"
INSTALLED_REVIEW_SECTION = "INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW"
LOCKFILE_MONITOR_SECTION = "LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR"
NOT_SCANNED_UNKNOWN_SECTION = "DELIVERY ARTIFACT NOT SCANNED - UNKNOWN"
PRESENCE_SECTIONS = (
    DELIVERED_SECTION,
    INSTALLED_REVIEW_SECTION,
    LOCKFILE_MONITOR_SECTION,
    NOT_SCANNED_UNKNOWN_SECTION,
)
MONITOR_APPENDIX_LABEL = "not-currently-delivered"

_MONITOR_RELATIONS = frozenset({"optional", "devOptional", "peer"})


def section_for_presence(presence: Presence | Mapping[str, object] | None) -> str:
    """Map a presence block to the operator-facing shortlist section."""

    data = _presence_dict(presence)
    delivery_state = str(data.get("delivery_state") or "unknown")
    install_state = str(data.get("install_state") or "unknown")
    relation = str(data.get("relation") or "unknown")
    if delivery_state == "delivered":
        return DELIVERED_SECTION
    if delivery_state == "not_delivered" or install_state == "lockfile_only":
        return LOCKFILE_MONITOR_SECTION
    if relation in _MONITOR_RELATIONS and install_state == "not_installed":
        return LOCKFILE_MONITOR_SECTION
    if install_state == "installed" and delivery_state == "not_scanned":
        return INSTALLED_REVIEW_SECTION
    return NOT_SCANNED_UNKNOWN_SECTION


def routes_to_monitor_appendix(presence: Presence | Mapping[str, object] | None) -> bool:
    if presence is None:
        return False
    return section_for_presence(presence) in {
        LOCKFILE_MONITOR_SECTION,
        NOT_SCANNED_UNKNOWN_SECTION,
    }


def _presence_dict(presence: Presence | Mapping[str, object] | None) -> Mapping[str, object]:
    if isinstance(presence, Presence):
        return presence.to_dict()
    if isinstance(presence, Mapping):
        return presence
    return {}
