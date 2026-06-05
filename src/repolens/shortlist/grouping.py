"""Grouped shortlist tiers and provenance helpers."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from repolens.policy import PolicyTier, classify_license_input
from repolens.shortlist.contexts import ShortlistMetadata, triage_for_item

ACCEPT_RECOMMENDED = "ACCEPT-RECOMMENDED"
NEEDS_JUDGMENT = "NEEDS-JUDGMENT"
LOW_CONFIDENCE = "LOW-CONFIDENCE / CONFLICT"
TIER_ORDER = (ACCEPT_RECOMMENDED, NEEDS_JUDGMENT, LOW_CONFIDENCE)

_UNKNOWN = "unknown"
_PERMISSIVE_FAMILIES = frozenset(
    {
        "0BSD",
        "Apache",
        "Artistic",
        "BSD",
        "BSL",
        "BlueOak",
        "CC0",
        "HPND",
        "ISC",
        "Libpng",
        "MIT",
        "MIT-0",
        "PSF",
        "Python",
        "Unlicense",
        "W3C",
        "X11",
        "Zlib",
        "curl",
    }
)
_VERSION_SUFFIX_RE = re.compile(r"-(?:v)?\d+(?:\.\d+)*(?:-(?:only|or-later))?$", re.I)
_COPYLEFT_VERSION_RE = re.compile(
    r"^(?P<family>AGPL|LGPL|GPL|SSPL|BUSL)-(?P<version>\d+(?:\.\d+)*)(?:-(?:only|or-later))?$",
    re.I,
)


@dataclass(frozen=True, slots=True)
class GroupKey:
    spdx_family: str
    distribution: str
    scope: str

    def encoded(self) -> str:
        return encode_group_key(self)


@dataclass(frozen=True, slots=True)
class ShortlistGroup:
    key: GroupKey
    tier: str
    items: tuple[Mapping[str, Any], ...]
    bulk_decision: bool
    component_refs: tuple[str, ...]
    found_in: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GroupMembership:
    key: GroupKey
    component_refs: tuple[str, ...]
    found_in: tuple[str, ...]


def build_groups(
    items: Sequence[Mapping[str, Any]],
    metadata: ShortlistMetadata,
) -> tuple[ShortlistGroup, ...]:
    buckets: dict[GroupKey, list[Mapping[str, Any]]] = {}
    for item in items:
        key = group_key_for_item(item, metadata)
        buckets.setdefault(key, []).append(item)

    groups = [
        _build_group(key, tuple(sorted(group_items, key=_item_sort_key)), metadata)
        for key, group_items in buckets.items()
    ]
    return tuple(sorted(groups, key=_group_sort_key))


def group_membership_by_ref(
    groups: Sequence[ShortlistGroup],
) -> dict[str, GroupMembership]:
    memberships: dict[str, GroupMembership] = {}
    for group in groups:
        membership = GroupMembership(
            key=group.key,
            component_refs=group.component_refs,
            found_in=group.found_in,
        )
        for component_ref in group.component_refs:
            memberships[component_ref] = membership
    return memberships


def group_key_for_item(item: Mapping[str, Any], metadata: ShortlistMetadata) -> GroupKey:
    triage = triage_for_item(item, metadata)
    spdx_id = triage.spdx_id or _license_from_ref(str(item.get("component_ref", ""))) or _UNKNOWN
    return GroupKey(
        spdx_family=spdx_family(spdx_id),
        distribution=triage.distribution or _UNKNOWN,
        scope=triage.scope or _UNKNOWN,
    )


def encode_group_key(key: GroupKey) -> str:
    payload = {
        "spdx_family": key.spdx_family,
        "distribution": key.distribution,
        "scope": key.scope,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_group_key(encoded: str) -> GroupKey | None:
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding)
        payload = json.loads(raw)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    spdx_family = _non_empty(payload.get("spdx_family"))
    distribution = _non_empty(payload.get("distribution"))
    scope = _non_empty(payload.get("scope"))
    if spdx_family is None or distribution is None or scope is None:
        return None
    return GroupKey(spdx_family=spdx_family, distribution=distribution, scope=scope)


def spdx_family(spdx_id: str) -> str:
    text = spdx_id.strip()
    if not text:
        return _UNKNOWN
    upper = text.upper()
    for prefix in ("AGPL", "LGPL", "GPL", "SSPL", "BUSL"):
        if upper == prefix:
            return prefix
    if match := _COPYLEFT_VERSION_RE.match(text):
        return f"{match.group('family').upper()}-{match.group('version')}"
    if upper.startswith("MIT-0"):
        return "MIT-0"
    if upper == "MIT":
        return "MIT"
    if upper.startswith("BSD-"):
        return "BSD"
    family = _VERSION_SUFFIX_RE.sub("", text)
    return family or text


def is_low_confidence(item: Mapping[str, Any]) -> bool:
    reason = str(item.get("reason") or "")
    note = str(item.get("note") or "")
    if reason == "CONFLICT":
        return True
    if note.startswith(("verify_failed", "proposal:invalid", "agent:abstained")):
        return True
    research = item.get("research_evidence")
    if isinstance(research, Mapping):
        outcome = str(research.get("outcome") or "")
        machine_verification = str(research.get("machine_verification") or "")
        if outcome in {"conflict", "no_public_evidence"}:
            return True
        if machine_verification in {"conflict", "no_public_evidence"}:
            return True
    suggestion = item.get("ai_suggestion")
    if isinstance(suggestion, Mapping):
        if suggestion.get("abstain"):
            return True
        confidence = suggestion.get("confidence")
        if isinstance(confidence, int | float) and not isinstance(confidence, bool):
            return confidence < 0.7
        if isinstance(confidence, str):
            normalized_confidence = confidence.strip().lower()
            try:
                return float(normalized_confidence) < 0.7
            except ValueError:
                return normalized_confidence in {"low", "weak", "uncertain"}
    return False


def is_verified_allow(item: Mapping[str, Any]) -> bool:
    if item.get("status") != "open":
        return False
    if str(item.get("note") or "") != "agent:verified_awaiting_human":
        return False
    spdx_id = _non_empty(item.get("candidate_spdx"))
    if spdx_id is None:
        return False
    suggestion = item.get("ai_suggestion")
    if isinstance(suggestion, Mapping):
        disposition = _non_empty(suggestion.get("disposition"))
        if disposition is not None and disposition.casefold() != "allow":
            return False
    decision = classify_license_input(spdx_id)
    return decision.tier == PolicyTier.ALLOW


def is_low_risk_group(key: GroupKey) -> bool:
    return key.distribution == "not-distributed" or key.spdx_family in _PERMISSIVE_FAMILIES


def _build_group(
    key: GroupKey,
    items: tuple[Mapping[str, Any], ...],
    metadata: ShortlistMetadata,
) -> ShortlistGroup:
    component_refs = tuple(str(item.get("component_ref", "")) for item in items)
    found_in = _group_found_in(items, metadata)
    if any(is_low_confidence(item) for item in items):
        tier = LOW_CONFIDENCE
        bulk_decision = False
    elif items and all(is_verified_allow(item) for item in items) and is_low_risk_group(key):
        tier = ACCEPT_RECOMMENDED
        bulk_decision = True
    else:
        tier = NEEDS_JUDGMENT
        bulk_decision = False
    return ShortlistGroup(
        key=key,
        tier=tier,
        items=items,
        bulk_decision=bulk_decision,
        component_refs=component_refs,
        found_in=found_in,
    )


def _group_found_in(
    items: Sequence[Mapping[str, Any]],
    metadata: ShortlistMetadata,
) -> tuple[str, ...]:
    repos: set[str] = set()
    for item in items:
        repos.update(triage_for_item(item, metadata).found_in)
    return tuple(sorted(repos, key=lambda value: (value.casefold(), value)))


def _license_from_ref(component_ref: str) -> str | None:
    if "|" not in component_ref:
        return None
    return _non_empty(component_ref.rsplit("|", 1)[1])


def _non_empty(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _item_sort_key(item: Mapping[str, Any]) -> tuple[str, str]:
    value = str(item.get("component_ref", ""))
    return (value.casefold(), value)


def _group_sort_key(group: ShortlistGroup) -> tuple[int, str, str, str]:
    return (
        TIER_ORDER.index(group.tier),
        group.key.spdx_family.casefold(),
        group.key.distribution.casefold(),
        group.key.scope.casefold(),
    )


__all__ = [
    "ACCEPT_RECOMMENDED",
    "LOW_CONFIDENCE",
    "NEEDS_JUDGMENT",
    "GroupKey",
    "GroupMembership",
    "ShortlistGroup",
    "TIER_ORDER",
    "build_groups",
    "decode_group_key",
    "encode_group_key",
    "group_membership_by_ref",
    "group_key_for_item",
    "is_low_confidence",
    "is_verified_allow",
    "spdx_family",
]
