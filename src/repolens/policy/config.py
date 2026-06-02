"""Policy configuration loader."""

from __future__ import annotations

import importlib.resources
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType

from repolens.policy.types import PolicyTier


@dataclass(frozen=True)
class NonSpdxPattern:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Policy:
    policy_version: str
    default_unknown_action: PolicyTier
    allow_ids: frozenset[str]
    review_ids: frozenset[str]
    block_ids: frozenset[str]
    alias_map: Mapping[str, str]
    deprecated_ids: frozenset[str]
    unknown_literals: frozenset[str]
    non_spdx_patterns: tuple[NonSpdxPattern, ...]
    exception_tiers: Mapping[tuple[str | None, str], PolicyTier]
    caveats: Mapping[str, str]


def _to_tier(value: str) -> PolicyTier:
    try:
        return PolicyTier[value.strip().upper()]
    except KeyError as exc:
        raise ValueError(f"Unsupported policy tier: {value!r}") from exc


def _load_json() -> dict[str, object]:
    data_path = importlib.resources.files("repolens.policy.data").joinpath(
        "license-policy.default.json"
    )
    return json.loads(data_path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_default_policy() -> Policy:
    raw = _load_json()
    tiers = raw["tiers"]

    non_spdx_patterns = tuple(
        NonSpdxPattern(
            name=entry["name"],
            pattern=re.compile(entry["pattern"]),
        )
        for entry in raw["non_spdx_patterns"]
    )

    exception_tiers: dict[tuple[str | None, str], PolicyTier] = {}
    for entry in raw["exception_table"]:
        key = (entry["license_id"], entry["exception_id"])
        exception_tiers[key] = _to_tier(entry["target_tier"])

    return Policy(
        policy_version=raw["policy_version"],
        default_unknown_action=_to_tier(raw["default_unknown_action"]),
        allow_ids=frozenset(tiers["ALLOW"]),
        review_ids=frozenset(tiers["REVIEW"]),
        block_ids=frozenset(tiers["BLOCK"]),
        alias_map=MappingProxyType({key.lower(): value for key, value in raw["aliases"].items()}),
        deprecated_ids=frozenset(raw["deprecated_ids"]),
        unknown_literals=frozenset(value.upper() for value in raw["unknown_literals"]),
        non_spdx_patterns=non_spdx_patterns,
        exception_tiers=MappingProxyType(exception_tiers),
        caveats=MappingProxyType(dict(raw["caveats"])),
    )
