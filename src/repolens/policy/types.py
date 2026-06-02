"""Core types for the policy engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PolicyTier(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class Action(str, Enum):
    PASS = "PASS"
    FLAG = "FLAG"
    FLAG_HARD = "FLAG_HARD"


@dataclass(frozen=True)
class NormalizationResult:
    spdx_id: str | None
    matched_pattern: str | None
    tier_override: PolicyTier | None
    reason: str


@dataclass(frozen=True)
class PolicyDecision:
    tier: PolicyTier
    effective_tier: PolicyTier
    action: Action
    reasons: tuple[str, ...]
    caveats: tuple[str, ...]
    chosen_branch: str | None
    dual_license_detected: bool
    policy_version: str
