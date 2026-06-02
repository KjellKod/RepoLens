"""Pure policy engine entrypoints."""

from __future__ import annotations

import re

from repolens.policy.config import Policy, load_default_policy
from repolens.policy.expression import EvalResult, ParseError, evaluate_expression
from repolens.policy.spdx import normalize_license
from repolens.policy.tiers import (
    action_for_tier,
    caveats_for_license,
    coerce_effective_tier,
    map_license_to_tier,
)
from repolens.policy.types import PolicyDecision, PolicyTier

_COMPOUND_PATTERN = re.compile(r"\b(AND|OR|WITH)\b|[()]", re.IGNORECASE)


def _resolve_leaf(
    raw_leaf: str, policy: Policy, *, exception_id: str | None = None
) -> tuple[PolicyTier, tuple[str, ...], str | None, tuple[str, ...]]:
    normalized = normalize_license(raw_leaf, policy)
    reasons: list[str] = [normalized.reason]
    if normalized.matched_pattern:
        reasons.append(normalized.matched_pattern)

    if normalized.tier_override is not None:
        return normalized.tier_override, tuple(reasons), None, tuple()

    if exception_id is not None:
        normalized_exception = normalize_license(exception_id, policy)
        if normalized_exception.tier_override is not None:
            exception_reasons = list(reasons)
            exception_reasons.append(normalized_exception.reason)
            if normalized_exception.matched_pattern:
                exception_reasons.append(normalized_exception.matched_pattern)
            return normalized_exception.tier_override, tuple(exception_reasons), None, tuple()

    tier = map_license_to_tier(normalized.spdx_id, policy, exception_id=exception_id)
    return (
        tier,
        tuple(reasons),
        normalized.spdx_id,
        caveats_for_license(normalized.spdx_id, policy),
    )


def classify_license_input(raw: str, policy: Policy | None = None) -> PolicyDecision:
    active_policy = policy or load_default_policy()
    stripped = raw.strip()

    reasons: list[str] = []
    caveats: list[str] = []
    chosen_branch: str | None = None
    dual_license_detected = False
    full_text_normalized = normalize_license(stripped, active_policy)
    is_compound_expression = bool(stripped and _COMPOUND_PATTERN.search(stripped))

    if full_text_normalized.tier_override is not None and not is_compound_expression:
        reasons.append(full_text_normalized.reason)
        if full_text_normalized.matched_pattern:
            reasons.append(full_text_normalized.matched_pattern)
        tier = full_text_normalized.tier_override

    elif is_compound_expression:
        def mapper(leaf_id: str, exception_id: str | None) -> EvalResult:
            tier, leaf_reasons, normalized_id, leaf_caveats = _resolve_leaf(
                leaf_id, active_policy, exception_id=exception_id
            )
            return EvalResult(
                tier=tier,
                chosen_branch=None,
                label=normalized_id or leaf_id,
                reasons=leaf_reasons,
                caveats=leaf_caveats,
            )

        try:
            eval_result = evaluate_expression(stripped, mapper)
            tier = eval_result.tier
            chosen_branch = eval_result.chosen_branch
            dual_license_detected = chosen_branch is not None
            reasons.extend(eval_result.reasons)
            reasons.append("compound_expression")
            caveats.extend(eval_result.caveats)
        except ParseError:
            if full_text_normalized.tier_override is not None:
                reasons.append(full_text_normalized.reason)
                if full_text_normalized.matched_pattern:
                    reasons.append(full_text_normalized.matched_pattern)
                tier = full_text_normalized.tier_override
            else:
                tier = PolicyTier.UNKNOWN
                reasons.append("parse_error")
            reasons.append("compound_expression")
    else:
        tier, leaf_reasons, _normalized_id, leaf_caveats = _resolve_leaf(
            stripped, active_policy
        )
        reasons.extend(leaf_reasons)
        caveats.extend(leaf_caveats)

    effective_tier = coerce_effective_tier(tier, active_policy.default_unknown_action)
    action = action_for_tier(effective_tier)

    return PolicyDecision(
        tier=tier,
        effective_tier=effective_tier,
        action=action,
        reasons=tuple(reasons),
        caveats=tuple(caveats),
        chosen_branch=chosen_branch,
        dual_license_detected=dual_license_detected,
        policy_version=active_policy.policy_version,
    )
