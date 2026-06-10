"""Disclosure-action policy loader and evaluator."""

from __future__ import annotations

import importlib.resources
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Literal

from repolens.data.validation import validate_artifact
from repolens.policy.config import Policy, load_default_policy
from repolens.policy.engine import classify_license_input
from repolens.policy.expression import EvalResult, ParseError, evaluate_expression
from repolens.policy.spdx import normalize_license
from repolens.policy.types import PolicyTier

PublicNotice = Literal["required", "not_required_by_default", "blocked", "unknown"]
BundledNotice = Literal["required", "not_required", "not_applicable", "unknown"]
InternalReview = Literal["record", "review", "escalate", "unknown"]
ReleaseGate = Literal["pass", "warn", "review", "block"]

_COMPOUND_PATTERN = re.compile(r"\b(AND|OR|WITH)\b|[()]", re.IGNORECASE)
_AND_SPLIT_PATTERN = re.compile(r"\bAND\b", re.IGNORECASE)
_BLOCKING_ACTION_VALUES = frozenset({"unknown"})
_GATE_ORDER: Mapping[ReleaseGate, int] = MappingProxyType(
    {"pass": 0, "warn": 1, "review": 2, "block": 3}
)


@dataclass(frozen=True, slots=True)
class DisclosureActions:
    public_notice: PublicNotice
    bundled_notice: BundledNotice
    internal_review: InternalReview
    release_gate: ReleaseGate
    rationale: str


@dataclass(frozen=True, slots=True)
class DisclosurePolicy:
    version: str
    contexts: frozenset[str]
    target_contexts: Mapping[str, str]
    delivery_state_contexts: Mapping[str, str]
    unscanned_delivery_gate: ReleaseGate
    entries: Mapping[str, Mapping[str, DisclosureActions]]


@dataclass(frozen=True, slots=True)
class DisclosureBlocked:
    reason_code: str
    message: str
    expression: str = ""
    context: str = ""


def context_for(
    target: str | None,
    delivery_state: str,
    policy: DisclosurePolicy,
) -> str | DisclosureBlocked:
    """Return the release disclosure context or a fail-closed blocker."""

    if target:
        context = policy.target_contexts.get(target)
        if context is None:
            return DisclosureBlocked(
                reason_code="unknown_context",
                message=f"release target {target!r} is not mapped by disclosure policy",
                context=target,
            )
    else:
        context = policy.delivery_state_contexts.get(delivery_state)
        if context is None:
            return DisclosureBlocked(
                reason_code="unknown_context",
                message=(f"delivery state {delivery_state!r} is not mapped by disclosure policy"),
                context=delivery_state,
            )
    if context not in policy.contexts:
        return DisclosureBlocked(
            reason_code="unknown_context",
            message=f"disclosure context {context!r} is not declared by policy",
            context=context,
        )
    return context


def evaluate_disclosure(
    expression: str,
    context: str,
    policy: DisclosurePolicy | None = None,
    tier_policy: Policy | None = None,
) -> DisclosureActions | DisclosureBlocked:
    """Evaluate disclosure actions for one SPDX expression and context.

    License-specific actions are resolved exclusively from policy data. Python only
    normalizes, parses, selects the risk-chosen OR branch, and combines AND actions.
    """

    active_policy = policy or load_default_disclosure_policy()
    active_tier_policy = tier_policy or load_default_policy()
    stripped = expression.strip()
    if context not in active_policy.contexts:
        return DisclosureBlocked(
            reason_code="unknown_context",
            message=f"disclosure context {context!r} is not declared by policy",
            expression=stripped,
            context=context,
        )

    exact = _lookup(stripped, context, active_policy)
    if isinstance(exact, DisclosureActions):
        return exact
    if isinstance(exact, DisclosureBlocked) and exact.reason_code == "unknown_action_value":
        return exact

    if not stripped or not _COMPOUND_PATTERN.search(stripped):
        normalized = normalize_license(stripped, active_tier_policy)
        if normalized.spdx_id is None:
            return DisclosureBlocked(
                reason_code="unknown_license_action",
                message=f"no disclosure action is modeled for license {stripped!r}",
                expression=stripped,
                context=context,
            )
        return _lookup_or_block(normalized.spdx_id, context, active_policy, stripped)

    if "WITH" in stripped.upper():
        return DisclosureBlocked(
            reason_code="irreducible_expression",
            message=(f"SPDX expression {stripped!r} uses WITH but has no exact disclosure entry"),
            expression=stripped,
            context=context,
        )

    try:
        _validate_parse(stripped, active_tier_policy)
    except ParseError:
        return DisclosureBlocked(
            reason_code="irreducible_expression",
            message=f"SPDX expression {stripped!r} could not be parsed",
            expression=stripped,
            context=context,
        )

    if _has_or(stripped) and _has_and(stripped):
        return DisclosureBlocked(
            reason_code="irreducible_expression",
            message=(
                f"SPDX expression {stripped!r} mixes AND/OR without an exact disclosure entry"
            ),
            expression=stripped,
            context=context,
        )

    if _has_or(stripped):
        decision = classify_license_input(stripped, active_tier_policy)
        if not decision.chosen_branch:
            return DisclosureBlocked(
                reason_code="irreducible_expression",
                message=f"SPDX expression {stripped!r} has no risk-chosen OR branch",
                expression=stripped,
                context=context,
            )
        return evaluate_disclosure(
            decision.chosen_branch, context, active_policy, active_tier_policy
        )

    parts = [part.strip(" ()") for part in _AND_SPLIT_PATTERN.split(stripped) if part.strip(" ()")]
    if not parts:
        return DisclosureBlocked(
            reason_code="irreducible_expression",
            message=f"SPDX expression {stripped!r} could not be reduced to AND leaves",
            expression=stripped,
            context=context,
        )
    actions: list[DisclosureActions] = []
    for part in parts:
        evaluated = evaluate_disclosure(part, context, active_policy, active_tier_policy)
        if isinstance(evaluated, DisclosureBlocked):
            return evaluated
        actions.append(evaluated)
    return _combine_and(actions)


@lru_cache(maxsize=1)
def load_default_disclosure_policy() -> DisclosurePolicy:
    data_path = importlib.resources.files("repolens.policy.data").joinpath(
        "disclosure-policy.default.json"
    )
    raw = json.loads(data_path.read_text(encoding="utf-8"))
    validate_artifact(raw, "disclosure_policy")
    return disclosure_policy_from_dict(raw)


def disclosure_policy_from_dict(raw: Mapping[str, object]) -> DisclosurePolicy:
    validate_artifact(raw, "disclosure_policy")
    contexts = frozenset(str(item) for item in raw["contexts"])
    profiles = raw["action_profiles"]
    if not isinstance(profiles, Mapping):
        raise ValueError("disclosure policy action_profiles must be an object")

    entries: dict[str, Mapping[str, DisclosureActions]] = {}
    raw_entries = raw["entries"]
    if not isinstance(raw_entries, Mapping):
        raise ValueError("disclosure policy entries must be an object")
    for expression, entry in raw_entries.items():
        if not isinstance(entry, Mapping):
            raise ValueError(f"disclosure entry {expression} must be an object")
        context_map = entry.get("contexts")
        if context_map is None:
            profile_name = entry.get("profile")
            if not isinstance(profile_name, str) or profile_name not in profiles:
                raise ValueError(f"disclosure entry {expression} references unknown profile")
            context_map = profiles[profile_name]
        if not isinstance(context_map, Mapping):
            raise ValueError(f"disclosure entry {expression} contexts must be an object")
        actions_by_context = {
            str(context): _actions_from_mapping(action_data)
            for context, action_data in context_map.items()
        }
        entries[str(expression)] = MappingProxyType(actions_by_context)

    return DisclosurePolicy(
        version=str(raw["disclosure_policy_version"]),
        contexts=contexts,
        target_contexts=MappingProxyType(
            {str(key): str(value) for key, value in dict(raw["target_contexts"]).items()}
        ),
        delivery_state_contexts=MappingProxyType(
            {str(key): str(value) for key, value in dict(raw["delivery_state_contexts"]).items()}
        ),
        unscanned_delivery_gate=str(raw["unscanned_delivery_gate"]),  # type: ignore[arg-type]
        entries=MappingProxyType(entries),
    )


def _actions_from_mapping(value: object) -> DisclosureActions:
    if not isinstance(value, Mapping):
        raise ValueError("disclosure actions must be an object")
    return DisclosureActions(
        public_notice=str(value["public_notice"]),  # type: ignore[arg-type]
        bundled_notice=str(value["bundled_notice"]),  # type: ignore[arg-type]
        internal_review=str(value["internal_review"]),  # type: ignore[arg-type]
        release_gate=str(value["release_gate"]),  # type: ignore[arg-type]
        rationale=str(value["rationale"]),
    )


def _lookup_or_block(
    expression: str,
    context: str,
    policy: DisclosurePolicy,
    original: str,
) -> DisclosureActions | DisclosureBlocked:
    result = _lookup(expression, context, policy)
    if isinstance(result, DisclosureActions):
        return result
    return DisclosureBlocked(
        reason_code=result.reason_code,
        message=result.message,
        expression=original,
        context=context,
    )


def _lookup(
    expression: str,
    context: str,
    policy: DisclosurePolicy,
) -> DisclosureActions | DisclosureBlocked:
    context_actions = policy.entries.get(expression)
    if context_actions is None:
        return DisclosureBlocked(
            reason_code="unknown_license_action",
            message=f"no disclosure action is modeled for license {expression!r}",
            expression=expression,
            context=context,
        )
    actions = context_actions.get(context)
    if actions is None:
        return DisclosureBlocked(
            reason_code="unknown_context",
            message=(f"license {expression!r} has no disclosure action for context {context!r}"),
            expression=expression,
            context=context,
        )
    if (
        actions.public_notice in _BLOCKING_ACTION_VALUES
        or actions.bundled_notice in _BLOCKING_ACTION_VALUES
        or actions.internal_review in _BLOCKING_ACTION_VALUES
    ):
        return DisclosureBlocked(
            reason_code="unknown_action_value",
            message=f"license {expression!r} has an unknown disclosure action in {context!r}",
            expression=expression,
            context=context,
        )
    return actions


def _validate_parse(expression: str, policy: Policy) -> None:
    def mapper(leaf_id: str, exception_id: str | None) -> EvalResult:
        normalized = normalize_license(leaf_id, policy)
        if normalized.spdx_id is None:
            return EvalResult(
                tier=PolicyTier.UNKNOWN,
                chosen_branch=None,
                label=leaf_id,
                reasons=(normalized.reason,),
            )
        return EvalResult(
            tier=PolicyTier.ALLOW,
            chosen_branch=None,
            label=normalized.spdx_id,
        )

    evaluate_expression(expression, mapper)


def _has_or(expression: str) -> bool:
    # The current policy only needs pure OR and pure AND chains. If OR is present,
    # defer branch selection to the tier engine and fail closed if it cannot choose.
    return bool(re.search(r"\bOR\b", expression, flags=re.IGNORECASE))


def _has_and(expression: str) -> bool:
    return bool(re.search(r"\bAND\b", expression, flags=re.IGNORECASE))


def _combine_and(actions: list[DisclosureActions]) -> DisclosureActions | DisclosureBlocked:
    if not actions:
        return DisclosureBlocked("irreducible_expression", "AND expression has no leaves")
    release_gate = max((item.release_gate for item in actions), key=lambda gate: _GATE_ORDER[gate])
    public_notice: PublicNotice = (
        "blocked"
        if any(item.public_notice == "blocked" for item in actions)
        else "required"
        if any(item.public_notice == "required" for item in actions)
        else "not_required_by_default"
    )
    bundled_notice: BundledNotice = (
        "required"
        if any(item.bundled_notice == "required" for item in actions)
        else "not_required"
        if any(item.bundled_notice == "not_required" for item in actions)
        else "not_applicable"
    )
    internal_review: InternalReview = (
        "escalate"
        if any(item.internal_review == "escalate" for item in actions)
        else "review"
        if any(item.internal_review == "review" for item in actions)
        else "record"
    )
    return DisclosureActions(
        public_notice=public_notice,
        bundled_notice=bundled_notice,
        internal_review=internal_review,
        release_gate=release_gate,
        rationale="; ".join(dict.fromkeys(item.rationale for item in actions)),
    )
