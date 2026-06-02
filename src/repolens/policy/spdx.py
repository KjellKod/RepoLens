"""SPDX normalization for policy lookups."""

from __future__ import annotations

from repolens.policy.config import Policy
from repolens.policy.types import NormalizationResult, PolicyTier


def _canonical_ids(policy: Policy) -> dict[str, str]:
    ids = policy.allow_ids | policy.review_ids | policy.block_ids | policy.deprecated_ids
    return {license_id.lower(): license_id for license_id in ids}


def normalize_license(raw: str, policy: Policy) -> NormalizationResult:
    text = raw.strip()
    if not text:
        return NormalizationResult(
            spdx_id=None,
            matched_pattern=None,
            tier_override=None,
            reason="empty_input",
        )

    upper_text = text.upper()
    if upper_text in policy.unknown_literals:
        return NormalizationResult(
            spdx_id=None,
            matched_pattern=None,
            tier_override=None,
            reason="unknown_literal",
        )

    canonical_ids = _canonical_ids(policy)
    canonical_hit = canonical_ids.get(text.lower())
    if canonical_hit is not None:
        if canonical_hit in policy.deprecated_ids:
            return NormalizationResult(
                spdx_id=None,
                matched_pattern=None,
                tier_override=None,
                reason="deprecated_id",
            )
        return NormalizationResult(
            spdx_id=canonical_hit,
            matched_pattern=None,
            tier_override=None,
            reason="canonical_id",
        )

    alias_hit = policy.alias_map.get(text.lower())
    if alias_hit is not None:
        if alias_hit in policy.deprecated_ids:
            return NormalizationResult(
                spdx_id=None,
                matched_pattern=None,
                tier_override=None,
                reason="deprecated_id",
            )
        return NormalizationResult(
            spdx_id=alias_hit,
            matched_pattern=None,
            tier_override=None,
            reason="alias_hit",
        )

    if text.endswith("+"):
        maybe_or_later = f"{text[:-1]}-or-later"
        canonical_or_later = canonical_ids.get(maybe_or_later.lower())
        if canonical_or_later is not None and canonical_or_later not in policy.deprecated_ids:
            return NormalizationResult(
                spdx_id=canonical_or_later,
                matched_pattern=None,
                tier_override=None,
                reason="legacy_plus",
            )

    for entry in policy.non_spdx_patterns:
        if entry.pattern.search(text):
            return NormalizationResult(
                spdx_id=None,
                matched_pattern=f"non_spdx:{entry.name}",
                tier_override=PolicyTier.BLOCK,
                reason="non_spdx_restrictive",
            )

    return NormalizationResult(
        spdx_id=None,
        matched_pattern=None,
        tier_override=None,
        reason="freeform_unknown",
    )
