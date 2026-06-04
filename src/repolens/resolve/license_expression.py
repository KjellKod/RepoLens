"""License expression helpers for resolve admission and evidence matching."""

from __future__ import annotations

from repolens.policy.config import Policy
from repolens.policy.expression import ExpressionFingerprint, ParseError, fingerprint_expression
from repolens.policy.spdx import normalize_license


def license_resolution_id(raw_license: str, policy: Policy) -> str | None:
    """Return a single SPDX id or policy-supported SPDX expression for resolve."""

    stripped = raw_license.strip()
    normalized = normalize_license(stripped, policy)
    if normalized.spdx_id is not None:
        return normalized.spdx_id

    if expression_fingerprint(stripped, policy) is None:
        return None
    return stripped


def expression_fingerprint(expression: str, policy: Policy) -> ExpressionFingerprint | None:
    """Return a structural expression fingerprint using policy-supported exceptions."""

    try:
        return fingerprint_expression(
            expression,
            leaf_normalizer=lambda leaf: normalize_license(leaf, policy).spdx_id,
            exception_normalizer=lambda license_id, exception: _normalize_exception(
                license_id, exception, policy
            ),
        )
    except ParseError:
        return None


def _normalize_exception(license_id: str, exception: str, policy: Policy) -> str | None:
    stripped = exception.strip()
    if not stripped:
        return None
    if (license_id, stripped) in policy.exception_tiers:
        return stripped
    if (None, stripped) in policy.exception_tiers:
        return stripped
    return None
