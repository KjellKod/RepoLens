"""Evidence checks shared by resolve orchestration and canaries."""

from __future__ import annotations

from repolens.policy.config import Policy, load_default_policy
from repolens.policy.expression import ExpressionFingerprint
from repolens.policy.spdx import normalize_license
from repolens.resolve.adapters import target_license_candidates
from repolens.resolve.license_expression import expression_fingerprint
from repolens.resolve.models import ApiCandidate, PackageFact
from repolens.resolve.purl import package_identity

UNKNOWN_VERSION = "unknown"


def should_attempt_api_resolution(package: PackageFact) -> bool:
    """Return whether a package has enough metadata for versioned API resolution."""

    if package.version != UNKNOWN_VERSION:
        return True
    ecosystem, _package_name = package_identity(package.package_type, package.name, package.purl)
    return ecosystem in {"python", "pypi"}


def has_exact_license_evidence(
    body: bytes, candidate: ApiCandidate, normalized_spdx_id: str
) -> bool:
    """Return true when structured target evidence exactly confirms the candidate."""

    policy = load_default_policy()
    license_texts = target_license_candidates(body)
    normalized = normalize_license(normalized_spdx_id, policy)
    if normalized.spdx_id is not None:
        for license_text in license_texts:
            target = normalize_license(license_text, policy)
            if target.spdx_id == normalized.spdx_id and license_text == candidate.evidence_anchor:
                return True
        return False

    expected = _expression_fingerprint(normalized_spdx_id, policy)
    anchor = _expression_fingerprint(candidate.evidence_anchor, policy)
    if expected is None or anchor != expected:
        return False

    for license_text in license_texts:
        if _expression_fingerprint(license_text, policy) == expected:
            return True
    return False


def _expression_fingerprint(expression: str, policy: Policy) -> ExpressionFingerprint | None:
    return expression_fingerprint(expression, policy)
