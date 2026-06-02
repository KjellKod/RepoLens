"""Evidence checks shared by resolve orchestration and canaries."""

from __future__ import annotations

from repolens.policy.config import load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.adapters import target_license_candidates
from repolens.resolve.models import ApiCandidate, PackageFact

UNKNOWN_VERSION = "unknown"


def should_attempt_api_resolution(package: PackageFact) -> bool:
    """Return whether a package has enough metadata for versioned API resolution."""

    return package.version != UNKNOWN_VERSION


def has_exact_license_evidence(
    body: bytes, candidate: ApiCandidate, normalized_spdx_id: str
) -> bool:
    """Return true when structured target evidence exactly confirms the candidate."""

    policy = load_default_policy()
    for license_text in target_license_candidates(body):
        normalized = normalize_license(license_text, policy)
        if normalized.spdx_id == normalized_spdx_id and license_text == candidate.evidence_anchor:
            return True
    return False
