"""Verify-don't-trust closure for agent-proposed resolutions.

Before any agent claim can influence an item the orchestrator re-fetches the cited evidence
URL through the SSRF-guarded :func:`repolens.security.http_client.fetch_url` and confirms the
fetched body exactly contains the claimed SPDX id or supported expression via
:func:`repolens.resolve.evidence.has_exact_license_evidence`. This reuses the resolve
stage's verification primitives (one home per concern) rather than reimplementing them.

The evidence host is validated against :data:`API_ALLOWED_HOSTS` — the frozen API allowlist,
**not** forked. ``API_ALLOWED_HOSTS`` does not include ``github.com`` /
``raw.githubusercontent.com``, so any raw blob/file evidence URL that P4 may have written is
intentionally treated as off-allowlist and fails closed (``VerifyOutcome.verified is False``
→ human queue), consistent with AC 15. A private-IP resolution behind an allowlisted host is
likewise blocked by ``validate_url_for_fetch``.
"""

from __future__ import annotations

from dataclasses import dataclass

from repolens.policy.config import load_default_policy
from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.resolve.evidence import has_exact_license_evidence
from repolens.resolve.license_expression import license_resolution_id
from repolens.resolve.models import ApiCandidate, FetchFunction
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import (
    HttpFetchOptions,
    Resolver,
    fetch_url,
    validate_url_for_fetch,
)
from repolens.shortlist.agent import Resolution


@dataclass(frozen=True, slots=True)
class VerifyOutcome:
    """Result of re-fetching and confirming an agent-proposed resolution."""

    verified: bool
    reason: str
    spdx_id: str | None = None
    evidence_url: str | None = None
    evidence_anchor: str | None = None


def _evidence_options() -> HttpFetchOptions:
    return HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})


def verify_agent_resolution(
    resolution: Resolution,
    *,
    fetcher: FetchFunction = fetch_url,
    resolver: Resolver | None = None,
) -> VerifyOutcome:
    """Re-fetch the cited evidence URL and confirm it exactly anchors the claim.

    Returns a fail-closed :class:`VerifyOutcome`: ``verified`` is ``True`` only when the
    SPDX id or expression is policy-supported, the URL is allowlisted and resolves to a
    public IP, the re-fetch succeeds, and ``has_exact_license_evidence`` confirms the
    claim. Every other path (bad SPDX, empty anchor, off-allowlist host, private IP,
    fetch failure, anchor
    mismatch) returns ``verified=False`` with a stated reason so the caller can route the
    item to the human queue.
    """

    policy = load_default_policy()
    spdx_id = license_resolution_id(resolution.spdx_id, policy)
    if spdx_id is None:
        return VerifyOutcome(verified=False, reason="verify:unrecognized_spdx")
    if not resolution.evidence_anchor:
        return VerifyOutcome(verified=False, reason="verify:empty_anchor")

    candidate = ApiCandidate(
        spdx_id=spdx_id,
        evidence_url=resolution.evidence_url,
        evidence_anchor=resolution.evidence_anchor,
    )
    options = _evidence_options()
    try:
        validate_url_for_fetch(candidate.evidence_url, options, resolver=resolver)
        result = fetcher(candidate.evidence_url, options)
    except FetchSecurityError:
        # Off-allowlist host, private-IP resolution, credentialed URL, or fetch failure all
        # fail closed to the human queue (AC 7, 15).
        return VerifyOutcome(verified=False, reason="verify:fetch_blocked_or_failed")

    if not has_exact_license_evidence(result.body, candidate, spdx_id):
        return VerifyOutcome(verified=False, reason="verify:anchor_mismatch")

    return VerifyOutcome(
        verified=True,
        reason="verify:exact_anchor",
        spdx_id=spdx_id,
        evidence_url=result.url,
        evidence_anchor=candidate.evidence_anchor,
    )


__all__ = ["VerifyOutcome", "verify_agent_resolution"]
