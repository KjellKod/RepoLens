"""Verify-don't-trust closure for agent-proposed resolutions.

Before any agent claim can influence an item the orchestrator re-fetches the cited evidence
URL through the SSRF-guarded :func:`repolens.security.http_client.fetch_url` and confirms the
fetched body exactly contains the claimed SPDX id or supported expression via
:func:`repolens.resolve.evidence.has_exact_license_evidence`. This reuses the resolve
stage's verification primitives (one home per concern) rather than reimplementing them.

The evidence host is validated against :data:`API_ALLOWED_HOSTS` — the frozen API allowlist,
**not** forked. ``API_ALLOWED_HOSTS`` includes public metadata hosts and the raw GitHub
host used by CocoaPods trunk redirects, but agent proposals may cite raw GitHub only for
CocoaPods Specs podspec JSON evidence. Repository browsing hosts such as ``github.com``
remain off-allowlist. A private-IP resolution behind an allowlisted host is likewise
blocked by ``validate_url_for_fetch``.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

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

_MUTABLE_GITHUB_REFS = frozenset({"main", "master", "develop", "development", "trunk", "default"})


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
    expected_ref: str | None = None,
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
    if _github_license_api_missing_ref(resolution.evidence_url):
        return VerifyOutcome(verified=False, reason="verify:missing_ref")
    github_ref_reason = _github_license_api_ref_mismatch(
        resolution.evidence_url,
        expected_ref=expected_ref,
    )
    if github_ref_reason is not None:
        return VerifyOutcome(verified=False, reason=github_ref_reason)

    candidate = ApiCandidate(
        spdx_id=spdx_id,
        evidence_url=resolution.evidence_url,
        evidence_anchor=resolution.evidence_anchor,
    )
    if not _proposal_evidence_url_allowed(candidate.evidence_url):
        return VerifyOutcome(verified=False, reason="verify:fetch_blocked_or_failed")
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


def _proposal_evidence_url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname != "raw.githubusercontent.com":
        return True
    return parsed.path.startswith("/CocoaPods/Specs/") and parsed.path.endswith(".podspec.json")


def _github_license_api_missing_ref(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname != "api.github.com":
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[0] != "repos" or parts[3] != "license":
        return False
    refs = parse_qs(parsed.query).get("ref", [])
    return not any(ref.strip() for ref in refs)


def _github_license_api_ref_mismatch(url: str, *, expected_ref: str | None) -> str | None:
    expected = _clean_ref(expected_ref)
    if expected is None:
        return None
    parsed = urlparse(url)
    if parsed.hostname != "api.github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 4 or parts[0] != "repos" or parts[3] != "license":
        return None
    refs = [ref.strip() for ref in parse_qs(parsed.query).get("ref", []) if ref.strip()]
    if not refs:
        return "verify:missing_ref"
    ref = refs[0]
    if _is_immutable_sha(ref):
        return None
    if ref.casefold() in _MUTABLE_GITHUB_REFS:
        return "verify:default_branch_rejected"
    if ref not in _acceptable_refs(expected):
        return "verify:ref_mismatch"
    return None


def _clean_ref(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text or text.casefold() in {"unknown", "declared-unpinned"}:
        return None
    return text


def _acceptable_refs(expected_ref: str) -> frozenset[str]:
    if expected_ref.startswith("v"):
        return frozenset({expected_ref, expected_ref[1:]})
    return frozenset({expected_ref, f"v{expected_ref}"})


def _is_immutable_sha(ref: str) -> bool:
    return len(ref) == 40 and all(char in "0123456789abcdefABCDEF" for char in ref)


__all__ = ["VerifyOutcome", "verify_agent_resolution"]
