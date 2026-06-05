#!/usr/bin/env python3
"""Generate RepoLens shortlist proposal artifacts from emitted contexts.

This is a skill helper, not a RepoLens product command: it performs the external,
model-adjacent proposal pass while RepoLens itself remains verify-first and
human-approved. The helper reuses RepoLens resolver adapters and verifier so generated
proposals cite evidence that `repolens shortlist --proposals` can independently re-fetch.
"""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from repolens.policy.config import Policy, load_default_policy
from repolens.policy.engine import classify_license_input
from repolens.policy.types import PolicyTier
from repolens.resolve.adapters import build_default_adapters
from repolens.resolve.ecosystems import is_cataloging_only_package
from repolens.resolve.models import ApiCandidate, FetchFunction, PackageFact, ResolveAdapter
from repolens.resolve.purl import parse_purl
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import FetchResult, HttpFetchOptions, Resolver, fetch_url
from repolens.shortlist.agent import Resolution
from repolens.shortlist.verify import verify_agent_resolution

Outcome = str
AdapterFactory = Callable[[FetchFunction], Iterable[ResolveAdapter]]

_PROPOSED: Outcome = "proposed"
_CONFIRMED_NEEDS_REVIEW: Outcome = "confirmed-needs-review"
_ABSTAINED: Outcome = "abstained"


@dataclass(frozen=True, slots=True)
class ReviewRow:
    component_ref: str
    outcome: Outcome
    evidence_checked: str
    recommendation: str


@dataclass(slots=True)
class GenerationResult:
    proposals: list[dict[str, object]]
    review_rows: list[ReviewRow]
    stats: Counter[str] = field(default_factory=Counter)
    verified_urls: set[str] = field(default_factory=set)
    fetch_count: int = 0
    duplicate_component_refs: dict[str, int] = field(default_factory=dict)
    duplicate_evidence_urls: dict[str, int] = field(default_factory=dict)
    policy_version: str = ""

    def summary(self) -> dict[str, object]:
        return {
            "rows": len(self.proposals),
            "stats": dict(self.stats),
            "unique_verified_urls": len(self.verified_urls),
            "fetches": self.fetch_count,
            "duplicate_component_refs": self.duplicate_component_refs,
            "duplicate_evidence_urls": self.duplicate_evidence_urls,
            "policy_version": self.policy_version,
        }


class CachedFetcher:
    """Small fetch cache shared by adapters and verifier."""

    def __init__(self, fetcher: FetchFunction) -> None:
        self._fetcher = fetcher
        self._cache: dict[tuple[object, ...], FetchResult] = {}

    @property
    def fetch_count(self) -> int:
        return len(self._cache)

    def __call__(self, url: str, options: HttpFetchOptions) -> FetchResult:
        key = (
            url,
            tuple(sorted(options.allowed_hosts)),
            options.max_redirects,
            tuple(sorted((options.headers or {}).items())),
            options.limits.max_fetch_bytes,
            options.limits.fetch_timeout_seconds,
        )
        if key not in self._cache:
            self._cache[key] = self._fetcher(url, options)
        return self._cache[key]


def generate_proposals(
    contexts: Sequence[Mapping[str, object]],
    *,
    fetcher: FetchFunction = fetch_url,
    adapter_factory: AdapterFactory = build_default_adapters,
    evidence_resolver: Resolver | None = None,
    policy: Policy | None = None,
) -> GenerationResult:
    active_policy = policy or load_default_policy()
    cached_fetcher = CachedFetcher(fetcher)
    adapters = tuple(adapter_factory(cached_fetcher))
    result = GenerationResult(
        proposals=[],
        review_rows=[],
        duplicate_component_refs=_duplicates(
            _optional_str(row.get("component_ref")) or "" for row in contexts
        ),
        duplicate_evidence_urls=_duplicates(
            _triage_text(row, "evidence_url")
            for row in contexts
            if _triage_text(row, "evidence_url")
        ),
        policy_version=active_policy.policy_version,
    )

    for row in contexts:
        proposal, review = _review_context_row(
            row,
            adapters=adapters,
            fetcher=cached_fetcher,
            evidence_resolver=evidence_resolver,
            policy=active_policy,
        )
        result.proposals.append(proposal)
        result.review_rows.append(review)
        result.stats[review.outcome] += 1
        if review.outcome == _PROPOSED:
            url = _optional_str(proposal.get("evidence_url"))
            if url:
                result.verified_urls.add(url)

    result.fetch_count = cached_fetcher.fetch_count
    return result


def _review_context_row(
    row: Mapping[str, object],
    *,
    adapters: Sequence[ResolveAdapter],
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
    policy: Policy,
) -> tuple[dict[str, object], ReviewRow]:
    component_ref = _optional_str(row.get("component_ref")) or ""
    triage = _triage(row)
    current_spdx = _optional_str(triage.get("spdx_id")) or ""
    current_anchor = _optional_str(triage.get("evidence_anchor")) or ""
    current_url = _optional_str(triage.get("evidence_url")) or ""

    if current_spdx and current_spdx != "UNKNOWN" and _needs_human_review(current_spdx, policy):
        reason = (
            f"Existing finding is {current_spdx}; review-tier or block-tier risk needs "
            "human/legal review."
        )
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _CONFIRMED_NEEDS_REVIEW,
            _evidence_text(current_url, current_anchor),
            reason,
        )

    package, reason = _package_fact_from_context(row)
    if package is None:
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _ABSTAINED,
            current_url or "none",
            reason,
        )

    if is_cataloging_only_package(package):
        reason = (
            f"{package.package_type} is cataloged only in this RepoLens resolver; no "
            "allowlisted exact-license API evidence is available."
        )
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _ABSTAINED,
            current_url or "none",
            reason,
        )

    candidate, checked = _first_candidate(package, adapters)
    checked_text = "; ".join(checked[:6]) if checked else "no registry/API lookup attempted"
    if candidate is None:
        reason = "No allowlisted registry/API lookup produced a target-package license anchor."
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _ABSTAINED,
            checked_text,
            reason,
        )

    verified = verify_agent_resolution(
        Resolution(
            spdx_id=candidate.spdx_id,
            evidence_url=candidate.evidence_url,
            evidence_anchor=candidate.evidence_anchor,
        ),
        fetcher=fetcher,
        resolver=evidence_resolver,
    )
    checked_text = _evidence_text(candidate.evidence_url, candidate.evidence_anchor)
    if not verified.verified:
        reason = (
            f"Candidate {candidate.spdx_id} did not pass RepoLens verifier "
            f"({verified.reason})."
        )
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _ABSTAINED,
            checked_text,
            reason,
        )

    if _needs_human_review(candidate.spdx_id, policy):
        reason = (
            f"Verified {candidate.spdx_id}, but review-tier or block-tier risk must remain "
            "for human/legal judgment."
        )
        return _abstain(component_ref, reason), ReviewRow(
            component_ref,
            _CONFIRMED_NEEDS_REVIEW,
            checked_text,
            reason,
        )

    proposal = {
        "component_ref": component_ref,
        "spdx_id": candidate.spdx_id,
        "evidence_url": candidate.evidence_url,
        "evidence_anchor": candidate.evidence_anchor,
        "disposition": "allow",
        "confidence": 0.95,
        "rationale": (
            "Fetched allowlisted package metadata for the exact package/version and found "
            f"target license {candidate.evidence_anchor}."
        ),
        "sanity_check": "No BLOCK or source-available terms found in the cited target field.",
    }
    return proposal, ReviewRow(
        component_ref,
        _PROPOSED,
        checked_text,
        f"Proposal changes to {candidate.spdx_id}; ingest proposals for verifier/human review.",
    )


def _package_fact_from_context(row: Mapping[str, object]) -> tuple[PackageFact | None, str]:
    triage = _triage(row)
    purl = _optional_str(triage.get("evidence_url")) or ""
    component_name, _license = _split_component_ref(_optional_str(row.get("component_ref")) or "")
    if not purl.startswith("pkg:"):
        return None, "No package-url identifier is available for registry lookup."
    parsed = parse_purl(purl)
    if parsed is None:
        return None, "Package-url identifier could not be parsed."
    if not parsed.version:
        return None, "No exact package version is available for registry lookup."

    package_type = parsed.package_type
    name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
    purl_for_identity: str | None = purl
    if package_type in {"golang", "gomod", "go-module"}:
        name = component_name
        purl_for_identity = None
    return (
        PackageFact(
            name=name,
            version=parsed.version,
            package_type=package_type,
            repo=",".join(_triage_list(triage, "found_in")),
            purl=purl_for_identity,
            declared_license_raw=None,
        ),
        "",
    )


def _first_candidate(
    package: PackageFact,
    adapters: Sequence[ResolveAdapter],
) -> tuple[ApiCandidate | None, list[str]]:
    checked: list[str] = []
    for adapter in adapters:
        name = adapter.__class__.__name__
        try:
            candidate = adapter.resolve(package)
        except FetchSecurityError as exc:
            checked.append(f"{name}: {exc.__class__.__name__}")
            continue
        except Exception as exc:  # pragma: no cover - defensive for external API drift.
            checked.append(f"{name}: {exc.__class__.__name__}")
            continue
        if candidate is None:
            checked.append(f"{name}: no candidate")
            continue
        checked.append(_evidence_text(candidate.evidence_url, candidate.evidence_anchor))
        return candidate, checked
    return None, checked


def _needs_human_review(spdx_id: str, policy: Policy) -> bool:
    decision = classify_license_input(spdx_id, policy)
    return decision.effective_tier in {PolicyTier.REVIEW, PolicyTier.BLOCK, PolicyTier.UNKNOWN}


def _abstain(component_ref: str, reason: str) -> dict[str, object]:
    return {"component_ref": component_ref, "abstain": True, "reason": reason}


def _read_contexts(path: Path) -> list[Mapping[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise SystemExit(f"{path}: expected a JSON array")
    rows: list[Mapping[str, object]] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, Mapping):
            raise SystemExit(f"{path}:{index}: expected object")
        rows.append(item)
    return rows


def _write_outputs(
    result: GenerationResult,
    *,
    contexts_path: Path,
    proposals_path: Path,
    review_path: Path,
) -> None:
    proposals_path.write_text(
        json.dumps(result.proposals, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    review_path.write_text(
        _review_markdown(result, contexts_path=contexts_path, proposals_path=proposals_path),
        encoding="utf-8",
    )


def _review_markdown(
    result: GenerationResult,
    *,
    contexts_path: Path,
    proposals_path: Path,
) -> str:
    lines = [
        "# RepoLens Shortlist Proposal Review",
        "",
        f"Input: `{contexts_path}`",
        f"Proposal artifact: `{proposals_path}`",
        "",
        "Summary:",
        f"- Rows reviewed: {len(result.proposals)}",
        f"- Proposed verified corrections: {result.stats[_PROPOSED]}",
        f"- Confirmed needs human review: {result.stats[_CONFIRMED_NEEDS_REVIEW]}",
        f"- Abstained: {result.stats[_ABSTAINED]}",
        f"- Unique verified evidence URLs: {len(result.verified_urls)}",
        f"- Fetches: {result.fetch_count}",
        f"- Policy version: {result.policy_version}",
        "",
        "Notes:",
        (
            "- Proposals cite only allowlisted registry/API evidence that passed the "
            "RepoLens exact-anchor verifier in this checkout."
        ),
        (
            "- Cataloging-only ecosystem rows are abstained because this RepoLens resolver "
            "does not have public exact-license API resolution for them."
        ),
        (
            "- Review-tier, block-tier, and otherwise risky rows are left for human/legal "
            "judgment even when evidence exists."
        ),
        "",
        "| component_ref | outcome | evidence checked | recommendation |",
        "| --- | --- | --- | --- |",
    ]
    for row in result.review_rows:
        lines.append(
            "| "
            f"`{_markdown_escape(row.component_ref)}` | "
            f"{row.outcome} | "
            f"{_markdown_escape(row.evidence_checked)} | "
            f"{_markdown_escape(row.recommendation)} |"
        )
    return "\n".join(lines) + "\n"


def _duplicates(values: Iterable[str]) -> dict[str, int]:
    counts = Counter(value for value in values if value)
    return {value: count for value, count in sorted(counts.items()) if count > 1}


def _triage(row: Mapping[str, object]) -> Mapping[str, object]:
    value = row.get("triage")
    return value if isinstance(value, Mapping) else {}


def _triage_text(row: Mapping[str, object], key: str) -> str:
    return _optional_str(_triage(row).get(key)) or ""


def _triage_list(triage: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = triage.get(key)
    if not isinstance(value, list):
        return tuple()
    return tuple(item for item in value if isinstance(item, str) and item)


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _split_component_ref(ref: str) -> tuple[str, str]:
    if "|" not in ref:
        return ref, ""
    name, license_id = ref.rsplit("|", 1)
    return name, license_id


def _evidence_text(url: str, anchor: str) -> str:
    if url and anchor:
        return f"{url} anchor `{anchor}`"
    return url or anchor or "none"


def _markdown_escape(value: str) -> str:
    return value.replace("`", "\\`").replace("|", "\\|").replace("\n", " ")


def _default_contexts_path(work_root: Path) -> Path:
    return work_root / "shortlist.contexts.json"


def _default_proposals_path(work_root: Path) -> Path:
    return work_root / "shortlist.proposals.json"


def _default_review_path(work_root: Path) -> Path:
    return work_root / "shortlist.review.md"


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate RepoLens shortlist.proposals.json and shortlist.review.md from "
            "emitted shortlist.contexts.json."
        )
    )
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--contexts", type=Path, default=None)
    parser.add_argument("--proposals", type=Path, default=None)
    parser.add_argument("--review", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    work_root = args.work_root
    contexts_path = args.contexts or _default_contexts_path(work_root)
    proposals_path = args.proposals or _default_proposals_path(work_root)
    review_path = args.review or _default_review_path(work_root)

    contexts = _read_contexts(contexts_path)
    result = generate_proposals(contexts)
    _write_outputs(
        result,
        contexts_path=contexts_path,
        proposals_path=proposals_path,
        review_path=review_path,
    )
    summary = {
        **result.summary(),
        "contexts_path": str(contexts_path),
        "proposal_path": str(proposals_path),
        "review_path": str(review_path),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
