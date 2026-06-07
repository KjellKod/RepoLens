from __future__ import annotations

from pathlib import Path

import pytest

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.agent import AgentRequest, AgentResponse
from repolens.shortlist.contexts import PackageMetadata, ShortlistMetadata, TriageMetadata
from repolens.shortlist.evidence import apply_evidence, identity_for_item, load_evidence
from repolens.shortlist.research import run_research
from repolens.shortlist.stage import run_shortlist

_PYPI_URL = "https://pypi.org/pypi/acme-lib/1.2.3/json"


class _ExplodingAgent:
    def resolve(self, request: AgentRequest) -> AgentResponse:
        del request
        raise AssertionError("evidence ingestion must not invoke the agent")


def _metadata() -> ShortlistMetadata:
    return ShortlistMetadata(
        triage_by_ref={
            "acme-lib|UNKNOWN": TriageMetadata(
                spdx_id="UNKNOWN",
                tier="UNKNOWN",
                origin="third-party",
                scope="runtime",
                distribution="shipped",
                evidence_url=None,
                evidence_anchor=None,
                found_in=("sentinel-alpha",),
            )
        },
        package_by_ref={
            "acme-lib|UNKNOWN": PackageMetadata(
                package="acme-lib",
                version="1.2.3",
                ecosystem="pypi",
                source_url="pkg:pypi/acme-lib@1.2.3",
                purl="pkg:pypi/acme-lib@1.2.3",
            )
        },
    )


def _item(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "component_ref": "acme-lib|UNKNOWN",
        "reason": "UNKNOWN",
        "evidence": {"source_layer": "api", "url": _PYPI_URL, "anchor": "UNKNOWN"},
        "candidate_spdx": None,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": None,
    }
    item.update(overrides)
    return item


def _write_shortlist(work_root: Path, item: dict[str, object] | None = None) -> None:
    store.write_inventory(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "name": "acme-lib",
                    "license": "UNKNOWN",
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                    "versions": ["1.2.3"],
                    "source_url": _PYPI_URL,
                    "modified": "unknown",
                    "found_in": ["sentinel-alpha"],
                    "policy_tier": "REVIEW",
                    "evidence_refs": ["sentinel-alpha/resolved.ndjson:1"],
                }
            ],
        },
    )
    store.write_resolved(
        work_root,
        "sentinel-alpha",
        [
            {
                "schema_version": "1.0",
                "name": "acme-lib",
                "version": "1.2.3",
                "repo": "sentinel-alpha",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "spdx_id": "UNKNOWN",
                "evidence": {"source_layer": "api", "url": _PYPI_URL, "anchor": "UNKNOWN"},
                "tags": {
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                },
                "modified": "unknown",
            }
        ],
    )
    store.write_shortlist(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [item or _item()],
        },
    )


def _evidence_record(
    work_root: Path,
    *,
    outcome: str = "pending_verifier_support",
    machine_verification: str = "pending_verifier_support",
    component_ref: str = "acme-lib|UNKNOWN",
    found_in: list[str] | None = None,
    browser_evidence: list[dict[str, object]] | None = None,
    lookups_attempted: list[str] | None = None,
) -> dict[str, object]:
    metadata = _metadata()
    item = _item(component_ref=component_ref)
    if found_in is not None:
        metadata = ShortlistMetadata(
            triage_by_ref={
                component_ref: TriageMetadata(
                    spdx_id="UNKNOWN",
                    tier="UNKNOWN",
                    origin="third-party",
                    scope="runtime",
                    distribution="shipped",
                    evidence_url=None,
                    evidence_anchor=None,
                    found_in=tuple(found_in),
                )
            },
            package_by_ref={
                component_ref: PackageMetadata(
                    package="acme-lib",
                    version="1.2.3",
                    ecosystem="pypi",
                    source_url="pkg:pypi/acme-lib@1.2.3",
                    purl="pkg:pypi/acme-lib@1.2.3",
                )
            },
        )
    identity = identity_for_item(item, metadata)
    del work_root
    record: dict[str, object] = {
        "component_ref": component_ref,
        "context_fingerprint": identity.context_fingerprint,
        "package": identity.package,
        "version": identity.version,
        "ecosystem": identity.ecosystem,
        "found_in": list(identity.found_in),
        "outcome": outcome,
        "machine_verification": machine_verification,
        "lookups_attempted": lookups_attempted or ["PyPI metadata"],
        "likely_spdx": "MIT",
        "confidence": "high",
        "browser_evidence": browser_evidence
        if browser_evidence is not None
        else [{"label": "PyPI metadata", "url": _PYPI_URL, "source_type": "pypi", "anchor": "MIT"}],
        "rationale": "Registry metadata anchors MIT.",
        "review_note": "Browser evidence found.",
    }
    if outcome == "no_public_evidence":
        record["likely_spdx"] = None
        record["browser_evidence"] = []
    return record


def _external_candidate_record(tmp_path: Path) -> dict[str, object]:
    record = _evidence_record(tmp_path)
    record["human_candidate_spdx"] = "MIT"
    record["source_repo"] = {
        "host": "github.com",
        "owner": "sentinel",
        "repo": "acme-lib",
        "ref": "1.2.3",
        "ref_kind": "version",
        "provenance": "external_candidate",
        "provenance_detail": "triage_evidence_url",
        "bound_to_package": False,
        "fetch_url": "https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3",
        "display_url": "https://github.com/sentinel/acme-lib/blob/1.2.3/LICENSE",
    }
    return record


def test_load_evidence_rejects_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    record = _evidence_record(tmp_path)
    record["unexpected"] = "drift"
    store.atomic_write_json(path, [record])

    with pytest.raises(SchemaValidationError, match="unexpected"):
        load_evidence(path)


def test_load_evidence_rejects_duplicate_context_identity(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    record = _evidence_record(tmp_path)
    store.atomic_write_json(path, [record, record])

    with pytest.raises(SchemaValidationError, match="duplicate context identity"):
        load_evidence(path)


def test_pending_evidence_requires_direct_https_link_and_label(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    record = _evidence_record(
        tmp_path,
        browser_evidence=[
            {"label": "placeholder", "url": "https://example.com", "source_type": "pypi"}
        ],
    )
    store.atomic_write_json(path, [record])

    with pytest.raises(SchemaValidationError, match="placeholder"):
        load_evidence(path)


def test_external_candidate_source_repo_schema_loads(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    store.atomic_write_json(path, [_external_candidate_record(tmp_path)])

    loaded = load_evidence(path)

    assert loaded[0].human_candidate_spdx == "MIT"
    assert loaded[0].source_repo is not None
    assert loaded[0].source_repo.provenance == "external_candidate"


def test_human_candidate_requires_external_source_repo(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    record = _evidence_record(tmp_path)
    record["human_candidate_spdx"] = "MIT"
    store.atomic_write_json(path, [record])

    with pytest.raises(SchemaValidationError, match="human candidate requires external"):
        load_evidence(path)


def test_no_public_evidence_records_lookup_attempts(tmp_path: Path) -> None:
    path = tmp_path / "shortlist.evidence.json"
    record = _evidence_record(
        tmp_path,
        outcome="no_public_evidence",
        machine_verification="no_public_evidence",
        lookups_attempted=["PyPI metadata", "GitHub license API"],
    )
    store.atomic_write_json(path, [record])

    loaded = load_evidence(path)

    assert loaded[0].machine_verification == "no_public_evidence"
    assert loaded[0].lookups_attempted == ("GitHub license API", "PyPI metadata")


def test_apply_evidence_preserves_pending_verifier_evidence(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    evidence_path = tmp_path / "shortlist.evidence.json"
    store.atomic_write_json(evidence_path, [_evidence_record(tmp_path)])

    result = run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        evidence_path=evidence_path,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert result.agent_invocations == 0
    assert item["status"] == "open"
    assert item["research_evidence"]["machine_verification"] == "pending_verifier_support"
    assert item["research_evidence"]["browser_evidence"][0]["label"] == "PyPI metadata"


def test_apply_evidence_does_not_overwrite_machine_verified_proposal(tmp_path: Path) -> None:
    """A proposal that passed verification is authoritative; a matching evidence artifact
    must not overwrite the verifier-produced research_evidence (precedence invariant).
    """

    verified = {
        "machine_verification": "verified",
        "outcome": "verify:exact_anchor_default_branch",
        "browser_evidence": [
            {
                "label": "🔎 GitHub license (MIT · default branch, not version-pinned)",
                "url": "https://github.com/sentinel/acme-lib/blob/HEAD/LICENSE",
                "source_type": "github_license_api_default_branch",
                "anchor": "MIT",
            }
        ],
    }
    item = _item(research_evidence=verified)
    evidence_path = tmp_path / "shortlist.evidence.json"
    store.atomic_write_json(evidence_path, [_evidence_record(tmp_path)])

    [updated] = apply_evidence([item], evidence_path, metadata=_metadata())

    research = updated["research_evidence"]
    assert research["machine_verification"] == "verified"
    assert research["outcome"] == "verify:exact_anchor_default_branch"
    assert research["browser_evidence"][0]["source_type"] == "github_license_api_default_branch"


def test_apply_evidence_ignores_stale_or_mismatched_identity(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    evidence_path = tmp_path / "shortlist.evidence.json"
    stale = _evidence_record(tmp_path, found_in=["sentinel-beta"])
    store.atomic_write_json(evidence_path, [stale])

    run_shortlist(tmp_path, agent_client=_ExplodingAgent(), evidence_path=evidence_path)

    item = store.read_shortlist(tmp_path)["items"][0]
    assert "research_evidence" not in item


def test_bare_shortlist_does_not_clobber_research_evidence(tmp_path: Path) -> None:
    item = _item(research_evidence=_evidence_record(tmp_path))
    _write_shortlist(tmp_path, item)

    run_shortlist(tmp_path, agent_client=_ExplodingAgent())

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["research_evidence"]["browser_evidence"][0]["url"] == _PYPI_URL


def test_emitted_contexts_research_and_ingest_preserve_identity_facts(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    contexts_path = tmp_path / "shortlist.contexts.json"
    proposals_path = tmp_path / "shortlist.proposals.json"
    evidence_path = tmp_path / "shortlist.evidence.json"
    review_path = tmp_path / "shortlist.review.md"

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        emit_contexts_path=contexts_path,
    )

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        body = b'{"info":{"license":"MIT"}}' if url == _PYPI_URL else b"{}"
        return FetchResult(url=url, status=200, headers=(), body=body)

    run_research(
        contexts_path=contexts_path,
        proposals_path=proposals_path,
        evidence_path=evidence_path,
        review_path=review_path,
        fetcher=fetcher,
    )
    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        evidence_path=evidence_path,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["research_evidence"]["package"] == "acme-lib"
    assert item["research_evidence"]["version"] == "1.2.3"
    assert item["research_evidence"]["ecosystem"] == "pypi"
    assert item["research_evidence"]["found_in"] == ["sentinel-alpha"]
    assert item["research_evidence"]["browser_evidence"][0]["label"] == "PyPI metadata"


def test_external_candidate_evidence_persists_in_shortlist_schema(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    evidence_path = tmp_path / "shortlist.evidence.json"
    store.atomic_write_json(evidence_path, [_external_candidate_record(tmp_path)])

    run_shortlist(tmp_path, agent_client=_ExplodingAgent(), evidence_path=evidence_path)

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["research_evidence"]["human_candidate_spdx"] == "MIT"
    assert item["research_evidence"]["source_repo"]["provenance"] == "external_candidate"
