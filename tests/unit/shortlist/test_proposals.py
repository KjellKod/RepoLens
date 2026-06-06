from __future__ import annotations

from pathlib import Path

import pytest

from repolens.data import store
from repolens.data.errors import SchemaValidationError
from repolens.data.validation import validate_artifact
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.agent import AgentRequest, AgentResponse
from repolens.shortlist.stage import run_shortlist

_GITHUB_DEFAULT_BRANCH_BODY = (
    b'{"license":{"spdx_id":"MIT"},'
    b'"html_url":"https://github.com/sentinel/acme-lib/blob/HEAD/LICENSE",'
    b'"download_url":"https://raw.githubusercontent.com/sentinel/acme-lib/HEAD/LICENSE"}'
)
_GITHUB_PINNED_BODY = (
    b'{"license":{"spdx_id":"MIT"},'
    b'"html_url":"https://github.com/sentinel/acme-lib/blob/1.2.3/LICENSE",'
    b'"download_url":"https://raw.githubusercontent.com/sentinel/acme-lib/1.2.3/LICENSE"}'
)

_DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3"


class _ExplodingAgent:
    def resolve(self, request: AgentRequest) -> AgentResponse:
        del request
        raise AssertionError("proposal artifact ingestion must not invoke an agent")


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def _fetcher(body: bytes):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=body)

    return fetch


def _write_shortlist(work_root: Path) -> None:
    store.write_shortlist(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [_item("acme-lib|MIT")],
        },
    )


def _write_inventory_metadata(work_root: Path) -> None:
    store.write_inventory(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "name": "acme-lib",
                    "license": "MIT",
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                    "versions": ["1.2.3"],
                    "source_url": "pkg:pypi/acme-lib@1.2.3",
                    "modified": "unknown",
                    "found_in": ["acme-alpha"],
                    "policy_tier": "REVIEW",
                    "evidence_refs": ["acme-alpha/resolved.ndjson:1"],
                }
            ],
        },
    )


def _write_swift_github_metadata(work_root: Path) -> None:
    store.write_inventory(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "name": "acme-lib",
                    "license": "MIT",
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                    "versions": ["1.2.3"],
                    "source_url": "pkg:swift/github.com/sentinel/acme-lib/acme-lib@1.2.3",
                    "modified": "unknown",
                    "found_in": ["acme-alpha"],
                    "policy_tier": "REVIEW",
                    "evidence_refs": ["acme-alpha/resolved.ndjson:1"],
                }
            ],
        },
    )


def _write_swift_github_issue_metadata(work_root: Path) -> None:
    store.write_inventory(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "name": "acme-lib",
                    "license": "MIT",
                    "origin": "third-party-oss",
                    "scope": "runtime",
                    "distribution": "server",
                    "versions": ["1.2.3"],
                    "source_url": "https://github.com/sentinel/acme-lib/issues/1",
                    "modified": "unknown",
                    "found_in": ["acme-alpha"],
                    "policy_tier": "REVIEW",
                    "evidence_refs": ["acme-alpha/resolved.ndjson:1"],
                }
            ],
        },
    )


def _item(component_ref: str) -> dict[str, object]:
    return {
        "component_ref": component_ref,
        "reason": "REVIEW",
        "evidence": {"source_layer": "api", "url": _DEPS_DEV_URL, "anchor": "MIT"},
        "candidate_spdx": None,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": None,
    }


def _proposal(**overrides: object) -> dict[str, object]:
    proposal: dict[str, object] = {
        "component_ref": "acme-lib|MIT",
        "spdx_id": "MIT",
        "evidence_url": _DEPS_DEV_URL,
        "evidence_anchor": "MIT",
        "disposition": "allow",
        "confidence": 0.95,
        "rationale": "Registry metadata anchors MIT.",
        "sanity_check": "No BLOCK terms found.",
    }
    proposal.update(overrides)
    return proposal


def _write_proposals(path: Path, proposals: list[dict[str, object]]) -> None:
    store.atomic_write_json(path, proposals)


def test_verified_proposal_records_candidate_but_keeps_open(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal()])

    result = run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert result.agent_invocations == 0
    assert item["status"] == "open"
    assert item["candidate_spdx"] == "MIT"
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["verify_reason"] == "verify:exact_anchor"
    assert item["ai_suggestion"]["disposition"] == "allow"


def test_verified_expression_proposal_records_candidate(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    expression = "PSF-2.0 AND ZPL-2.1"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                spdx_id=expression,
                evidence_anchor=expression,
                rationale="Registry metadata anchors a permissive expression.",
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"licensed":{"declared":"PSF-2.0 AND ZPL-2.1"}}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] == expression
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["verify_reason"] == "verify:exact_anchor"


def test_bad_anchor_keeps_open_with_verify_failed(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal()])

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"GPL-3.0-only"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:anchor_mismatch"


def test_github_main_ref_proposal_rejected_for_versioned_item(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_inventory_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [_proposal(evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=main")],
    )
    fetched: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetched.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=fetcher,
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert fetched == []
    assert item["status"] == "open"
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"


def test_github_wrong_tag_proposal_rejected_for_versioned_item(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_inventory_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=2.0.0"
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"


def test_off_allowlist_url_rejected(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [_proposal(evidence_url="https://attacker.example.invalid/license")],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["note"] == "verify_failed:verify:fetch_blocked_or_failed"


def test_abstention_records_reason_without_verification(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [{"component_ref": "acme-lib|MIT", "abstain": True, "reason": "ambiguous"}],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["status"] == "open"
    assert item["note"] == "agent:abstained"
    assert item["ai_suggestion"]["reason"] == "ambiguous"


def test_proposal_ingest_reports_missing_and_settled_refs(tmp_path: Path) -> None:
    store.write_shortlist(
        tmp_path,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [
                _item("acme-lib|MIT"),
                {**_item("settled-lib|MIT"), "status": "approved"},
            ],
        },
    )
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(component_ref="acme-lib|MIT"),
            _proposal(component_ref="settled-lib|MIT"),
            _proposal(component_ref="stale-lib|MIT"),
        ],
    )

    result = run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    assert result.proposal_summary is not None
    assert result.proposal_summary.total_records == 3
    assert result.proposal_summary.matched_open_refs == ("acme-lib|MIT",)
    assert result.proposal_summary.skipped_settled_refs == ("settled-lib|MIT",)
    assert result.proposal_summary.skipped_missing_refs == ("stale-lib|MIT",)


def test_proposal_artifact_schema_rejects_unknown_fields(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(proposals_path, [_proposal(unexpected="drift")])

    with pytest.raises(SchemaValidationError, match="unexpected"):
        run_shortlist(
            tmp_path,
            agent_client=_ExplodingAgent(),
            proposals_path=proposals_path,
            fetcher=_fetcher(b'{"license":"MIT"}'),
            evidence_resolver=_public_resolver,
        )


def test_source_repo_proposal_fields_fail_closed_until_supported(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3",
                evidence_kind="github_source_repo",
                source_repo={
                    "host": "github.com",
                    "owner": "sentinel",
                    "repo": "acme-lib",
                    "ref": "1.2.3",
                    "provenance": "external_candidate",
                    "provenance_detail": "proposal_candidate",
                    "bound_to_package": False,
                },
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"


def test_github_source_repo_proposal_rejects_wrong_repo(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/attacker/acme-lib/license?ref=1.2.3",
                evidence_kind="github_source_repo",
                source_repo={
                    "host": "github.com",
                    "owner": "attacker",
                    "repo": "acme-lib",
                    "ref": "1.2.3",
                    "ref_kind": "version",
                    "provenance": "package_metadata",
                    "provenance_detail": "swiftpm_purl",
                    "bound_to_package": True,
                },
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_mismatch"


def _default_branch_source_repo(**overrides: object) -> dict[str, object]:
    source_repo: dict[str, object] = {
        "host": "github.com",
        "owner": "sentinel",
        "repo": "acme-lib",
        "ref_kind": "default_branch",
        "provenance": "package_metadata",
        "provenance_detail": "swiftpm_purl",
        "bound_to_package": True,
    }
    source_repo.update(overrides)
    return source_repo


def test_github_default_branch_proposal_verifies_with_provenance(tmp_path: Path) -> None:
    """#12 — provenance-bound default-branch proposal verifies and emits the unpinned link."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] == "MIT"
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["verify_reason"] == "verify:exact_anchor_default_branch"
    research = item["research_evidence"]
    entry = research["browser_evidence"][0]
    assert entry["label"] == "🔎 GitHub license (MIT · default branch, not version-pinned)"
    assert entry["source_type"] == "github_license_api_default_branch"
    assert entry["url"] == "https://github.com/sentinel/acme-lib/blob/HEAD/LICENSE"
    assert research["outcome"] == "verify:exact_anchor_default_branch"
    assert research["machine_verification"] == "verified"


def test_github_default_branch_proposal_verifies_even_with_known_version(tmp_path: Path) -> None:
    """#13 — default-branch acceptance is allowed despite a known package version."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)  # carries version 1.2.3
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] == "MIT"
    assert item["verify_reason"] == "verify:exact_anchor_default_branch"


def test_provenance_missing_required(tmp_path: Path) -> None:
    """#14 — a GitHub license URL with no source_repo fails provenance-required."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [_proposal(evidence_url="https://api.github.com/repos/sentinel/acme-lib/license")],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"


def test_default_branch_without_ref_kind_fails_closed(tmp_path: Path) -> None:
    """#15 — a bare missing ref with no ref_kind=default_branch fails closed."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(ref_kind="unknown"),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"


def test_source_pins_ref_url_unpinned_ref_mismatch(tmp_path: Path) -> None:
    """#16 — source pins a ref but the URL is unpinned: asymmetric, no downgrade."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(ref="1.2.3", ref_kind="version"),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_ref_mismatch"


def test_default_branch_kind_but_url_pinned_ref_mismatch(tmp_path: Path) -> None:
    """#17 — source says default branch but the URL pins a ref: asymmetric reverse."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=master",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_ref_mismatch"


def test_owner_repo_mismatch(tmp_path: Path) -> None:
    """#18 — URL repo differs from the provenance-bound repo: source_repo_mismatch."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/attacker/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(owner="attacker"),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_mismatch"


def test_pinned_but_wrong_ref_proposal_ref_mismatch(tmp_path: Path) -> None:
    """#19 — pinned source ref but URL pins a different ref: source_repo_ref_mismatch."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=2.0.0",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(ref="1.2.3", ref_kind="version"),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_PINNED_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_ref_mismatch"


def test_verified_github_proposal_emits_validated_browser_evidence(tmp_path: Path) -> None:
    """#20 — a pinned proposal emits the clean (no caveat) browser-evidence link."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(ref="1.2.3", ref_kind="version"),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_PINNED_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] == "MIT"
    assert item["verify_reason"] == "verify:exact_anchor"
    entry = item["research_evidence"]["browser_evidence"][0]
    assert entry["label"] == "GitHub license (MIT)"
    assert entry["source_type"] == "github_license_api"
    # html_url is preferred over the raw download_url; its hostname is exactly github.com.
    assert entry["url"] == "https://github.com/sentinel/acme-lib/blob/1.2.3/LICENSE"


def test_attacker_host_lifted_url_dropped(tmp_path: Path) -> None:
    """#21 — look-alike/attacker lifted URLs are dropped; no browser_evidence written."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(),
            )
        ],
    )
    body = (
        b'{"license":{"spdx_id":"MIT"},'
        b'"html_url":"https://github.com.attacker.test/x/LICENSE",'
        b'"download_url":"https://evil.example/raw"}'
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(body),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    # Verification still succeeds, but the look-alike hosts are dropped (exact-match guard).
    assert item["candidate_spdx"] == "MIT"
    research = item.get("research_evidence") or {}
    assert not research.get("browser_evidence")


def test_default_branch_proposal_missing_provenance_rejected(tmp_path: Path) -> None:
    """#22 — a default-branch proposal cannot verify without a provenance binding."""

    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
                evidence_kind="github_source_repo",
                source_repo=_default_branch_source_repo(bound_to_package=False),
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(_GITHUB_DEFAULT_BRANCH_BODY),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_provenance_required"
    research = item.get("research_evidence") or {}
    assert not research.get("browser_evidence")


def _schema_proposal(**source_repo_overrides: object) -> dict[str, object]:
    source_repo: dict[str, object] = {
        "host": "github.com",
        "owner": "sentinel",
        "repo": "acme-lib",
        "provenance": "package_metadata",
        "provenance_detail": "swiftpm_purl",
        "bound_to_package": True,
    }
    source_repo.update(source_repo_overrides)
    return _proposal(
        evidence_url="https://api.github.com/repos/sentinel/acme-lib/license",
        evidence_kind="github_source_repo",
        source_repo=source_repo,
    )


def test_default_branch_proposal_passes_artifact_schema() -> None:
    """#24 — the schema ACCEPTS the default-branch shape (ref absent) and a pinned shape."""

    default_branch = _schema_proposal(ref_kind="default_branch")
    validate_artifact([default_branch], "shortlist_proposals")  # must not raise

    pinned = _schema_proposal(ref_kind="version", ref="1.2.3")
    validate_artifact([pinned], "shortlist_proposals")  # if/then did not break pinned


def test_bare_missing_ref_without_ref_kind_still_fails_schema() -> None:
    """#25 — a version proposal that omits ref fails the schema if/then (ref required).

    The absent-``ref_kind`` variant is permitted by the schema (it is the runtime gate that
    fail-closes it via ``verify:source_repo_provenance_required`` — covered by test #15);
    the schema's role is to guarantee a pinned proposal can never silently drop its ``ref``.
    """

    version_without_ref = _schema_proposal(ref_kind="version")
    with pytest.raises(SchemaValidationError):
        validate_artifact([version_without_ref], "shortlist_proposals")


def test_github_source_repo_proposal_accepts_matching_package_repo(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_swift_github_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3",
                evidence_kind="github_source_repo",
                source_repo={
                    "host": "github.com",
                    "owner": "sentinel",
                    "repo": "acme-lib",
                    "ref": "1.2.3",
                    "ref_kind": "version",
                    "provenance": "package_metadata",
                    "provenance_detail": "swiftpm_purl",
                    "bound_to_package": True,
                },
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":{"spdx_id":"MIT"}}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] == "MIT"
    assert item["note"] == "agent:verified_awaiting_human"
    assert item["ai_suggestion"]["source_repo"]["owner"] == "sentinel"


def test_github_source_repo_proposal_rejects_arbitrary_metadata_path(tmp_path: Path) -> None:
    _write_shortlist(tmp_path)
    _write_swift_github_issue_metadata(tmp_path)
    proposals_path = tmp_path / "proposals.json"
    _write_proposals(
        proposals_path,
        [
            _proposal(
                evidence_url="https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3",
                evidence_kind="github_source_repo",
                source_repo={
                    "host": "github.com",
                    "owner": "sentinel",
                    "repo": "acme-lib",
                    "ref": "1.2.3",
                    "ref_kind": "version",
                    "provenance": "package_metadata",
                    "provenance_detail": "swiftpm_purl",
                    "bound_to_package": True,
                },
            )
        ],
    )

    run_shortlist(
        tmp_path,
        agent_client=_ExplodingAgent(),
        proposals_path=proposals_path,
        fetcher=_fetcher(b'{"license":{"spdx_id":"MIT"}}'),
        evidence_resolver=_public_resolver,
    )

    item = store.read_shortlist(tmp_path)["items"][0]
    assert item["candidate_spdx"] is None
    assert item["note"] == "verify_failed:verify:source_repo_mismatch"
