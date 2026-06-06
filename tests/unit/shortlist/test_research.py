from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data import store
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.research import (
    load_context_rows,
    render_review_markdown,
    research_context,
    run_research,
)


def _context(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "component_ref": "acme-lib|UNKNOWN",
        "wrapped_context": None,
        "package": "acme-lib",
        "version": "1.2.3",
        "ecosystem": "pypi",
        "triage": {"found_in": ["sentinel-alpha"], "spdx_id": "UNKNOWN"},
    }
    row.update(overrides)
    return row


def _fetcher(responses: dict[str, bytes]):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=responses.get(url, b"{}"))

    return fetch


def _tracking_fetcher(responses: dict[str, bytes], fetched: list[str]):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetched.append(url)
        return FetchResult(url=url, status=200, headers=(), body=responses.get(url, b"{}"))

    return fetch


def test_research_prefers_pypi_metadata_when_verified() -> None:
    url = "https://pypi.org/pypi/acme-lib/1.2.3/json"
    record, proposal = research_context(
        _context(),
        fetcher=_fetcher({url: json.dumps({"info": {"license": "MIT"}}).encode()}),
    )

    assert record.outcome == "machine_verified"
    assert record.machine_verification == "verified"
    assert record.browser_evidence[0].label == "PyPI metadata"
    assert proposal is not None
    assert proposal["spdx_id"] == "MIT"


def test_research_records_no_public_evidence_lookup_attempts() -> None:
    record, proposal = research_context(_context(), fetcher=_fetcher({}))

    assert record.outcome == "no_public_evidence"
    assert "PyPI metadata" in record.lookups_attempted
    assert proposal is None


def test_research_records_conflict_without_allow_proposal() -> None:
    pypi_url = "https://pypi.org/pypi/acme-lib/1.2.3/json"
    cd_url = "https://api.clearlydefined.io/definitions/registry/pypi/-/acme-lib/1.2.3"
    record, proposal = research_context(
        _context(),
        fetcher=_fetcher(
            {
                pypi_url: json.dumps({"info": {"license": "MIT"}}).encode(),
                cd_url: json.dumps({"licensed": {"declared": "Apache-2.0"}}).encode(),
            }
        ),
    )

    assert record.outcome == "conflict"
    assert len(record.conflicts) == 2
    assert proposal is None


def test_cocoapods_podspec_license_can_be_machine_verified() -> None:
    url = "https://trunk.cocoapods.org/api/v1/pods/acme-lib/specs/1.2.3"
    record, proposal = research_context(
        _context(ecosystem="cocoapods"),
        fetcher=_fetcher({url: json.dumps({"license": {"type": "MIT"}}).encode()}),
    )

    assert record.outcome == "machine_verified"
    assert record.browser_evidence[0].label == "podspec"
    assert proposal is not None


def test_swiftpm_default_branch_license_is_not_machine_verified() -> None:
    url = "https://api.github.com/repos/sentinel/acme-lib/license"
    record, proposal = research_context(
        _context(
            ecosystem="swiftpm",
            version="unknown",
            triage={
                "found_in": ["sentinel-alpha"],
                "evidence_url": "https://github.com/sentinel/acme-lib",
            },
        ),
        fetcher=_fetcher({url: json.dumps({"license": {"spdx_id": "MIT"}}).encode()}),
    )

    assert record.outcome == "pending_verifier_support"
    assert record.machine_verification == "pending_verifier_support"
    assert proposal is None


def test_swiftpm_purl_derives_exact_github_license_api_proposal() -> None:
    url = "https://api.github.com/repos/pointfreeco/xctest-dynamic-overlay/license?ref=1.9.0"
    record, proposal = research_context(
        _context(
            component_ref="xctest-dynamic-overlay|UNKNOWN",
            ecosystem="swift",
            package="github.com/pointfreeco/xctest-dynamic-overlay/xctest-dynamic-overlay",
            version="1.9.0",
            purl=(
                "pkg:swift/github.com/pointfreeco/xctest-dynamic-overlay/"
                "xctest-dynamic-overlay@1.9.0"
            ),
            triage={
                "found_in": ["ios-driver"],
                "spdx_id": "UNKNOWN",
                "evidence_url": (
                    "pkg:swift/github.com/pointfreeco/xctest-dynamic-overlay/"
                    "xctest-dynamic-overlay@1.9.0"
                ),
            },
        ),
        fetcher=_fetcher({url: json.dumps({"license": {"spdx_id": "MIT"}}).encode()}),
    )

    assert record.outcome == "machine_verified"
    assert record.machine_verification == "verified"
    assert record.likely_spdx == "MIT"
    assert record.browser_evidence[0].url == url
    assert record.source_repo is not None
    assert record.source_repo.provenance == "package_metadata"
    assert proposal is not None
    assert proposal["spdx_id"] == "MIT"
    assert proposal["evidence_url"] == url


def test_swiftpm_purl_tries_bounded_v_tag_variant() -> None:
    first = "https://api.github.com/repos/pointfreeco/xctest-dynamic-overlay/license?ref=1.9.0"
    second = "https://api.github.com/repos/pointfreeco/xctest-dynamic-overlay/license?ref=v1.9.0"
    fetched: list[str] = []

    record, proposal = research_context(
        _context(
            ecosystem="swiftpm",
            package="github.com/pointfreeco/xctest-dynamic-overlay/xctest-dynamic-overlay",
            version="1.9.0",
            purl=(
                "pkg:swift/github.com/pointfreeco/xctest-dynamic-overlay/"
                "xctest-dynamic-overlay@1.9.0"
            ),
        ),
        fetcher=_tracking_fetcher(
            {second: json.dumps({"license": {"spdx_id": "MIT"}}).encode()},
            fetched,
        ),
    )

    assert record.outcome == "machine_verified"
    assert proposal is not None
    assert proposal["evidence_url"] == second
    assert fetched == [first, second]


def test_swiftpm_github_package_string_derives_repo_without_product_suffix() -> None:
    url = "https://api.github.com/repos/pointfreeco/xctest-dynamic-overlay/license?ref=1.9.0"
    fetched: list[str] = []

    record, proposal = research_context(
        _context(
            ecosystem="swiftpm",
            package="github.com/pointfreeco/xctest-dynamic-overlay/xctest-dynamic-overlay",
            version="1.9.0",
        ),
        fetcher=_tracking_fetcher(
            {url: json.dumps({"license": {"spdx_id": "MIT"}}).encode()},
            fetched,
        ),
    )

    assert record.outcome == "machine_verified"
    assert proposal is not None
    assert fetched[0] == url


def test_external_github_repo_url_becomes_human_candidate_evidence() -> None:
    url = "https://api.github.com/repos/Owner/RepoName/license?ref=1.2.3"

    record, proposal = research_context(
        _context(
            ecosystem="swiftpm",
            package="not-github-shaped",
            version="1.2.3",
            triage={
                "found_in": ["sentinel-alpha"],
                "spdx_id": "UNKNOWN",
                "evidence_url": "https://GitHub.com/Owner/RepoName",
            },
        ),
        fetcher=_fetcher({url: json.dumps({"license": {"spdx_id": "MIT"}}).encode()}),
    )

    assert proposal is None
    assert record.outcome == "pending_verifier_support"
    assert record.human_candidate_spdx == "MIT"
    assert record.source_repo is not None
    assert record.source_repo.provenance == "external_candidate"
    assert record.source_repo.owner == "Owner"
    assert record.source_repo.repo == "RepoName"


def test_raw_license_fallback_stays_pending_and_renders_blob_url() -> None:
    api = "https://api.github.com/repos/pointfreeco/xctest-dynamic-overlay/license?ref=1.9.0"
    raw = "https://raw.githubusercontent.com/pointfreeco/xctest-dynamic-overlay/1.9.0/LICENSE"
    blob = "https://github.com/pointfreeco/xctest-dynamic-overlay/blob/1.9.0/LICENSE"

    record, proposal = research_context(
        _context(
            component_ref="xctest-dynamic-overlay|UNKNOWN",
            ecosystem="swift",
            package="github.com/pointfreeco/xctest-dynamic-overlay/xctest-dynamic-overlay",
            version="1.9.0",
            purl=(
                "pkg:swift/github.com/pointfreeco/xctest-dynamic-overlay/"
                "xctest-dynamic-overlay@1.9.0"
            ),
        ),
        fetcher=_fetcher(
            {
                api: b"{}",
                raw: (
                    b"MIT License\n\nPermission is hereby granted, free of charge, to any "
                    b"person obtaining a copy.\n\nTHE SOFTWARE IS PROVIDED AS IS."
                ),
            }
        ),
    )

    assert proposal is None
    assert record.outcome == "pending_verifier_support"
    assert record.machine_verification == "pending_verifier_support"
    assert record.likely_spdx == "MIT"
    assert record.browser_evidence[0].url == blob


def test_github_blob_license_url_canonicalizes_to_raw_fetch() -> None:
    api = "https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3"
    raw = "https://raw.githubusercontent.com/sentinel/acme-lib/1.2.3/LICENSE"
    blob = "https://github.com/sentinel/acme-lib/blob/1.2.3/LICENSE"
    fetched: list[str] = []

    record, proposal = research_context(
        _context(
            ecosystem="swiftpm",
            package="not-github-shaped",
            version="1.2.3",
            triage={
                "found_in": ["sentinel-alpha"],
                "spdx_id": "UNKNOWN",
                "evidence_url": blob,
            },
        ),
        fetcher=_tracking_fetcher(
            {
                api: b"{}",
                raw: (
                    b"MIT License\n\nPermission is hereby granted, free of charge.\n\n"
                    b"THE SOFTWARE IS PROVIDED AS IS."
                ),
            },
            fetched,
        ),
    )

    assert proposal is None
    assert raw in fetched
    assert record.human_candidate_spdx == "MIT"
    assert record.browser_evidence[0].url == blob


def test_bare_package_name_does_not_infer_github_lookup() -> None:
    fetched: list[str] = []

    record, proposal = research_context(
        _context(ecosystem="swiftpm", package="xctest-dynamic-overlay", version="1.9.0"),
        fetcher=_tracking_fetcher({}, fetched),
    )

    assert record.outcome == "no_public_evidence"
    assert proposal is None
    assert fetched == []


def test_review_markdown_has_one_row_per_context_row() -> None:
    record, _proposal = research_context(_context(), fetcher=_fetcher({}))

    markdown = render_review_markdown([record])

    assert markdown.count("| `acme-lib\\|UNKNOWN` |") == 1
    assert "no_public_evidence: 1" in markdown
    assert "agent:abstained" not in markdown


def test_run_research_reports_progress(tmp_path: Path) -> None:
    contexts_path = tmp_path / "shortlist.contexts.json"
    proposals_path = tmp_path / "shortlist.proposals.json"
    evidence_path = tmp_path / "shortlist.evidence.json"
    review_path = tmp_path / "shortlist.review.md"
    store.atomic_write_json(contexts_path, [_context()])
    progress: list[str] = []

    result = run_research(
        contexts_path=contexts_path,
        proposals_path=proposals_path,
        evidence_path=evidence_path,
        review_path=review_path,
        fetcher=_fetcher({}),
        progress=progress.append,
    )

    assert result.row_count == 1
    assert result.proposal_count == 0
    assert progress == [
        f"Reading shortlist contexts: {contexts_path}",
        "Loaded 1 shortlist context row(s).",
        "Researching 1/1: acme-lib|UNKNOWN",
        "Finished 1/1: no_public_evidence",
        f"Writing proposals: {proposals_path}",
        f"Writing evidence: {evidence_path}",
        f"Writing review notes: {review_path}",
        "Done: researched 1 row(s); proposals: 0.",
    ]


def test_load_context_rows_rejects_non_object_entries_with_index(tmp_path: Path) -> None:
    contexts_path = tmp_path / "shortlist.contexts.json"
    store.atomic_write_json(contexts_path, [_context(), "not-an-object"])

    with pytest.raises(ValueError, match=r"contexts\[1\] must be an object"):
        load_context_rows(contexts_path)
