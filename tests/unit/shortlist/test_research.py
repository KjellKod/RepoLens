from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data import store
from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.research import load_context_rows, render_review_markdown, research_context


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


def test_review_markdown_has_one_row_per_context_row() -> None:
    record, _proposal = research_context(_context(), fetcher=_fetcher({}))

    markdown = render_review_markdown([record])

    assert markdown.count("| `acme-lib\\|UNKNOWN` |") == 1
    assert "no_public_evidence: 1" in markdown
    assert "agent:abstained" not in markdown


def test_load_context_rows_rejects_non_object_entries_with_index(tmp_path: Path) -> None:
    contexts_path = tmp_path / "shortlist.contexts.json"
    store.atomic_write_json(contexts_path, [_context(), "not-an-object"])

    with pytest.raises(ValueError, match=r"contexts\[1\] must be an object"):
        load_context_rows(contexts_path)
