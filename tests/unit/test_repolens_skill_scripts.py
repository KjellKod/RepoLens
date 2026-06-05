from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from repolens.security.http_client import FetchResult, HttpFetchOptions


def _load_skill_script(repo_root: Path, name: str) -> ModuleType:
    path = repo_root / ".skills" / "repolens" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"repolens_skill_{name}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def test_generate_shortlist_proposals_proposes_verified_exact_license(repo_root: Path) -> None:
    script = _load_skill_script(repo_root, "generate_shortlist_proposals")
    deps_url = "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3"
    contexts = [
        {
            "component_ref": "acme-lib|UNKNOWN",
            "triage": {
                "spdx_id": "UNKNOWN",
                "evidence_url": "pkg:pypi/acme-lib@1.2.3",
                "found_in": ["acme-alpha"],
            },
        },
        {
            "component_ref": "copyleft-lib|GPL-3.0-only",
            "triage": {
                "spdx_id": "GPL-3.0-only",
                "evidence_url": deps_url,
                "evidence_anchor": "GPL-3.0-only",
            },
        },
        {
            "component_ref": "Pods/Thing|UNKNOWN",
            "triage": {
                "spdx_id": "UNKNOWN",
                "evidence_url": "pkg:cocoapods/Thing@1.0.0",
            },
        },
    ]

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        assert url == deps_url
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    result = script.generate_proposals(
        contexts,
        fetcher=fetcher,
        evidence_resolver=_public_resolver,
    )

    assert result.stats == {
        "proposed": 1,
        "confirmed-needs-review": 1,
        "abstained": 1,
    }
    assert result.proposals[0]["component_ref"] == "acme-lib|UNKNOWN"
    assert result.proposals[0]["spdx_id"] == "MIT"
    assert result.proposals[0]["evidence_url"] == deps_url
    assert result.proposals[1]["abstain"] is True
    assert result.review_rows[1].outcome == "confirmed-needs-review"
    assert result.proposals[2]["abstain"] is True
    assert "cataloged only" in result.proposals[2]["reason"]
    assert result.fetch_count == 1


def test_generate_shortlist_proposals_preserves_go_semantic_import_suffix(
    repo_root: Path,
) -> None:
    script = _load_skill_script(repo_root, "generate_shortlist_proposals")
    expected_url = (
        "https://api.deps.dev/v3alpha/systems/go/packages/"
        "github.com%2Fcenkalti%2Fbackoff%2Fv4/versions/v4.3.0"
    )
    contexts = [
        {
            "component_ref": "github.com/cenkalti/backoff/v4|UNKNOWN",
            "triage": {
                "spdx_id": "UNKNOWN",
                "evidence_url": "pkg:golang/github.com/cenkalti/backoff@v4.3.0#v4",
            },
        }
    ]
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    result = script.generate_proposals(
        contexts,
        fetcher=fetcher,
        evidence_resolver=_public_resolver,
    )

    assert result.proposals[0]["spdx_id"] == "MIT"
    assert result.proposals[0]["evidence_url"] == expected_url
    assert seen == [expected_url]


def test_generate_shortlist_proposals_reports_duplicate_inputs(repo_root: Path) -> None:
    script = _load_skill_script(repo_root, "generate_shortlist_proposals")
    contexts = [
        {"component_ref": "acme-lib|UNKNOWN", "triage": {"evidence_url": "not-a-purl"}},
        {"component_ref": "acme-lib|UNKNOWN", "triage": {"evidence_url": "not-a-purl"}},
    ]

    result = script.generate_proposals(contexts, fetcher=lambda *_args: None)

    assert result.duplicate_component_refs == {"acme-lib|UNKNOWN": 2}
    assert result.duplicate_evidence_urls == {"not-a-purl": 2}
    assert result.stats["abstained"] == 2


def test_inspect_evidence_uses_repolens_candidate_extraction(repo_root: Path) -> None:
    script = _load_skill_script(repo_root, "inspect_evidence")
    polaris_url = "https://registry.npmjs.org/%40shopify%2Fpolaris/10.50.1"
    callsite_url = "https://registry.npmjs.org/callsite/1.0.0"
    bodies = {
        polaris_url: b'{"license":"SEE LICENSE IN LICENSE.md"}',
        callsite_url: b"{}",
    }

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert "registry.npmjs.org" in options.allowed_hosts
        return FetchResult(url=url, status=200, headers=(), body=bodies[url])

    rows = script.inspect_urls([polaris_url, callsite_url], fetcher=fetcher)

    assert rows[0]["candidates"] == ["SEE LICENSE IN LICENSE.md"]
    assert rows[0]["raw_fields"] == {"license": "SEE LICENSE IN LICENSE.md"}
    assert rows[1]["candidates"] == []
    assert rows[1]["raw_fields"] == {}
