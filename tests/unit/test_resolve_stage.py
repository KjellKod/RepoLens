from __future__ import annotations

import json
from pathlib import Path

from repolens.data.store import iter_resolved, replace_source_snapshot, write_sbom
from repolens.exit_codes import InputError
from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.resolve.mobile import MobileEnrichmentOutcome
from repolens.resolve.models import ApiCandidate, PackageFact, ResolveAdapter
from repolens.resolve.stage import ResolveCacheStats, run_resolve
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import FetchResult, HttpFetchOptions

GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

RESOLVER_COVERAGE_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "resolve" / "resolver_coverage"
)


class FailingAdapter:
    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        del package
        raise AssertionError("declared license should not call API adapters")


class CandidateAdapter:
    def __init__(self, candidate: ApiCandidate | None) -> None:
        self.candidate = candidate
        self.calls = 0

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        del package
        self.calls += 1
        return self.candidate


def public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def fetcher_with_body(body: bytes):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts
        return FetchResult(url=url, status=200, headers=(), body=body)

    return fetch


def write_test_sbom(
    tmp_path: Path,
    repo_ref: str,
    *,
    licenses: list[str] | None,
    version: str | None = "1.2.3",
    locations: list[str] | None = None,
    description: object | None = None,
) -> None:
    artifact: dict[str, object] = {
        "name": "acme-lib",
        "version": version,
        "type": "python",
        "purl": "pkg:pypi/acme-lib@1.2.3",
        "licenses": licenses or [],
        "locations": locations or ["requirements.txt"],
    }
    if version is None:
        artifact["version"] = None
    if description is not None:
        artifact["description"] = description
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/acme-alpha",
            "artifacts": [artifact],
        },
    )


def write_single_artifact_sbom(
    tmp_path: Path,
    repo_ref: str,
    artifact: dict[str, object],
) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/sentinel-source",
            "artifacts": [artifact],
        },
    )


def write_artifact_sbom(
    tmp_path: Path,
    repo_ref: str,
    artifacts: list[dict[str, object]],
) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/sentinel-source",
            "artifacts": artifacts,
        },
    )


def read_single_resolved(tmp_path: Path, repo_ref: str) -> dict[str, object]:
    path = tmp_path / "work" / repo_ref / "resolved.ndjson"
    return list(iter_resolved(path))[0]


def test_declared_spdx_license_writes_syft_resolved_record(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=["MIT"])

    run_resolve(tmp_path, repo_ref, adapters=[FailingAdapter()])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert record["declared_license_raw"] == "MIT"
    assert record["evidence"]["source_layer"] == "syft"


def test_declared_spdx_license_writes_brief_description_from_sbom(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(
        tmp_path,
        repo_ref,
        licenses=["MIT"],
        description="  A compact package description.\n",
    )

    run_resolve(tmp_path, repo_ref, adapters=[FailingAdapter()])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["description"] == "A compact package description."


def test_declared_spdx_license_enriches_brief_description_from_registry(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=["MIT"])
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"info":{"summary":"Brief registry summary."}}',
        )

    run_resolve(tmp_path, repo_ref, fetcher=fetcher)

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["description"] == "Brief registry summary."
    assert seen == ["https://pypi.org/pypi/acme-lib/1.2.3/json"]


def test_first_party_name_gets_origin_first_party(tmp_path: Path, repo_ref: str) -> None:
    # An unpublished workspace member: no declared license, no API candidate, so it
    # stays UNKNOWN — exactly the case that must be tagged first-party regardless of
    # resolution path.
    write_test_sbom(tmp_path, repo_ref, licenses=[])

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        first_party_reader=lambda _root, _ref: frozenset({"acme-lib"}),
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["tags"]["origin"] == "first-party"


def test_declared_first_party_name_gets_origin_first_party(tmp_path: Path, repo_ref: str) -> None:
    # The single stamp in run_resolve also covers the declared (syft) path.
    write_test_sbom(tmp_path, repo_ref, licenses=["MIT"])

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        first_party_reader=lambda _root, _ref: frozenset({"acme-lib"}),
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert record["tags"]["origin"] == "first-party"


def test_name_absent_from_first_party_set_stays_third_party(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=["MIT"])

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        first_party_reader=lambda _root, _ref: frozenset({"some-other-pkg"}),
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"]["origin"] == "third-party-oss"


def test_default_first_party_reader_treats_absent_sidecar_as_empty(
    tmp_path: Path, repo_ref: str
) -> None:
    # No first_party.json (old work-root): the default reader yields an empty set,
    # so every row stays third-party-oss.
    write_test_sbom(tmp_path, repo_ref, licenses=["MIT"])

    run_resolve(tmp_path, repo_ref, adapters=[FailingAdapter()])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"]["origin"] == "third-party-oss"


def test_api_candidate_requires_validated_matching_evidence(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
            description="Brief API package summary",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"licenses":["MIT"]}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "MIT"
    assert record["description"] == "Brief API package summary"


def test_api_resolution_uses_registry_description_when_first_license_api_has_none(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        if url == "https://pypi.org/pypi/acme-lib/1.2.3/json":
            body = b'{"info":{"summary":"Brief registry summary.","license":"MIT"}}'
        else:
            body = b'{"license":"MIT"}'
        return FetchResult(url=url, status=200, headers=(), body=body)

    run_resolve(
        tmp_path,
        repo_ref,
        fetcher=fetcher,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert record["description"] == "Brief registry summary."
    assert seen == [
        "https://pypi.org/pypi/acme-lib/1.2.3/json",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
    ]


def test_duplicate_api_resolution_reuses_lookup_but_rebuilds_records(
    tmp_path: Path, repo_ref: str
) -> None:
    write_artifact_sbom(
        tmp_path,
        repo_ref,
        [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [],
                "locations": ["requirements.txt"],
            },
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [],
                "locations": ["requirements-dev.txt"],
            },
        ],
    )
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
        )
    )
    fetch_calls: list[str] = []

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetch_calls.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"licenses":["MIT"]}')

    stats = ResolveCacheStats()
    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetch,
        evidence_resolver=public_resolver,
        cache_stats=stats,
    )

    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert adapter.calls == 1
    assert len(fetch_calls) == 1
    assert stats.api_hits == 1
    assert [record["spdx_id"] for record in records] == ["MIT", "MIT"]
    assert records[0]["tags"] == {
        "origin": "third-party-oss",
        "scope": "runtime",
        "distribution": "server",
    }
    assert records[1]["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }
    assert [record["repo"] for record in records] == [repo_ref, repo_ref]
    assert [record["purl"] for record in records] == [
        "pkg:pypi/acme-lib@1.2.3",
        "pkg:pypi/acme-lib@1.2.3",
    ]


def test_api_miss_cache_does_not_skip_scancode_when_source_root_available(
    tmp_path: Path, repo_ref: str
) -> None:
    write_artifact_sbom(
        tmp_path,
        repo_ref,
        [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [],
                "locations": ["vendor/acme-lib/package.py"],
            },
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [],
                "locations": ["vendor/acme-lib/package.py"],
            },
        ],
    )
    source_root = tmp_path / "source"
    package_dir = source_root / "vendor" / "acme-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "package.py").write_text("print('fixture')\n", encoding="utf-8")
    (package_dir / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    scancode_calls: list[list[str]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        scancode_calls.append(list(argv))
        return type(
            "Completed",
            (),
            {"returncode": 0, "stdout": '{"files":[{"license_expression_spdx":"Apache-2.0"}]}'},
        )()

    stats = ResolveCacheStats()
    run_resolve(
        tmp_path,
        repo_ref,
        source_root=source_root,
        adapters=[],
        scancode_runner=runner,
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
        cache_stats=stats,
    )

    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert stats.api_hits == 1
    assert len(scancode_calls) == 2
    assert [record["spdx_id"] for record in records] == ["Apache-2.0", "Apache-2.0"]


def test_api_candidate_accepts_equivalent_compound_expression_evidence(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="Apache-2.0 OR MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/cargo/packages/anyhow/versions/1.0.98",
            evidence_anchor="Apache-2.0 OR MIT",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"license":"MIT OR Apache-2.0"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "Apache-2.0 OR MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "Apache-2.0 OR MIT"


def test_equivalent_compound_api_candidates_do_not_conflict(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    first = CandidateAdapter(
        ApiCandidate(
            spdx_id="Apache-2.0 OR MIT",
            evidence_url="https://api.deps.dev/v3alpha/one",
            evidence_anchor="Apache-2.0 OR MIT",
        )
    )
    second = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT OR Apache-2.0",
            evidence_url="https://api.deps.dev/v3alpha/two",
            evidence_anchor="MIT OR Apache-2.0",
        )
    )

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        body = (
            b'{"license":"Apache-2.0 OR MIT"}'
            if url.endswith("/one")
            else b'{"license":"MIT OR Apache-2.0"}'
        )
        return FetchResult(url=url, status=200, headers=(), body=body)

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[first, second],
        fetcher=fetch,
        evidence_resolver=public_resolver,
        detect_conflicts=True,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "Apache-2.0 OR MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "Apache-2.0 OR MIT"


def test_malformed_api_expression_lowers_unresolved_without_fetch(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT OR (Apache-2.0",
            evidence_url="https://api.deps.dev/v3alpha/systems/cargo/packages/anyhow/versions/1.0.98",
            evidence_anchor="MIT OR (Apache-2.0",
        )
    )
    fetched: list[str] = []

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetched.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"MIT"}')

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetch,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert fetched == []
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "unresolved:evidence_mismatch"


def test_unknown_with_exception_lowers_unresolved_without_fetch(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="GPL-3.0-only WITH Unknown-exception",
            evidence_url="https://api.deps.dev/v3alpha/systems/cargo/packages/acme-lib/versions/1.2.3",
            evidence_anchor="GPL-3.0-only WITH Unknown-exception",
        )
    )
    fetched: list[str] = []

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetched.append(url)
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"license":"GPL-3.0-only WITH Unknown-exception"}',
        )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetch,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert fetched == []
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "unresolved:evidence_mismatch"


def test_known_with_exception_resolves_and_verifies(tmp_path: Path, repo_ref: str) -> None:
    expression = "GPL-3.0-only WITH Autoconf-exception-3.0"
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id=expression,
            evidence_url="https://api.deps.dev/v3alpha/systems/cargo/packages/acme-lib/versions/1.2.3",
            evidence_anchor=expression,
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"license":"GPL-3.0-only WITH Autoconf-exception-3.0"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == expression
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == expression


def test_known_llvm_exception_resolves_and_verifies(tmp_path: Path, repo_ref: str) -> None:
    expression = "Apache-2.0 WITH LLVM-exception"
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id=expression,
            evidence_url="https://api.deps.dev/v3alpha/systems/cargo/packages/acme-lib/versions/1.2.3",
            evidence_anchor=expression,
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"license":"Apache-2.0 WITH LLVM-exception"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == expression
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == expression


def test_api_candidate_lowers_mismatched_evidence(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"licenses":["Apache-2.0"]}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "unresolved:evidence_mismatch"


def test_api_candidate_rejects_similar_spdx_substrings(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"license":"MIT-0"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["anchor"] == "unresolved:evidence_mismatch"


def test_rejected_credential_evidence_url_is_not_written(tmp_path: Path, repo_ref: str) -> None:
    secret = "plainsecret"
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url=(
                f"https://user:{secret}@api.deps.dev/v3alpha/systems/pypi/"
                "packages/acme-lib/versions/1.2.3"
            ),
            evidence_anchor="MIT",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(b'{"license":"MIT"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert "url" not in record["evidence"]
    text = (tmp_path / "work" / repo_ref / "resolved.ndjson").read_text(encoding="utf-8")
    assert secret not in text


def test_api_ladder_continues_after_unverified_candidate(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    bad = CandidateAdapter(
        ApiCandidate("MIT", "https://offlist.example.invalid/licenses/acme-lib", "MIT")
    )
    good = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[bad, good],
        fetcher=fetcher_with_body(b'{"licenses":["MIT"]}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert bad.calls == 1
    assert good.calls == 1


def test_api_ladder_short_circuits_after_first_verified_candidate(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    first = CandidateAdapter(ApiCandidate("MIT", "https://api.deps.dev/v3alpha/one", "MIT"))
    second = CandidateAdapter(
        ApiCandidate("Apache-2.0", "https://api.deps.dev/v3alpha/two", "Apache-2.0")
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[first, second],
        fetcher=fetcher_with_body(b'{"license":"MIT"}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert first.calls == 1
    assert second.calls == 0


def test_run_resolve_reports_progress_for_each_package(tmp_path: Path, repo_ref: str) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/progress",
            "artifacts": [
                {
                    "name": "declared-one",
                    "version": "1.0.0",
                    "type": "python",
                    "licenses": ["MIT"],
                },
                {
                    "name": "declared-two",
                    "version": "2.0.0",
                    "type": "python",
                    "licenses": ["Apache-2.0"],
                },
            ],
        },
    )
    events: list[tuple[int, int, str]] = []

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        progress=lambda index, total, package_name: events.append((index, total, package_name)),
    )

    assert events == [(1, 2, "declared-one"), (2, 2, "declared-two")]


def test_non_pypi_missing_or_null_version_becomes_unknown_without_api_fetch(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-maven-runtime",
            "version": None,
            "type": "maven",
            "purl": "pkg:maven/invalid.sentinel/sentinel-maven-runtime",
            "licenses": [],
        },
    )
    adapter = CandidateAdapter(ApiCandidate("MIT", "https://api.deps.dev/example", "MIT"))

    run_resolve(tmp_path, repo_ref, adapters=[adapter])

    record = read_single_resolved(tmp_path, repo_ref)
    assert adapter.calls == 0
    assert record["version"] == "unknown"
    assert record["spdx_id"] is None
    assert record["evidence"]["anchor"] == "unresolved:missing_version"
    assert "declared_version_status" not in record


def test_declared_unpinned_pyproject_status_is_stamped_after_resolution(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-runtime",
            "version": None,
            "type": "python",
            "purl": "pkg:pypi/sentinel-runtime",
            "licenses": [],
            "locations": ["pyproject.toml"],
            "declared_version_status": "declared-unpinned",
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[CandidateAdapter(None)])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["version"] == "unknown"
    assert record["declared_version_status"] == "declared-unpinned"
    assert record["evidence"]["anchor"] == "unresolved:no_candidate"


def test_declared_unpinned_marker_on_exact_version_is_not_stamped(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-runtime",
            "version": "1.2.3",
            "type": "python",
            "purl": "pkg:pypi/sentinel-runtime@1.2.3",
            "licenses": ["MIT"],
            "locations": ["pyproject.toml"],
            "declared_version_status": "declared-unpinned",
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[FailingAdapter()])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["version"] == "1.2.3"
    assert "declared_version_status" not in record


def test_unversioned_pypi_package_resolves_from_package_metadata(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-runtime",
            "version": None,
            "type": "python",
            "purl": "pkg:pypi/sentinel-runtime",
            "licenses": [],
            "locations": ["pyproject.toml"],
        },
    )
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"info":{"license":"MIT"}}')

    run_resolve(
        tmp_path,
        repo_ref,
        fetcher=fetcher,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["version"] == "unknown"
    assert record["spdx_id"] == "MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["url"] == "https://pypi.org/pypi/sentinel-runtime/json"
    assert seen == [
        "https://pypi.org/pypi/sentinel-runtime/json",
        "https://pypi.org/pypi/sentinel-runtime/json",
        "https://pypi.org/pypi/sentinel-runtime/json",
    ]


def test_swiftpm_purl_resolves_from_package_resolved_metadata(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-swift-runtime",
            "version": "1.0.0",
            "type": "swift",
            "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
            "licenses": [],
            "locations": ["Package.resolved"],
        },
    )
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Package.resolved").write_text(
        json.dumps(
            {
                "pins": [
                    {
                        "identity": "sentinel-swift-runtime",
                        "kind": "remoteSourceControl",
                        "location": "https://github.com/example/sentinel-swift-runtime.git",
                        "state": {"version": "1.0.0", "revision": "abc123"},
                    }
                ],
                "version": 3,
            }
        ),
        encoding="utf-8",
    )
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        assert options.headers == GITHUB_API_HEADERS
        seen.append(url)
        return FetchResult(
            url=url,
            status=200,
            headers=(),
            body=b'{"license":{"spdx_id":"MIT"}}',
        )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        source_root=source_root,
        fetcher=fetcher,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert seen == [
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
    ]
    assert record["spdx_id"] == "MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["url"] == (
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123"
    )
    assert record["evidence"]["anchor"] == "MIT"


def test_duplicate_swiftpm_metadata_reuses_api_cache_but_rebuilds_records(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_artifact_sbom(
        tmp_path,
        repo_ref,
        [
            {
                "name": "sentinel-swift-runtime",
                "version": "1.0.0",
                "type": "swift",
                "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
                "licenses": [],
                "locations": ["Package.resolved"],
            },
            {
                "name": "sentinel-swift-runtime",
                "version": "1.0.0",
                "type": "swift",
                "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
                "licenses": [],
                "locations": ["Package.resolved"],
            },
        ],
    )
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Package.resolved").write_text(
        json.dumps(
            {
                "pins": [
                    {
                        "identity": "sentinel-swift-runtime",
                        "kind": "remoteSourceControl",
                        "location": "https://github.com/example/sentinel-swift-runtime.git",
                        "state": {"version": "1.0.0", "revision": "abc123"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    fetch_calls: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        fetch_calls.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":{"spdx_id":"MIT"}}')

    stats = ResolveCacheStats()
    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        source_root=source_root,
        fetcher=fetcher,
        evidence_resolver=public_resolver,
        cache_stats=stats,
    )

    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert fetch_calls == [
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
    ]
    assert stats.api_hits == 1
    assert [record["spdx_id"] for record in records] == ["MIT", "MIT"]
    assert [record["evidence"]["url"] for record in records] == [
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
    ]


def test_swiftpm_purl_with_mobile_native_opt_in_uses_mobile_enricher(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-swift-runtime",
            "version": "1.0.0",
            "type": "swift",
            "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
            "licenses": [],
        },
    )
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Package.swift").write_text(
        "// swift-tools-version: 5.9\n"
        "import PackageDescription\n"
        'let package = Package(name: "SentinelClient")\n',
        encoding="utf-8",
    )
    calls: list[PackageFact] = []

    def mobile_enricher(
        package: PackageFact,
        detection: object,
        root: Path,
        sandbox_runner: object,
        limits: object,
    ) -> MobileEnrichmentOutcome:
        del detection, root, sandbox_runner, limits
        calls.append(package)
        return MobileEnrichmentOutcome(
            candidate=ApiCandidate("MIT", "mobile-native://sandbox", "license:mit")
        )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        source_root=source_root,
        enable_mobile_native=True,
        mobile_enricher=mobile_enricher,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert [package.name for package in calls] == ["sentinel-swift-runtime"]
    assert record["spdx_id"] == "MIT"
    assert record["evidence"]["source_layer"] == "mobile"
    assert record["evidence"]["anchor"] == "license:mit"


def test_cocoapods_purl_resolves_from_exact_trunk_metadata(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "SentinelPodRuntime",
            "version": "2.0.0",
            "type": "cocoapods",
            "purl": "pkg:cocoapods/SentinelPodRuntime@2.0.0",
            "licenses": [],
        },
    )
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        assert options.allowed_hosts == API_ALLOWED_HOSTS
        seen.append(url)
        return FetchResult(url=url, status=200, headers=(), body=b'{"license":"Apache-2.0"}')

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[FailingAdapter()],
        fetcher=fetcher,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert seen == [
        "https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0",
        "https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0",
    ]
    assert record["spdx_id"] == "Apache-2.0"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "Apache-2.0"


def test_mobile_metadata_miss_without_native_stays_no_supported_catalog_api(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-swift-runtime",
            "version": "1.0.0",
            "type": "swift",
            "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
            "licenses": [],
        },
    )

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        raise AssertionError(f"unexpected fetch: {url} {options}")

    run_resolve(tmp_path, repo_ref, adapters=[FailingAdapter()], fetcher=fetcher)

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "unresolved:no_supported_catalog_license_api"


def test_githubactions_purl_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-ci-owner/sentinel-ci-action",
            "version": "v1",
            "type": "githubactions",
            "purl": "pkg:githubactions/sentinel-ci-owner/sentinel-ci-action@v1",
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }
    assert record["evidence"]["anchor"] == "unresolved:no_candidate"


def test_syft_github_action_shape_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-ci-owner/sentinel-ci-action",
            "version": "v1",
            "type": "github-action",
            "purl": "pkg:github/sentinel-ci-owner/sentinel-ci-action@v1",
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }
    assert record["evidence"]["anchor"] == "unresolved:no_candidate"


def test_build_tool_locations_get_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-build-tool",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-build-tool@1.0.0",
            "locations": ["/requirements-dev.txt"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }


def test_pyproject_dev_optional_dependency_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-dev-extra",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-dev-extra@1.0.0",
            "locations": ["pyproject.toml#project.optional-dependencies.dev"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }


def test_mixed_runtime_and_build_locations_keep_runtime_scope(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-shared-runtime",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-shared-runtime@1.0.0",
            "locations": ["/requirements-dev.txt", "/requirements.txt"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "runtime",
        "distribution": "server",
    }


def test_scancode_bootstrap_tooling_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-scancode-tool",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-scancode-tool@1.0.0",
            "locations": ["/src/repolens/bootstrap/scancode.requirements.txt"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }


def test_synthetic_fixture_dependency_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-fixture-lib",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-fixture-lib@1.0.0",
            "locations": ["/tests/fixtures/synthetic/fixture_requirements.txt"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }


def test_bootstrap_fixture_dependency_gets_build_scope_not_distributed(
    tmp_path: Path,
    repo_ref: str,
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "sentinel-bootstrap-fixture",
            "version": "1.0.0",
            "type": "python",
            "purl": "pkg:pypi/sentinel-bootstrap-fixture@1.0.0",
            "locations": ["/tests/bootstrap/fixtures/requirements.nohash.bad.txt"],
            "licenses": [],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["tags"] == {
        "origin": "third-party-oss",
        "scope": "build",
        "distribution": "not-distributed",
    }


def test_token_shaped_api_payload_is_redacted_from_resolved_artifact(
    tmp_path: Path, repo_ref: str
) -> None:
    token = "ghp_" + "A" * 24
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor=f"MIT {token}",
        )
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=fetcher_with_body(f'{{"license":"MIT {token}"}}'.encode()),
        evidence_resolver=public_resolver,
    )

    text = (tmp_path / "work" / repo_ref / "resolved.ndjson").read_text(encoding="utf-8")
    assert token not in text


def test_fetch_security_failure_lowers_unresolved(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    adapter = CandidateAdapter(
        ApiCandidate(
            spdx_id="MIT",
            evidence_url="https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_anchor="MIT",
        )
    )

    def failing_fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del url, options
        raise FetchSecurityError("response body exceeds size cap")

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[adapter],
        fetcher=failing_fetcher,
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["anchor"] == "unresolved:evidence_mismatch"


def test_default_path_uses_stored_source_snapshot_for_scancode(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "fixture-lib",
            "version": None,
            "type": "unknown",
            "licenses": [],
            "locations": ["vendor/fixture-lib/package.json"],
        },
    )
    staged = tmp_path / "staged-source"
    package_dir = staged / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text('{"name":"fixture-lib"}\n', encoding="utf-8")
    replace_source_snapshot(tmp_path, repo_ref, staged)

    def runner(argv: list[str], *, timeout: float):
        del argv, timeout
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"files":[{"license_expression_spdx":"Apache-2.0"}]}',
                "stderr": "",
            },
        )()

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        scancode_runner=runner,
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "Apache-2.0"
    assert record["evidence"]["source_layer"] == "scancode"


def test_android_mobile_repo_unresolved_dependency_falls_back_to_scancode(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "invalid.sentinel:sentinel-android-runtime",
            "version": "3.1.4",
            "type": "maven",
            "purl": "pkg:maven/invalid.sentinel/sentinel-android-runtime@3.1.4",
            "licenses": [],
            "locations": ["app/gradle.lockfile"],
        },
    )
    staged = tmp_path / "staged-source"
    app_dir = staged / "app"
    app_dir.mkdir(parents=True)
    (staged / "settings.gradle").write_text(
        "pluginManagement { repositories {} }\n", encoding="utf-8"
    )
    (staged / "build.gradle").write_text(
        "plugins { id 'com.android.application' version '8.0.0' apply false }\n",
        encoding="utf-8",
    )
    (app_dir / "gradle.lockfile").write_text(
        "invalid.sentinel:sentinel-android-runtime:3.1.4=runtimeClasspath\n",
        encoding="utf-8",
    )
    replace_source_snapshot(tmp_path, repo_ref, staged)
    calls: list[list[str]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        calls.append(argv)
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"files":[{"license_expression_spdx":"Apache-2.0"}]}',
                "stderr": "",
            },
        )()

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        scancode_runner=runner,
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    record = read_single_resolved(tmp_path, repo_ref)
    snapshot_app_dir = tmp_path / "work" / repo_ref / "source.snapshot" / "app"
    assert record["spdx_id"] == "Apache-2.0"
    assert record["evidence"]["source_layer"] == "scancode"
    assert calls
    assert str(snapshot_app_dir.resolve()) in calls[0]
    assert str((tmp_path / "work" / repo_ref / "source.snapshot").resolve()) not in calls[0]


def test_root_manifest_only_stored_snapshot_does_not_scan_repo_root(
    tmp_path: Path, repo_ref: str
) -> None:
    write_single_artifact_sbom(
        tmp_path,
        repo_ref,
        {
            "name": "fixture-lib",
            "version": None,
            "type": "unknown",
            "licenses": [],
            "locations": ["package.json"],
        },
    )
    staged = tmp_path / "staged-source"
    staged.mkdir()
    (staged / "package.json").write_text('{"name":"root"}\n', encoding="utf-8")
    replace_source_snapshot(tmp_path, repo_ref, staged)

    def fail_runner(*args: object, **kwargs: object) -> object:
        raise AssertionError("root-only manifest must not invoke ScanCode over repo root")

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        scancode_runner=fail_runner,  # type: ignore[arg-type]
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "scancode"
    assert record["evidence"]["anchor"] == "unresolved:scancode_no_target"


def test_resolver_coverage_fixture_moves_targets_from_no_candidate_to_resolved(
    tmp_path: Path, repo_ref: str
) -> None:
    sbom = json.loads((RESOLVER_COVERAGE_FIXTURE / "sbom.syft.json").read_text(encoding="utf-8"))
    before_root = tmp_path / "before"
    write_sbom(before_root, repo_ref, sbom)
    run_resolve(before_root, repo_ref, adapters=[])
    before_records = list(iter_resolved(before_root / "work" / repo_ref / "resolved.ndjson"))
    assert all(
        record["evidence"]["anchor"] == "unresolved:no_candidate" for record in before_records
    )

    write_sbom(tmp_path, repo_ref, sbom)
    expected_payloads = {
        "https://api.deps.dev/v3alpha/systems/cargo/packages/anyhow/versions/1.0.98": (
            b'{"license":"Apache-2.0 OR MIT"}'
        ),
        "https://api.deps.dev/v3alpha/systems/cargo/packages/either/versions/1.15.0": (
            b'{"licenses":["Apache-2.0 OR MIT"]}'
        ),
        "https://api.deps.dev/v3alpha/systems/npm/packages/"
        "@img%2Fsharp-win32-x64/versions/0.33.5": (
            b'{"license":"Apache-2.0 AND LGPL-3.0-or-later"}'
        ),
    }
    expected_description_urls = {
        "https://crates.io/api/v1/crates/anyhow",
        "https://crates.io/api/v1/crates/either",
        "https://registry.npmjs.org/@img%2Fsharp-win32-x64/0.33.5",
    }
    seen: list[str] = []

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        body = expected_payloads.get(url, b"{}")
        return FetchResult(url=url, status=200, headers=(), body=body)

    run_resolve(
        tmp_path,
        repo_ref,
        fetcher=fetch,
        evidence_resolver=public_resolver,
    )

    records = {
        str(record["name"]): record
        for record in iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson")
    }
    assert records["anyhow"]["spdx_id"] == "Apache-2.0 OR MIT"
    assert records["either"]["spdx_id"] == "Apache-2.0 OR MIT"
    assert records["@img/sharp-win32-x64"]["spdx_id"] == "Apache-2.0 AND LGPL-3.0-or-later"
    assert all(
        record["evidence"]["anchor"] != "unresolved:no_candidate" for record in records.values()
    )
    assert set(seen) == set(expected_payloads) | expected_description_urls


def test_p3b_scancode_runs_only_for_unresolved_package_with_locations(
    tmp_path: Path, repo_ref: str
) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/fixture",
            "artifacts": [
                {
                    "name": "declared-lib",
                    "version": "1.0.0",
                    "type": "python",
                    "licenses": ["MIT"],
                    "locations": ["declared/package.py"],
                },
                {
                    "name": "unknown-lib",
                    "version": "2.0.0",
                    "type": "python",
                    "licenses": [],
                    "locations": ["unknown/package.py"],
                },
            ],
        },
    )
    source_root = tmp_path / "source"
    (source_root / "unknown").mkdir(parents=True)
    (source_root / "unknown" / "package.py").write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        calls.append(argv)
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"files":[{"license_expression_spdx":"Apache-2.0"}]}',
                "stderr": "",
            },
        )()

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        source_root=source_root,
        scancode_runner=runner,
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"
    assert records[1]["spdx_id"] == "Apache-2.0"
    assert records[1]["evidence"]["source_layer"] == "scancode"
    assert len(calls) == 1
    assert str(source_root / "unknown") in calls[0]
    assert str(source_root) not in calls[0]


def test_p3b_mobile_native_requires_opt_in(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[], locations=[])
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "build.gradle").write_text(
        "plugins { id 'com.android.application' }", encoding="utf-8"
    )

    def fail_mobile(*args: object) -> MobileEnrichmentOutcome:
        raise AssertionError("mobile native should be off by default")

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        source_root=source_root,
        mobile_enricher=fail_mobile,
        scancode_executable_provider=lambda work_root: (_ for _ in ()).throw(
            InputError("no scancode")
        ),
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["evidence"]["source_layer"] == "scancode"
    assert record["evidence"]["anchor"] == "unresolved:scancode_tool_unavailable"


def test_p3b_missing_mobile_sandbox_lowers_to_mobile_unresolved(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[], locations=[])
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "settings.gradle").write_text(
        "pluginManagement { repositories { google() } }\n"
        "plugins { id 'com.android.library' version '1.0.0' }",
        encoding="utf-8",
    )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        source_root=source_root,
        enable_mobile_native=True,
        scancode_executable_provider=lambda work_root: (_ for _ in ()).throw(
            InputError("no scancode")
        ),
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] is None
    assert record["evidence"]["source_layer"] == "mobile"
    assert record["evidence"]["anchor"] == "unresolved:mobile_sandbox_unavailable"


def test_p3b_mobile_conflict_writes_mobile_conflict(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[], locations=[])
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "build.gradle").write_text(
        "plugins { id 'com.android.application' }", encoding="utf-8"
    )

    def mobile_conflict(
        package: PackageFact,
        detection: object,
        source_root: Path,
        sandbox_runner: object,
        limits: object,
    ) -> MobileEnrichmentOutcome:
        del package, detection, source_root, sandbox_runner, limits
        return MobileEnrichmentOutcome(
            candidate=ApiCandidate(
                "CONFLICT",
                "mobile-native://sandbox",
                "conflict:mobile_disagreement",
            )
        )

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[],
        source_root=source_root,
        enable_mobile_native=True,
        mobile_enricher=mobile_conflict,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "CONFLICT"
    assert record["evidence"]["source_layer"] == "mobile"
    assert record["evidence"]["anchor"] == "conflict:mobile_disagreement"


def test_detect_conflicts_cross_checks_api_disagreement(tmp_path: Path, repo_ref: str) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[])
    first = CandidateAdapter(ApiCandidate("MIT", "https://api.deps.dev/v3alpha/one", "MIT"))
    second = CandidateAdapter(
        ApiCandidate("Apache-2.0", "https://api.deps.dev/v3alpha/two", "Apache-2.0")
    )

    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        body = b'{"license":"MIT"}' if url.endswith("/one") else b'{"license":"Apache-2.0"}'
        return FetchResult(url=url, status=200, headers=(), body=body)

    run_resolve(
        tmp_path,
        repo_ref,
        adapters=[first, second],
        fetcher=fetch,
        evidence_resolver=public_resolver,
        detect_conflicts=True,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "CONFLICT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "conflict:api_disagreement"
    assert first.calls == 1
    assert second.calls == 1


def test_unsupported_package_lowers_unresolved(tmp_path: Path, repo_ref: str) -> None:
    write_sbom(
        tmp_path,
        repo_ref,
        {
            "schema_version": "1.0",
            "repo": repo_ref,
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.0.0"},
            "source": "https://example.invalid/acme-alpha",
            "artifacts": [
                {
                    "name": "acme-lib",
                    "version": "",
                    "type": "unknown",
                    "licenses": ["NOASSERTION"],
                }
            ],
        },
    )

    run_resolve(tmp_path, repo_ref, adapters=[])

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["version"] == "unknown"
    assert record["spdx_id"] is None


def test_adapter_protocol_is_narrow() -> None:
    adapter: ResolveAdapter = CandidateAdapter(None)
    assert (
        adapter.resolve(PackageFact("acme-lib", "1.0.0", "python", "acme-alpha", None, None))
        is None
    )
