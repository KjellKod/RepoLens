from __future__ import annotations

from pathlib import Path

from repolens.data.store import iter_resolved, write_sbom
from repolens.resolve.models import ApiCandidate, PackageFact, ResolveAdapter
from repolens.resolve.stage import run_resolve
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import FetchResult, HttpFetchOptions


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
) -> None:
    artifact: dict[str, object] = {
        "name": "acme-lib",
        "version": version,
        "type": "python",
        "purl": "pkg:pypi/acme-lib@1.2.3",
        "licenses": licenses or [],
        "locations": ["requirements.txt"],
    }
    if version is None:
        artifact["version"] = None
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


def test_api_candidate_requires_validated_matching_evidence(tmp_path: Path, repo_ref: str) -> None:
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
        fetcher=fetcher_with_body(b'{"licenses":["MIT"]}'),
        evidence_resolver=public_resolver,
    )

    record = read_single_resolved(tmp_path, repo_ref)
    assert record["spdx_id"] == "MIT"
    assert record["evidence"]["source_layer"] == "api"
    assert record["evidence"]["anchor"] == "MIT"


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


def test_missing_or_null_version_becomes_unknown_without_api_fetch(
    tmp_path: Path, repo_ref: str
) -> None:
    write_test_sbom(tmp_path, repo_ref, licenses=[], version=None)
    adapter = CandidateAdapter(ApiCandidate("MIT", "https://api.deps.dev/example", "MIT"))

    run_resolve(tmp_path, repo_ref, adapters=[adapter])

    record = read_single_resolved(tmp_path, repo_ref)
    assert adapter.calls == 0
    assert record["version"] == "unknown"
    assert record["spdx_id"] is None
    assert record["evidence"]["anchor"] == "unresolved:missing_version"


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
