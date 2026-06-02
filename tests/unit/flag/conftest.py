from __future__ import annotations

from typing import Any

import pytest

from repolens.flag.dedup import CollectedRecord


def _resolved_record(
    *,
    name: str = "acme-lib",
    version: str = "1.2.3",
    repo: str = "acme-alpha",
    spdx_id: str | None = "MIT",
    declared_license_raw: str | None = "MIT",
    origin: str = "third-party-oss",
    scope: str = "runtime",
    distribution: str = "server",
    modified: Any = "unknown",
    url: str | None = "https://example.invalid/licenses/mit",
    anchor: str = "MIT",
    purl: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "source_layer": "syft",
        "anchor": anchor,
        "fetched_at": "2026-01-01T00:00:00Z",
    }
    if url is not None:
        evidence["url"] = url
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "name": name,
        "version": version,
        "repo": repo,
        "declared_license_raw": declared_license_raw,
        "spdx_id": spdx_id,
        "evidence": evidence,
        "tags": {"origin": origin, "scope": scope, "distribution": distribution},
        "modified": modified,
    }
    if purl is not None:
        record["purl"] = purl
    return record


@pytest.fixture
def make_record():
    return _resolved_record


@pytest.fixture
def collected():
    def factory(
        records: list[dict[str, Any]], repo_dir: str = "acme-alpha"
    ) -> list[CollectedRecord]:
        return [
            CollectedRecord(data=record, repo_dir=repo_dir, ordinal=index)
            for index, record in enumerate(records, start=1)
        ]

    return factory
