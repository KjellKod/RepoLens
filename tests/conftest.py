from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def block_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("live network is disabled for security tests")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_connect)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def synthetic_fixture_root(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "synthetic"


@pytest.fixture(scope="session")
def fixture_manifest_path(synthetic_fixture_root: Path) -> Path:
    return synthetic_fixture_root / "fixture_manifest.json"


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )


def create_local_repo(root: Path, *, gitmodules: str | None = None) -> Path:
    repo = root / "acme-source"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "acme@example.invalid")
    git(repo, "config", "user.name", "Acme Tester")
    (repo / "README.md").write_text("acme fixture\n", encoding="utf-8")
    if gitmodules is not None:
        (repo / ".gitmodules").write_text(gitmodules, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


@pytest.fixture
def local_repo_factory(tmp_path: Path):
    def factory(*, gitmodules: str | None = None) -> Path:
        return create_local_repo(tmp_path, gitmodules=gitmodules)

    return factory


@pytest.fixture
def repo_ref() -> str:
    return "acme-alpha"


@pytest.fixture
def sbom(repo_ref: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "repo": repo_ref,
        "generated_at": "2026-01-01T00:00:00Z",
        "tool": {"name": "syft", "version": "1.0.0"},
        "source": "https://example.invalid/acme-alpha",
        "artifacts": [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": ["MIT"],
                "locations": ["requirements.txt"],
            }
        ],
    }


@pytest.fixture
def resolved_record(repo_ref: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "name": "acme-lib",
        "version": "1.2.3",
        "repo": repo_ref,
        "purl": "pkg:pypi/acme-lib@1.2.3",
        "declared_license_raw": "MIT",
        "spdx_id": "MIT",
        "evidence": {
            "source_layer": "syft",
            "url": "https://example.invalid/licenses/mit",
            "anchor": "MIT",
            "fetched_at": "2026-01-01T00:00:00Z",
        },
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "modified": "unknown",
    }


@pytest.fixture
def inventory(repo_ref: str) -> dict[str, Any]:
    return {
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
                "source_url": "https://example.invalid/acme-lib",
                "modified": "unknown",
                "found_in": [repo_ref],
                "policy_tier": "ALLOW",
                "evidence_refs": ["acme-alpha/resolved.ndjson:1"],
            }
        ],
    }


@pytest.fixture
def shortlist() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "open_count": 1,
        "items": [
            {
                "component_ref": "acme-lib|MIT",
                "reason": "REVIEW",
                "evidence": {
                    "source_layer": "syft",
                    "url": "https://example.invalid/licenses/mit",
                    "anchor": "MIT",
                },
                "candidate_spdx": "MIT",
                "status": "open",
                "decided_by": None,
                "decided_at": None,
                "note": None,
            }
        ],
    }


@pytest.fixture
def shortlist_proposals() -> list[dict[str, Any]]:
    return [
        {
            "component_ref": "acme-lib|MIT",
            "spdx_id": "MIT",
            "evidence_url": "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            "evidence_anchor": "MIT",
            "disposition": "allow",
            "confidence": 0.95,
            "rationale": "Registry metadata anchors MIT.",
            "sanity_check": "No BLOCK terms found.",
        },
        {
            "component_ref": "acme-lib|UNKNOWN",
            "abstain": True,
            "reason": "No fetchable evidence URL in context.",
        },
    ]


@pytest.fixture
def shortlist_evidence() -> list[dict[str, Any]]:
    return [
        {
            "component_ref": "acme-lib|UNKNOWN",
            "context_fingerprint": "abc123def456",
            "package": "acme-lib",
            "version": "1.2.3",
            "ecosystem": "pypi",
            "found_in": ["acme-alpha"],
            "outcome": "pending_verifier_support",
            "machine_verification": "pending_verifier_support",
            "lookups_attempted": ["PyPI metadata"],
            "likely_spdx": "MIT",
            "confidence": "high",
            "browser_evidence": [
                {
                    "label": "PyPI metadata",
                    "url": "https://pypi.org/pypi/acme-lib/1.2.3/json",
                    "source_type": "pypi",
                    "anchor": "MIT",
                }
            ],
            "rationale": "Registry metadata anchors MIT.",
            "review_note": "Browser evidence found.",
        }
    ]
