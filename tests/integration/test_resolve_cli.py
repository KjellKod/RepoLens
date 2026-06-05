from __future__ import annotations

from pathlib import Path

import pytest

from repolens import cli
from repolens.data.store import iter_resolved, replace_source_snapshot, write_sbom
from repolens.resolve.stage import run_resolve
from repolens.security.http_client import FetchResult, HttpFetchOptions


def test_resolve_cli_reads_sbom_and_writes_resolved_ndjson(tmp_path: Path, repo_ref: str) -> None:
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
                    "version": "1.2.3",
                    "type": "python",
                    "purl": "pkg:pypi/acme-lib@1.2.3",
                    "licenses": ["MIT"],
                }
            ],
        },
    )

    code = cli.main(["resolve", "--work-root", str(tmp_path), "--repo-ref", repo_ref])

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["name"] == "acme-lib"
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"


def test_resolve_cli_prints_elapsed_repo_and_total_summary(
    tmp_path: Path,
    repo_ref: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
                    "version": "1.2.3",
                    "type": "python",
                    "purl": "pkg:pypi/acme-lib@1.2.3",
                    "licenses": ["MIT"],
                }
            ],
        },
    )
    ticks = iter((10.0, 10.0, 12.0, 12.0, 22.3, 77.7))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))

    code = cli.main(["resolve", "--work-root", str(tmp_path), "--repo-ref", repo_ref])

    assert code == 0
    err = capsys.readouterr().err
    assert f"[1/1] {repo_ref} — 1/1 resolved… (2.0s) acme-lib" in err
    assert f"[1/1] {repo_ref} ✓ wrote resolved.ndjson (12.3s)" in err
    assert "Done: 1 repos resolved in 1m07s." in err


def test_resolve_cli_detect_conflicts_flag_reaches_resolve_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_resolve(*args: object, **kwargs: object) -> Path:
        captured["detect_conflicts"] = kwargs["detect_conflicts"]
        return tmp_path / "work" / "acme-alpha" / "resolved.ndjson"

    monkeypatch.setattr(cli, "_resolve_repo_refs", lambda work_root, repo_ref: ("acme-alpha",))
    monkeypatch.setattr("repolens.resolve.run_resolve", fake_run_resolve)

    code = cli.main(["resolve", "--work-root", str(tmp_path), "--detect-conflicts"])

    assert code == 0
    assert captured == {"detect_conflicts": True}


def test_resolve_cli_reports_cache_reuse(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_resolve(*args: object, **kwargs: object) -> Path:
        del args
        kwargs["cache_stats"].api_hits = 3
        return tmp_path / "work" / "acme-alpha" / "resolved.ndjson"

    monkeypatch.setattr(cli, "_resolve_repo_refs", lambda work_root, repo_ref: ("acme-alpha",))
    monkeypatch.setattr("repolens.resolve.run_resolve", fake_run_resolve)

    code = cli.main(["resolve", "--work-root", str(tmp_path)])

    assert code == 0
    captured = capsys.readouterr()
    assert "reused 3 cached resolution(s)" in captured.err
    assert "reused 3 cached resolution(s)" in captured.out


def test_resolve_cli_without_repo_ref_resolves_all_scanned_repos(tmp_path: Path) -> None:
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        write_sbom(
            tmp_path,
            repo_ref,
            {
                "schema_version": "1.0",
                "repo": repo_ref,
                "generated_at": "2026-01-01T00:00:00Z",
                "tool": {"name": "syft", "version": "1.0.0"},
                "source": f"https://example.invalid/{repo_ref}",
                "artifacts": [
                    {
                        "name": f"{repo_ref}-lib",
                        "version": "1.2.3",
                        "type": "python",
                        "purl": f"pkg:pypi/{repo_ref}-lib@1.2.3",
                        "licenses": ["MIT"],
                    }
                ],
            },
        )

    code = cli.main(["resolve", "--work-root", str(tmp_path)])

    assert code == 0
    for repo_ref in ("sentinel-alpha", "sentinel-beta"):
        records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
        assert records[0]["name"] == f"{repo_ref}-lib"
        assert records[0]["spdx_id"] == "MIT"


def test_resolve_cli_accepts_source_root_and_preserves_p3a_shape(
    tmp_path: Path, repo_ref: str
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Package.swift").write_text("// fixture", encoding="utf-8")
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
                    "name": "fixture-lib",
                    "version": "1.2.3",
                    "type": "python",
                    "licenses": ["MIT"],
                    "locations": ["Package.swift"],
                }
            ],
        },
    )

    code = cli.main(
        [
            "resolve",
            "--work-root",
            str(tmp_path),
            "--repo-ref",
            repo_ref,
            "--source-root",
            str(source_root),
        ]
    )

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"


def test_resolve_cli_default_uses_stored_source_snapshot_for_scancode(
    tmp_path: Path,
    repo_ref: str,
    monkeypatch: pytest.MonkeyPatch,
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
                    "name": "fixture-lib",
                    "version": None,
                    "type": "unknown",
                    "licenses": [],
                    "locations": ["vendor/fixture-lib/package.json"],
                }
            ],
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

    monkeypatch.setattr(
        "repolens.resolve.stage.resolve_scancode_path",
        lambda work_root: Path(work_root) / "tools" / "scancode",
    )
    monkeypatch.setattr("repolens.resolve.scancode._default_command_runner", runner)

    code = cli.main(["resolve", "--work-root", str(tmp_path), "--repo-ref", repo_ref])

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] == "Apache-2.0"
    assert records[0]["evidence"]["source_layer"] == "scancode"


def test_resolve_metadata_only_mobile_dependencies_from_stored_snapshot(
    tmp_path: Path,
    repo_ref: str,
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
                    "name": "sentinel-swift-runtime",
                    "version": "1.0.0",
                    "type": "swift",
                    "purl": "pkg:swift/sentinel-swift-runtime@1.0.0",
                    "licenses": [],
                    "locations": ["Package.resolved"],
                },
                {
                    "name": "SentinelPodRuntime",
                    "version": "2.0.0",
                    "type": "cocoapods",
                    "purl": "pkg:cocoapods/SentinelPodRuntime@2.0.0",
                    "licenses": [],
                    "locations": ["Podfile.lock"],
                },
            ],
        },
    )
    staged = tmp_path / "staged-source"
    staged.mkdir()
    (staged / "Package.swift").write_text("// swift package\n", encoding="utf-8")
    (staged / "Package.resolved").write_text(
        """
{
  "pins": [
    {
      "identity": "sentinel-swift-runtime",
      "kind": "remoteSourceControl",
      "location": "https://github.com/example/sentinel-swift-runtime.git",
      "state": {"version": "1.0.0", "revision": "abc123"}
    }
  ],
  "version": 3
}
""".strip(),
        encoding="utf-8",
    )
    (staged / "Podfile.lock").write_text(
        "PODS:\n  - SentinelPodRuntime (2.0.0)\n", encoding="utf-8"
    )
    replace_source_snapshot(tmp_path, repo_ref, staged)
    seen: list[str] = []

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        seen.append(url)
        if "api.github.com" in url:
            body = b'{"license":{"spdx_id":"MIT"}}'
        else:
            body = b'{"license":"Apache-2.0"}'
        return FetchResult(url=url, status=200, headers=(), body=body)

    def public_resolver(host: str, port: int) -> tuple[str, ...]:
        del host, port
        return ("8.8.8.8",)

    def fail_mobile_enricher(*args: object, **kwargs: object) -> object:
        raise AssertionError("native mobile enrichment must stay opt-in")

    run_resolve(
        tmp_path,
        repo_ref,
        fetcher=fetcher,
        evidence_resolver=public_resolver,
        mobile_enricher=fail_mobile_enricher,  # type: ignore[arg-type]
    )

    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    by_name = {record["name"]: record for record in records}
    assert by_name["sentinel-swift-runtime"]["spdx_id"] == "MIT"
    assert by_name["sentinel-swift-runtime"]["evidence"]["source_layer"] == "api"
    assert by_name["sentinel-swift-runtime"]["evidence"]["url"] == (
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123"
    )
    assert by_name["SentinelPodRuntime"]["spdx_id"] == "Apache-2.0"
    assert by_name["SentinelPodRuntime"]["evidence"]["source_layer"] == "api"
    assert by_name["SentinelPodRuntime"]["evidence"]["url"] == (
        "https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0"
    )
    assert seen == [
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
        "https://api.github.com/repos/example/sentinel-swift-runtime/license?ref=abc123",
        "https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0",
        "https://trunk.cocoapods.org/api/v1/pods/SentinelPodRuntime/specs/2.0.0",
    ]


def test_resolve_cli_explicit_source_root_overrides_stored_snapshot(
    tmp_path: Path,
    repo_ref: str,
    monkeypatch: pytest.MonkeyPatch,
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
                    "name": "fixture-lib",
                    "version": None,
                    "type": "unknown",
                    "licenses": [],
                    "locations": ["vendor/fixture-lib/package.json"],
                }
            ],
        },
    )
    staged = tmp_path / "staged-source"
    stored_package = staged / "vendor" / "fixture-lib"
    stored_package.mkdir(parents=True)
    (stored_package / "package.json").write_text('{"name":"stored"}\n', encoding="utf-8")
    replace_source_snapshot(tmp_path, repo_ref, staged)

    explicit_root = tmp_path / "explicit-source"
    explicit_package = explicit_root / "vendor" / "fixture-lib"
    explicit_package.mkdir(parents=True)
    (explicit_package / "package.json").write_text('{"name":"explicit"}\n', encoding="utf-8")
    calls: list[list[str]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        calls.append(argv)
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"files":[{"license_expression_spdx":"MIT"}]}',
                "stderr": "",
            },
        )()

    monkeypatch.setattr(
        "repolens.resolve.stage.resolve_scancode_path",
        lambda work_root: Path(work_root) / "tools" / "scancode",
    )
    monkeypatch.setattr("repolens.resolve.scancode._default_command_runner", runner)

    code = cli.main(
        [
            "resolve",
            "--work-root",
            str(tmp_path),
            "--repo-ref",
            repo_ref,
            "--source-root",
            str(explicit_root),
        ]
    )

    assert code == 0
    assert calls
    assert str(explicit_package) in calls[0]
    assert str(stored_package) not in calls[0]


def test_resolve_cli_mobile_native_missing_sandbox_is_non_fatal(
    tmp_path: Path, repo_ref: str
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "build.gradle").write_text(
        "plugins { id 'com.android.application' }", encoding="utf-8"
    )
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
                    "name": "sentinel-lib",
                    "version": None,
                    "type": "unknown",
                    "licenses": [],
                    "locations": [],
                }
            ],
        },
    )

    code = cli.main(
        [
            "resolve",
            "--work-root",
            str(tmp_path),
            "--repo-ref",
            repo_ref,
            "--source-root",
            str(source_root),
            "--enable-mobile-native",
        ]
    )

    assert code == 0
    records = list(iter_resolved(tmp_path / "work" / repo_ref / "resolved.ndjson"))
    assert records[0]["spdx_id"] is None
    assert records[0]["evidence"]["source_layer"] == "mobile"
    assert records[0]["evidence"]["anchor"] == "unresolved:mobile_sandbox_unavailable"
