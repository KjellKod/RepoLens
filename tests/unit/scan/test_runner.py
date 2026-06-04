"""Unit tests for the P2 scan runner.

These exercise the runner against the *real* on-disk store (jsonschema is present
in the unit env), so the Syft->SBOM mapping is proven to validate against the
frozen ``sbom.schema.json``. The clone and Syft boundaries are injected.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repolens.data import store
from repolens.scan.runner import RepoSpec, ScanBatchError, scan_repos

CLONE_URL = "https://example.invalid/acme-alpha"


def _syft_document() -> dict:
    return {
        "descriptor": {"name": "syft", "version": "1.18.1"},
        "source": {"type": "directory", "target": "/scan/repo"},
        "artifacts": [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [{"value": "MIT", "spdxExpression": "MIT"}],
                "locations": [{"path": "requirements.txt"}],
            },
            {
                # Malformed entry (no type) must be dropped, not crash the mapping.
                "name": "acme-orphan",
            },
        ],
    }


def _clone_into(options):
    destination = Path(options.destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "README.md").write_text("acme\n", encoding="utf-8")
    return destination


def _clone_with_pyproject(text: str):
    def clone(options):
        destination = _clone_into(options)
        (destination / "pyproject.toml").write_text(text, encoding="utf-8")
        return destination

    return clone


def _clone_with_cargo_workspace():
    def clone(options):
        destination = _clone_into(options)
        (destination / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/app"]\n', encoding="utf-8"
        )
        member = destination / "crates" / "app"
        member.mkdir(parents=True, exist_ok=True)
        (member / "Cargo.toml").write_text('[package]\nname = "diffly-app"\n', encoding="utf-8")
        return destination

    return clone


def _syft_ok(document: dict):
    def runner(argv, *, timeout):
        return subprocess.CompletedProcess(list(argv), 0, stdout=json.dumps(document), stderr="")

    return runner


def test_maps_syft_output_to_valid_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    report = scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    assert [o.status for o in report.outcomes] == ["scanned"]
    # Persisted + schema-validated by the real store; read it back.
    sbom = store.read_sbom(work_root, "acme-alpha")
    assert sbom["schema_version"] == "1.0"
    assert sbom["repo"] == "acme-alpha"
    assert sbom["source"] == CLONE_URL
    assert sbom["tool"] == {"name": "syft", "version": "1.18.1"}
    assert len(sbom["artifacts"]) == 1  # malformed entry dropped
    artifact = sbom["artifacts"][0]
    assert artifact["name"] == "acme-lib"
    assert artifact["type"] == "python"
    assert artifact["licenses"] == ["MIT"]
    assert artifact["locations"] == ["requirements.txt"]


def test_scan_writes_first_party_names_from_workspace_manifests(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_cargo_workspace(),
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    # The fresh scan persisted the detected workspace member set to the sidecar
    # that survives the ephemeral-workdir cleanup.
    assert store.read_first_party(work_root, "acme-alpha") == frozenset({"diffly-app"})


def test_scan_writes_empty_first_party_set_when_no_workspaces(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    # A fresh scan always writes the sidecar (empty here), so "a scan ran" is observable.
    assert store.read_first_party(work_root, "acme-alpha") == frozenset()


def test_scan_writes_bounded_source_snapshot_from_sparse_manifest_paths(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work-root"
    token = "ghp_" + "A" * 24

    def clone(options):
        destination = _clone_into(options)
        package_dir = destination / "vendor" / "fixture-lib"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text('{"name":"fixture-lib"}\n', encoding="utf-8")
        (package_dir / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (package_dir / "requirements-token.txt").write_text(token, encoding="utf-8")
        (destination / ".git").mkdir()
        (destination / ".git" / "config").write_text(
            f"url = https://{token}@github.com/acme/private.git\n", encoding="utf-8"
        )
        (destination / "src").mkdir()
        (destination / "src" / "private.py").write_text("SECRET = 1\n", encoding="utf-8")
        (destination / "dist").mkdir()
        (destination / "dist" / "bundle.js").write_text("compiled\n", encoding="utf-8")
        (package_dir / "LICENSE.link").symlink_to(package_dir / "LICENSE")
        return destination

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=clone,
        command_runner=_syft_ok(_syft_document()),
    )

    snapshot = store.read_source_snapshot(work_root, "acme-alpha")
    assert snapshot is not None
    assert (snapshot / "vendor" / "fixture-lib" / "package.json").read_text(
        encoding="utf-8"
    ) == '{"name":"fixture-lib"}\n'
    assert (snapshot / "vendor" / "fixture-lib" / "LICENSE").read_text(encoding="utf-8") == "MIT\n"
    assert not (snapshot / ".git" / "config").exists()
    assert not (snapshot / "src" / "private.py").exists()
    assert not (snapshot / "dist" / "bundle.js").exists()
    assert not (snapshot / "vendor" / "fixture-lib" / "LICENSE.link").exists()
    assert not (snapshot / "vendor" / "fixture-lib" / "requirements-token.txt").exists()
    snapshot_text = "\n".join(
        path.read_text(encoding="utf-8") for path in snapshot.rglob("*") if path.is_file()
    )
    assert token not in snapshot_text


def test_full_materialized_checkout_snapshot_remains_sparse_policy_bounded(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work-root"
    token = "ghp_" + "B" * 24

    def clone(options):
        destination = _clone_into(options)
        package_dir = destination / "packages" / "fixture-lib"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text('{"name":"fixture-lib"}\n', encoding="utf-8")
        (package_dir / "package-lock.json").write_bytes(b"{" + b" " * (600 * 1024) + b"}")
        (package_dir / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
        (destination / ".git").mkdir()
        (destination / ".git" / "config").write_text(
            f"extraheader = Authorization: Basic {token}\n", encoding="utf-8"
        )
        return destination

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=clone,
        command_runner=_syft_ok(_syft_document()),
    )

    snapshot = store.read_source_snapshot(work_root, "acme-alpha")
    assert snapshot is not None
    assert (snapshot / "packages" / "fixture-lib" / "package.json").is_file()
    assert not (snapshot / "packages" / "fixture-lib" / "package-lock.json").exists()
    assert not (snapshot / "packages" / "fixture-lib" / "index.js").exists()
    assert not (snapshot / ".git" / "config").exists()


def test_pyproject_project_dependencies_are_added_to_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_pyproject(
            """
[project]
dependencies = ["Sentinel_Py.Runtime[http]==1.2.3; python_version >= '3.11'"]
"""
        ),
        command_runner=_syft_ok({**_syft_document(), "artifacts": []}),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    artifact = store.read_sbom(work_root, "acme-alpha")["artifacts"][0]
    assert artifact == {
        "name": "sentinel-py-runtime",
        "type": "python",
        "version": "1.2.3",
        "purl": "pkg:pypi/sentinel-py-runtime@1.2.3",
        "locations": ["pyproject.toml"],
    }
    assert "declared_version_status" not in artifact


def test_pyproject_project_dependency_merges_with_existing_lockfile_artifact(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_pyproject(
            """
[project]
dependencies = ["Sentinel_Shared==1.2.3"]
"""
        ),
        command_runner=_syft_ok(
            {
                **_syft_document(),
                "artifacts": [
                    {
                        "name": "sentinel-shared",
                        "version": "1.2.3",
                        "type": "python",
                        "purl": "pkg:pypi/sentinel-shared@1.2.3",
                        "locations": [{"path": "/requirements-dev.txt"}],
                    }
                ],
            }
        ),
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert len(artifacts) == 1
    assert artifacts[0] == {
        "name": "sentinel-shared",
        "type": "python",
        "version": "1.2.3",
        "purl": "pkg:pypi/sentinel-shared@1.2.3",
        "locations": ["/requirements-dev.txt", "pyproject.toml"],
    }


def test_pyproject_optional_dependencies_are_added_to_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_pyproject(
            """
[project]
dependencies = []

[project.optional-dependencies]
dev = ["Sentinel.Optional===4.5.6"]
"""
        ),
        command_runner=_syft_ok({**_syft_document(), "artifacts": []}),
    )

    artifact = store.read_sbom(work_root, "acme-alpha")["artifacts"][0]
    assert artifact["name"] == "sentinel-optional"
    assert artifact["version"] == "4.5.6"
    assert artifact["purl"] == "pkg:pypi/sentinel-optional@4.5.6"
    assert artifact["locations"] == ["pyproject.toml#project.optional-dependencies.dev"]


def test_unpinned_pyproject_dependency_lowers_version_to_null(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_pyproject('[project]\ndependencies = ["Sentinel.Range>=1,<2"]\n'),
        command_runner=_syft_ok({**_syft_document(), "artifacts": []}),
    )

    artifact = store.read_sbom(work_root, "acme-alpha")["artifacts"][0]
    assert artifact["name"] == "sentinel-range"
    assert artifact["version"] is None
    assert artifact["purl"] == "pkg:pypi/sentinel-range"
    assert artifact["declared_version_status"] == "declared-unpinned"


def test_pyproject_dependency_parser_skips_invalid_and_direct_reference_strings(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work-root"

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_with_pyproject(
            """
[project]
dependencies = [
  "sentinel-keep==1.0.0",
  "bad name == 1",
  "sentinel-direct @ https://example.invalid/pkg.tar.gz",
  "git+https://example.invalid/repo",
]
"""
        ),
        command_runner=_syft_ok({**_syft_document(), "artifacts": []}),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-keep"]


def test_default_exclusions_drop_test_fixture_locations_but_keep_vendor(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {"name": "sentinel-vendor", "type": "python", "locations": [{"path": "vendor/a.py"}]},
            {
                "name": "sentinel-test-fixture",
                "type": "python",
                "locations": [{"path": "tests/fixtures/a.py"}],
            },
            {
                "name": "sentinel-runtime",
                "type": "python",
                "locations": [{"path": "src/runtime.py"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == [
        "sentinel-vendor",
        "sentinel-runtime",
    ]


def test_default_exclusions_drop_syft_root_relative_fixture_locations(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {
                "name": "sentinel-test-fixture",
                "type": "python",
                "locations": [{"path": "/tests/fixtures/a.py"}],
            },
            {
                "name": "sentinel-runtime",
                "type": "python",
                "locations": [{"path": "/src/runtime.py"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-runtime"]


def test_default_exclusions_drop_bootstrap_fixture_locations(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {
                "name": "sentinel-bootstrap-fixture",
                "type": "python",
                "locations": [{"path": "/tests/bootstrap/fixtures/requirements.bad.txt"}],
            },
            {
                "name": "sentinel-runtime",
                "type": "python",
                "locations": [{"path": "/src/runtime.py"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-runtime"]


def test_default_exclusions_keep_top_level_fixtures_path(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {
                "name": "sentinel-sample",
                "type": "python",
                "locations": [{"path": "fixtures/runtime.py"}],
            }
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-sample"]


def test_default_exclusions_preserve_leading_dot_boundary(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {
                "name": "sentinel-dot-git",
                "type": "python",
                "locations": [{"path": ".git/config"}],
            },
            {
                "name": "sentinel-git-dir",
                "type": "python",
                "locations": [{"path": "git/config"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-git-dir"]


def test_scan_config_can_override_exclusions(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {"name": "sentinel-vendor", "type": "python", "locations": [{"path": "vendor/a.py"}]},
            {"name": "sentinel-src", "type": "python", "locations": [{"path": "src/a.py"}]},
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
        exclude_paths=("src/",),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-vendor"]


def test_scan_config_can_opt_into_vendor_exclusion(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {"name": "sentinel-vendor", "type": "python", "locations": [{"path": "vendor/a.py"}]},
            {"name": "sentinel-src", "type": "python", "locations": [{"path": "src/a.py"}]},
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
        exclude_paths=("vendor/",),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-src"]


def test_scan_config_ignores_absolute_and_parent_escaping_exclusions(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {"name": "sentinel-vendor", "type": "python", "locations": [{"path": "vendor/a.py"}]},
            {"name": "sentinel-src", "type": "python", "locations": [{"path": "src/a.py"}]},
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
        exclude_paths=("/repo/vendor/", "../src/"),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == [
        "sentinel-vendor",
        "sentinel-src",
    ]


def test_exclusions_keep_artifacts_with_only_untrusted_locations(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {
                "name": "sentinel-absolute",
                "type": "python",
                "locations": [{"path": "/repo/vendor/a.py"}],
            },
            {
                "name": "sentinel-parent-escaping",
                "type": "python",
                "locations": [{"path": "../vendor/a.py"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == [
        "sentinel-absolute",
        "sentinel-parent-escaping",
    ]


def test_scan_config_override_exclusions_match_path_boundaries(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = {
        **_syft_document(),
        "artifacts": [
            {"name": "sentinel-src", "type": "python", "locations": [{"path": "src/a.py"}]},
            {
                "name": "sentinel-src-sibling",
                "type": "python",
                "locations": [{"path": "src2/a.py"}],
            },
        ],
    }

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(document),
        exclude_paths=("src",),
    )

    artifacts = store.read_sbom(work_root, "acme-alpha")["artifacts"]
    assert [artifact["name"] for artifact in artifacts] == ["sentinel-src-sibling"]


def test_restricted_syft_catalogers_keep_gradle_cocoapods_swiftpm(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    seen_argv: list[str] = []

    def runner(argv, *, timeout):
        del timeout
        seen_argv.extend(argv)
        return subprocess.CompletedProcess(
            list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
        )

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=runner,
        syft_catalogers=("python-package-cataloger",),
    )

    assert "--select-catalogers" in seen_argv
    selected = seen_argv[seen_argv.index("--select-catalogers") + 1].split(",")
    assert "python-package-cataloger" in selected
    assert "java-gradle-lockfile-cataloger" in selected
    assert "cocoapods-cataloger" in selected
    assert "swift-package-manager-cataloger" in selected


def test_resume_skips_already_scanned_repo(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    store.write_sbom(
        work_root,
        "acme-alpha",
        {
            "schema_version": "1.0",
            "repo": "acme-alpha",
            "generated_at": "2026-01-01T00:00:00Z",
            "tool": {"name": "syft", "version": "1.18.1"},
            "source": CLONE_URL,
            "artifacts": [],
        },
    )
    clone_calls: list = []

    def clone_spy(options):
        clone_calls.append(options)
        return _clone_into(options)

    report = scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=clone_spy,
        command_runner=_syft_ok(_syft_document()),
    )

    assert [o.status for o in report.outcomes] == ["skipped"]
    assert report.outcomes[0].skipped_reason == "cached"
    assert clone_calls == []  # resume guard prevented re-clone


def test_mixed_run_returns_failure_report_and_persists_successes(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    document = _syft_document()

    def runner(argv, *, timeout):
        if "acme-bad" in argv[2]:
            return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="syft boom")
        return subprocess.CompletedProcess(list(argv), 0, stdout=json.dumps(document), stderr="")

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [
                RepoSpec("acme-ok", CLONE_URL),
                RepoSpec("acme-bad", "https://example.invalid/acme-bad"),
            ],
            syft_path=tmp_path / "tools" / "syft",
            clone=_clone_into,
            command_runner=runner,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["scanned", "failed"]
    assert {o.repo_ref for o in report.scanned} == {"acme-ok"}
    assert {o.repo_ref for o in report.failed} == {"acme-bad"}
    # The good repo's SBOM is persisted despite the sibling failure.
    assert store.is_repo_scanned(work_root, "acme-ok")
    assert not store.is_repo_scanned(work_root, "acme-bad")
    # The failed repo carries a status artifact.
    status = json.loads(
        (store.repo_dir(work_root, "acme-bad") / "scan.status.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "failed"


def test_progress_events_include_start_outcomes_and_dependency_counts(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    events = []

    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
        progress=events.append,
    )

    assert [(event.kind, event.index, event.total, event.repo_ref) for event in events] == [
        ("start", 1, 1, "acme-alpha"),
        ("outcome", 1, 1, "acme-alpha"),
    ]
    assert events[1].status == "scanned"
    assert events[1].deps_count == 1
    assert events[1].elapsed_seconds is not None


def test_private_repo_fails_without_clone_when_auth_missing(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    clone_calls: list = []
    events = []

    def clone_spy(options):
        clone_calls.append(options)
        return _clone_into(options)

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-private", CLONE_URL, private=True)],
            syft_path=tmp_path / "tools" / "syft",
            clone=clone_spy,
            command_runner=_syft_ok(_syft_document()),
            progress=events.append,
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert "needs auth" in str(report.outcomes[0].error)
    assert clone_calls == []
    assert events[-1].status == "failed"
    assert "needs auth" in str(events[-1].error)


def test_ephemeral_workdir_cleaned_up(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    scan_repos(
        work_root,
        [RepoSpec("acme-alpha", CLONE_URL)],
        syft_path=tmp_path / "tools" / "syft",
        clone=_clone_into,
        command_runner=_syft_ok(_syft_document()),
        clock=lambda: "2026-01-01T00:00:00Z",
    )
    leftovers = list(store.repo_dir(work_root, "acme-alpha").glob(".scan-*"))
    assert leftovers == []


def test_status_file_redacts_token_in_error(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"
    token = "ghp_" + "Z" * 36

    def runner(argv, *, timeout):
        return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr=f"denied {token}")

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-alpha", CLONE_URL)],
            syft_path=tmp_path / "tools" / "syft",
            clone=_clone_into,
            command_runner=runner,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert {o.repo_ref for o in report.failed} == {"acme-alpha"}
    status_text = (store.repo_dir(work_root, "acme-alpha") / "scan.status.json").read_text(
        encoding="utf-8"
    )
    assert token not in status_text
    assert "[REDACTED_TOKEN]" in status_text


def test_timeout_records_failure_without_sbom(tmp_path: Path) -> None:
    work_root = tmp_path / "work-root"

    def slow(argv, *, timeout):
        raise subprocess.TimeoutExpired(list(argv), timeout)

    with pytest.raises(ScanBatchError) as exc_info:
        scan_repos(
            work_root,
            [RepoSpec("acme-alpha", CLONE_URL)],
            syft_path=tmp_path / "tools" / "syft",
            timeout_seconds=0.01,
            clone=_clone_into,
            command_runner=slow,
            clock=lambda: "2026-01-01T00:00:00Z",
        )

    report = exc_info.value.report
    assert [o.status for o in report.outcomes] == ["failed"]
    assert {o.repo_ref for o in report.failed} == {"acme-alpha"}
    assert not store.is_repo_scanned(work_root, "acme-alpha")
