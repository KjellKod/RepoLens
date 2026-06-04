from __future__ import annotations

import json
import subprocess
from pathlib import Path

from repolens.data import store
from repolens.scan.runner import RepoSpec, scan_repos
from repolens.security.clone import (
    SPARSE_MANIFEST_PATTERNS,
    CloneOptions,
    is_sparse_manifest_path,
)

MANIFEST_MATRIX: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "gradle",
        (
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle/libs.versions.toml",
            "gradle.lockfile",
        ),
        (
            "apps/mobile/build.gradle",
            "apps/mobile/build.gradle.kts",
            "apps/mobile/settings.gradle",
            "apps/mobile/settings.gradle.kts",
            "apps/mobile/gradle/libs.versions.toml",
            "apps/mobile/gradle.lockfile",
        ),
    ),
    (
        "npm",
        ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
        (
            "packages/web/package.json",
            "packages/web/package-lock.json",
            "packages/web/npm-shrinkwrap.json",
            "packages/web/yarn.lock",
            "packages/web/pnpm-lock.yaml",
        ),
    ),
    ("cargo", ("Cargo.toml", "Cargo.lock"), ("crates/api/Cargo.toml", "crates/api/Cargo.lock")),
    (
        "python",
        (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "requirements-dev.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
        ),
        (
            "services/api/pyproject.toml",
            "services/api/setup.py",
            "services/api/setup.cfg",
            "services/api/requirements.txt",
            "services/api/requirements-dev.txt",
            "services/api/Pipfile",
            "services/api/Pipfile.lock",
            "services/api/poetry.lock",
            "services/api/uv.lock",
        ),
    ),
    ("go", ("go.mod", "go.sum"), ("services/worker/go.mod", "services/worker/go.sum")),
    ("maven", ("pom.xml",), ("modules/core/pom.xml",)),
    (
        "nuget",
        ("App.csproj", "packages.config", "Package.nuspec"),
        ("src/App/App.csproj", "src/App/packages.config", "src/App/Package.nuspec"),
    ),
    (
        "ruby",
        ("Gemfile", "Gemfile.lock", "library.gemspec"),
        ("engines/api/Gemfile", "engines/api/Gemfile.lock", "engines/api/library.gemspec"),
    ),
    (
        "apple",
        (
            "Podfile",
            "Podfile.lock",
            "Library.podspec",
            "Package.swift",
            "Package.resolved",
            "Cartfile",
            "Cartfile.resolved",
        ),
        (
            "ios/App/Podfile",
            "ios/App/Podfile.lock",
            "ios/App/Library.podspec",
            "ios/App/Package.swift",
            "ios/App/Package.resolved",
            "ios/App/Cartfile",
            "ios/App/Cartfile.resolved",
        ),
    ),
    (
        "composer",
        ("composer.json", "composer.lock"),
        ("plugins/acme/composer.json", "plugins/acme/composer.lock"),
    ),
    (
        "license",
        ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"),
        (
            "packages/lib/LICENSE",
            "packages/lib/LICENSE.txt",
            "packages/lib/LICENSE.md",
            "packages/lib/COPYING",
            "packages/lib/COPYING.txt",
        ),
    ),
    ("gitmodules", (".gitmodules",), ("libs/.gitmodules",)),
)


def test_sparse_manifest_matrix_matches_root_and_nested_examples() -> None:
    for _family, root_examples, nested_examples in MANIFEST_MATRIX:
        for example in (*root_examples, *nested_examples):
            assert is_sparse_manifest_path(example), example

    for excluded in (
        "maestroFlows/results/demo.mp4",
        "apps/mobile/maestroFlows/results/demo.mp4",
        "src/App/App.csproj.mp4",
        "packages/web/package.json.mp4",
        "docs/readme.md",
    ):
        assert not is_sparse_manifest_path(excluded), excluded


def test_sparse_checkout_materializes_manifest_matrix_examples(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "sentinel@example.invalid")
    _git(source, "config", "user.name", "Sentinel")
    _git(source, "config", "uploadpack.allowFilter", "true")

    expected: list[str] = []
    for _family, root_examples, nested_examples in MANIFEST_MATRIX:
        for relative in (*root_examples, *nested_examples):
            expected.append(relative)
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative}\n", encoding="utf-8")
    for relative in (
        "maestroFlows/results/demo.mp4",
        "apps/mobile/maestroFlows/results/demo.mp4",
        "packages/web/package.json.mp4",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\0" * 1024)

    _git(source, "add", ".")
    _git(source, "commit", "-q", "-m", "seed manifests")

    checkout = tmp_path / "checkout"
    _git(
        tmp_path,
        "clone",
        "-q",
        "--filter=blob:none",
        "--no-checkout",
        source.as_uri(),
        str(checkout),
    )
    _git(checkout, "sparse-checkout", "init", "--no-cone")
    _git(checkout, "sparse-checkout", "set", "--no-cone", "--", *SPARSE_MANIFEST_PATTERNS)
    _git(checkout, "checkout", "-q")

    for relative in expected:
        assert (checkout / relative).is_file(), relative
    assert not (checkout / "maestroFlows/results/demo.mp4").exists()
    assert not (checkout / "apps/mobile/maestroFlows/results/demo.mp4").exists()
    assert not (checkout / "packages/web/package.json.mp4").exists()
    assert _git_output(checkout, "config", "--get", "remote.origin.promisor") == "true"
    assert (
        _git_output(checkout, "config", "--get", "remote.origin.partialclonefilter") == "blob:none"
    )


def test_partial_sparse_clone_does_not_fetch_large_blob(tmp_path: Path) -> None:
    source = tmp_path / "source"
    large_path = "maestroFlows/results/demo.mp4"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "sentinel@example.invalid")
    _git(source, "config", "user.name", "Sentinel")
    _git(source, "config", "uploadpack.allowFilter", "true")
    manifest = source / "apps/mobile/build.gradle"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("plugins { id 'java' }\n", encoding="utf-8")
    large = source / large_path
    large.parent.mkdir(parents=True, exist_ok=True)
    large.write_bytes(bytes(range(256)) * 8192)
    _git(source, "add", ".")
    _git(source, "commit", "-q", "-m", "seed large binary")
    large_blob_sha = _git_output(source, "rev-parse", f"HEAD:{large_path}")

    destination = tmp_path / "destination"
    _git(
        tmp_path,
        "clone",
        "-q",
        "--filter=blob:none",
        "--no-checkout",
        source.as_uri(),
        str(destination),
    )
    _git(destination, "sparse-checkout", "init", "--no-cone")
    _git(destination, "sparse-checkout", "set", "--no-cone", "--", *SPARSE_MANIFEST_PATTERNS)
    _git(destination, "checkout", "-q")

    assert (destination / "apps/mobile/build.gradle").is_file()
    assert not (destination / large_path).exists()
    assert _git_output(destination, "config", "--get", "remote.origin.promisor") == "true"
    assert (
        _git_output(destination, "config", "--get", "remote.origin.partialclonefilter")
        == "blob:none"
    )
    assert not _object_exists_without_lazy_fetch(destination, large_blob_sha)


def test_fixture_scan_inventories_manifest_without_large_binary(tmp_path: Path) -> None:
    work_root = tmp_path / "work"
    large_path = Path("maestroFlows/results/demo.mp4")

    def clone(options: CloneOptions) -> Path:
        destination = Path(options.destination)
        manifest = destination / "apps/mobile/build.gradle"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("plugins { id 'java' }\n", encoding="utf-8")
        return destination

    def syft(argv, *, timeout):
        del timeout
        target = Path(str(argv[2]).removeprefix("dir:"))
        assert (target / "apps/mobile/build.gradle").is_file()
        assert not (target / large_path).exists()
        document = {
            "descriptor": {"name": "syft", "version": "1.18.1"},
            "artifacts": [
                {
                    "name": "sentinel-gradle-lib",
                    "version": "1.0.0",
                    "type": "java",
                    "locations": [{"path": "apps/mobile/build.gradle"}],
                }
            ],
        }
        return subprocess.CompletedProcess(list(argv), 0, stdout=json.dumps(document), stderr="")

    scan_repos(
        work_root,
        [RepoSpec("sentinel-large", "https://example.invalid/sentinel-large.git")],
        syft_path=tmp_path / "syft",
        clone=clone,
        command_runner=syft,
        clock=lambda: "2026-01-01T00:00:00Z",
    )

    sbom = store.read_sbom(work_root, "sentinel-large")
    assert sbom["artifacts"][0]["name"] == "sentinel-gradle-lib"
    assert sbom["artifacts"][0]["locations"] == ["apps/mobile/build.gradle"]


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _git_output(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _object_exists_without_lazy_fetch(repo: Path, sha: str) -> bool:
    loose_object = repo / ".git" / "objects" / sha[:2] / sha[2:]
    if loose_object.exists():
        return True
    for pack_index in (repo / ".git" / "objects" / "pack").glob("*.idx"):
        completed = subprocess.run(
            ["git", "verify-pack", "-v", str(pack_index)],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        if sha in completed.stdout:
            return True
    return False
