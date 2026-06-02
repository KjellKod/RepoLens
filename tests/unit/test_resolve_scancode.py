from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repolens.bootstrap.record import VERSIONS_SCHEMA
from repolens.bootstrap.scancode import (
    SCANCODE_REQUIREMENTS_SOURCE_PREFIX,
    build_scancode_wrapper,
)
from repolens.exit_codes import InputError
from repolens.resolve.models import PackageFact
from repolens.resolve.scancode import (
    ScanCodeTargetError,
    resolve_scancode_path,
    run_scancode_fallback,
    select_scancode_targets,
)


def package_with_location(location: str) -> PackageFact:
    return PackageFact("fixture-lib", "1.0.0", "python", "fixture-repo", None, None, (location,))


def write_scancode_record(
    root: Path,
    *,
    version: str = "32.3.1",
    digest: str = "c" * 64,
    source: str = f"{SCANCODE_REQUIREMENTS_SOURCE_PREFIX}scancode.requirements.txt",
) -> None:
    (root / "tool_versions.json").write_text(
        json.dumps(
            {
                "schema": VERSIONS_SCHEMA,
                "generated_at": "2026-01-01T00:00:00Z",
                "base_image": "python@sha256:" + "d" * 64,
                "tools": {
                    "scancode": {
                        "version": version,
                        "digest": digest,
                        "source": source,
                    }
                },
            }
        ),
        encoding="utf-8",
    )


def test_scancode_targets_single_package_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    package_dir = source / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")
    (package_dir / "LICENSE").write_text("MIT", encoding="utf-8")

    targets = select_scancode_targets(package_with_location("vendor/fixture-lib/module.py"), source)

    assert targets[0] == package_dir.resolve()
    assert package_dir / "LICENSE" in targets
    assert source.resolve() not in targets


def test_scancode_rejects_broad_repo_root_scan(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("fixture-lib==1.0.0", encoding="utf-8")

    with pytest.raises(ScanCodeTargetError):
        select_scancode_targets(package_with_location("requirements.txt"), source)


def test_scancode_rejects_paths_outside_source_root(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(ScanCodeTargetError):
        select_scancode_targets(package_with_location("../outside/file.py"), source)


def test_scancode_skips_license_symlink_resolving_outside_source_root(tmp_path: Path) -> None:
    source = tmp_path / "source"
    package_dir = source / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")
    outside = tmp_path / "outside-license"
    outside.write_text("MIT", encoding="utf-8")
    (package_dir / "LICENSE").symlink_to(outside)

    targets = select_scancode_targets(package_with_location("vendor/fixture-lib/module.py"), source)

    assert targets == (package_dir.resolve(),)


def test_resolve_scancode_path_requires_bootstrap_wrapper_and_record(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    digest = "c" * 64
    wrapper = tools / "scancode"
    wrapper.write_text(build_scancode_wrapper("32.3.1", digest), encoding="utf-8")
    wrapper.chmod(0o755)

    with pytest.raises(InputError):
        resolve_scancode_path(tmp_path)

    write_scancode_record(tmp_path, digest=digest)

    assert resolve_scancode_path(tmp_path) == tools / "scancode"


def test_resolve_scancode_path_rejects_arbitrary_local_executable(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "scancode").write_text("#!/bin/sh\necho unsafe\n", encoding="utf-8")
    (tools / "scancode").chmod(0o755)
    write_scancode_record(tmp_path)

    with pytest.raises(InputError, match="wrapper does not match"):
        resolve_scancode_path(tmp_path)


def test_resolve_scancode_path_rejects_unverified_record(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    digest = "c" * 64
    (tools / "scancode").write_text(build_scancode_wrapper("32.3.1", digest), encoding="utf-8")
    (tools / "scancode").chmod(0o755)
    write_scancode_record(tmp_path, digest=digest, source="caller-provided")

    with pytest.raises(InputError, match="requirements source"):
        resolve_scancode_path(tmp_path)


def test_scancode_result_normalizes_spdx(tmp_path: Path) -> None:
    source = tmp_path / "source"
    package_dir = source / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout='{"files":[{"license_expression_spdx":"MIT"}]}',
            stderr="",
        )

    outcome = run_scancode_fallback(
        package_with_location("vendor/fixture-lib/module.py"),
        work_root=tmp_path,
        source_root=source,
        command_runner=runner,
        executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    assert outcome.spdx_id == "MIT"
    assert outcome.anchor.startswith("scancode:MIT:")
    assert str(package_dir) in calls[0]


def test_scancode_timeout_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    package_dir = source / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")

    def runner(argv: list[str], *, timeout: float):
        raise subprocess.TimeoutExpired(argv, timeout)

    outcome = run_scancode_fallback(
        package_with_location("vendor/fixture-lib/module.py"),
        work_root=tmp_path,
        source_root=source,
        command_runner=runner,
        executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    assert outcome.spdx_id is None
    assert outcome.anchor == "unresolved:scancode_timeout"


def test_scancode_unlaunchable_executable_fails_closed(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    digest = "c" * 64
    (tools / "scancode").write_text(build_scancode_wrapper("32.3.1", digest), encoding="utf-8")
    write_scancode_record(tmp_path, digest=digest)
    source = tmp_path / "source"
    package_dir = source / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")

    outcome = run_scancode_fallback(
        package_with_location("vendor/fixture-lib/module.py"),
        work_root=tmp_path,
        source_root=source,
    )

    assert outcome.spdx_id is None
    assert outcome.anchor == "unresolved:scancode_tool_unavailable"
