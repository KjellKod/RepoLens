from __future__ import annotations

from pathlib import Path

from repolens.resolve.mobile import detect_mobile, enrich_mobile_native
from repolens.resolve.models import PackageFact
from repolens.security.limits import SecurityLimits
from repolens.security.sandbox import SandboxSpec, SandboxUnavailable


def test_android_markers_require_android_plugin(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }", encoding="utf-8")

    assert not detect_mobile(tmp_path).android

    (tmp_path / "settings.gradle").write_text(
        "plugins { id 'com.android.application' version '1.0.0' }",
        encoding="utf-8",
    )

    detection = detect_mobile(tmp_path)
    assert detection.android
    assert detection.detected


def test_ios_markers_detect_locked_files(tmp_path: Path) -> None:
    (tmp_path / "Package.swift").write_text("// swift package", encoding="utf-8")

    detection = detect_mobile(tmp_path)

    assert detection.ios
    assert detection.detected


def test_android_marker_detection_ignores_bytes_after_limit(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "plugins { id 'java' }\nplugins { id 'com.android.application' }",
        encoding="utf-8",
    )
    limits = SecurityLimits(max_parse_bytes=len("plugins { id 'java' }\n"))

    detection = detect_mobile(tmp_path, limits=limits)

    assert not detection.android
    assert not detection.detected


def test_native_enrichment_uses_sandbox_spec_without_tokens(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins { id 'com.android.library' }", encoding="utf-8")
    package = PackageFact("fixture-lib", "1.0.0", "gradle", "fixture-repo", None, None)
    seen: list[SandboxSpec] = []

    def runner(spec: SandboxSpec):
        seen.append(spec)
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": '{"dependencies":[{"name":"fixture-lib","license":"MIT"}]}',
                "stderr": "",
            },
        )()

    outcome = enrich_mobile_native(
        package,
        detection=detect_mobile(tmp_path),
        source_root=tmp_path,
        sandbox_runner=runner,
    )

    assert outcome.candidate is not None
    assert outcome.candidate.spdx_id == "MIT"
    spec = seen[0]
    assert spec.read_only_mounts[0].host_path == tmp_path.resolve()
    assert spec.egress.block_metadata
    assert not any("TOKEN" in key.upper() for key in spec.env)


def test_ios_native_enrichment_reads_stdout_from_tool(tmp_path: Path) -> None:
    (tmp_path / "Cartfile").write_text("", encoding="utf-8")
    package = PackageFact("fixture-lib", "1.0.0", "swift", "fixture-repo", None, None)
    seen: list[SandboxSpec] = []

    def runner(spec: SandboxSpec):
        seen.append(spec)
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": '{"libraries":[{"name":"fixture-lib","spdx":"Apache-2.0"}]}',
                "stderr": "",
            },
        )()

    outcome = enrich_mobile_native(
        package,
        detection=detect_mobile(tmp_path),
        source_root=tmp_path,
        sandbox_runner=runner,
    )

    assert outcome.candidate is not None
    assert outcome.candidate.spdx_id == "Apache-2.0"
    assert seen[0].argv == ("license-plist", "--output-path", "/dev/stdout")


def test_missing_sandbox_is_non_fatal(tmp_path: Path) -> None:
    (tmp_path / "Cartfile").write_text("", encoding="utf-8")
    package = PackageFact("fixture-lib", "1.0.0", "swift", "fixture-repo", None, None)

    def runner(spec: SandboxSpec):
        del spec
        raise SandboxUnavailable("not configured")

    outcome = enrich_mobile_native(
        package,
        detection=detect_mobile(tmp_path),
        source_root=tmp_path,
        sandbox_runner=runner,
    )

    assert outcome.candidate is None
    assert outcome.unresolved_anchor == "unresolved:mobile_sandbox_unavailable"


def test_native_enrichment_conflicting_output_writes_conflict(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins { id 'com.android.library' }", encoding="utf-8")
    package = PackageFact("fixture-lib", "1.0.0", "gradle", "fixture-repo", None, None)

    def runner(spec: SandboxSpec):
        del spec
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": (
                    '{"dependencies":['
                    '{"name":"fixture-lib","license":"MIT"},'
                    '{"name":"fixture-lib","license":"Apache-2.0"}'
                    "]}"
                ),
                "stderr": "",
            },
        )()

    outcome = enrich_mobile_native(
        package,
        detection=detect_mobile(tmp_path),
        source_root=tmp_path,
        sandbox_runner=runner,
    )

    assert outcome.candidate is not None
    assert outcome.candidate.spdx_id == "CONFLICT"
    assert outcome.candidate.evidence_anchor == "conflict:mobile_disagreement"
