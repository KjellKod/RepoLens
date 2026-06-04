from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.resolve.adapters import API_ALLOWED_HOSTS
from repolens.resolve.evidence import (
    UNKNOWN_VERSION,
    has_exact_license_evidence,
    should_attempt_api_resolution,
)
from repolens.resolve.mobile import detect_mobile, enrich_mobile_native
from repolens.resolve.models import ApiCandidate, PackageFact
from repolens.resolve.scancode import run_scancode_fallback, select_scancode_targets
from repolens.resolve.stage import run_resolve
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, validate_url_for_fetch
from repolens.security.redaction import REDACTION, redact_tokens
from repolens.security.sandbox import (
    SandboxSpec,
    SandboxUnavailable,
    build_native_tool_sandbox_spec,
    scrubbed_tool_env,
)

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def metadata_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("169.254.169.254",)


def evidence_options() -> HttpFetchOptions:
    return HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})


def test_p3a_resolve_blocks_off_allowlist_evidence() -> None:
    with pytest.raises(FetchSecurityError, match="host is not allowlisted"):
        validate_url_for_fetch(
            "https://offlist.example.invalid/licenses/acme-lib",
            evidence_options(),
            resolver=public_resolver,
        )


def test_p3a_resolve_rejects_mismatched_evidence_anchor() -> None:
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        "MIT",
    )

    assert not has_exact_license_evidence(b'{"licenses":["Apache-2.0"]}', candidate, "MIT")


def test_p3a_resolve_rejects_similar_spdx_evidence() -> None:
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        "MIT",
    )

    assert not has_exact_license_evidence(b'{"license":"MIT-0"}', candidate, "MIT")


def test_p3a_resolve_accepts_equivalent_compound_expression_evidence() -> None:
    candidate = ApiCandidate(
        "Apache-2.0 OR MIT",
        "https://api.deps.dev/v3alpha/systems/cargo/packages/anyhow/versions/1.0.98",
        "Apache-2.0 OR MIT",
    )

    assert has_exact_license_evidence(
        b'{"license":"MIT OR Apache-2.0"}',
        candidate,
        "Apache-2.0 OR MIT",
    )


def test_p3a_resolve_gates_with_exceptions_to_policy_table() -> None:
    unknown = ApiCandidate(
        "GPL-3.0-only WITH Unknown-exception",
        "https://api.deps.dev/v3alpha/systems/cargo/packages/acme-lib/versions/1.2.3",
        "GPL-3.0-only WITH Unknown-exception",
    )
    known = ApiCandidate(
        "GPL-3.0-only WITH Autoconf-exception-3.0",
        "https://api.deps.dev/v3alpha/systems/cargo/packages/acme-lib/versions/1.2.3",
        "GPL-3.0-only WITH Autoconf-exception-3.0",
    )

    assert not has_exact_license_evidence(
        b'{"license":"GPL-3.0-only WITH Unknown-exception"}',
        unknown,
        "GPL-3.0-only WITH Unknown-exception",
    )
    assert has_exact_license_evidence(
        b'{"license":"GPL-3.0-only WITH Autoconf-exception-3.0"}',
        known,
        "GPL-3.0-only WITH Autoconf-exception-3.0",
    )


def test_p3a_resolve_blocks_allowlisted_host_resolving_private_ip() -> None:
    with pytest.raises(FetchSecurityError, match="blocked IP"):
        validate_url_for_fetch(
            "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_options(),
            resolver=metadata_resolver,
        )


def test_p3a_resolve_does_not_fetch_unversioned_package() -> None:
    package = PackageFact("acme-lib", UNKNOWN_VERSION, "python", "fixture-repo", None, None)

    assert not should_attempt_api_resolution(package)


def test_p3a_resolve_redacts_token_shaped_api_payload() -> None:
    token = "ghp_" + "A" * 24
    candidate = ApiCandidate(
        "MIT",
        "https://api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
        f"MIT {token}",
    )

    assert not has_exact_license_evidence(f'{{"license":"MIT {token}"}}'.encode(), candidate, "MIT")
    redacted = redact_tokens(candidate.evidence_anchor)
    assert token not in redacted
    assert REDACTION in redacted


def test_p3a_resolve_drops_rejected_credential_evidence_url() -> None:
    with pytest.raises(FetchSecurityError, match="must not embed credentials"):
        validate_url_for_fetch(
            "https://user:plainsecret@api.deps.dev/v3alpha/systems/pypi/packages/acme-lib/versions/1.2.3",
            evidence_options(),
            resolver=public_resolver,
        )


def test_p3b_mobile_sandbox_spec_has_no_token_env_and_read_only_mount(tmp_path: Path) -> None:
    spec = build_native_tool_sandbox_spec(
        ["aboutlibraries", "--export-license-json", "/out/licenses.json"],
        source_root=tmp_path,
        env_source={"PATH": "/bin", "GITHUB_TOKEN": "ghp_" + "A" * 24},
    )

    assert spec.read_only_mounts[0].host_path == tmp_path.resolve()
    assert not any("TOKEN" in key.upper() for key in spec.env)
    assert spec.env == {"PATH": "/bin"}


def test_p3b_mobile_sandbox_egress_blocks_metadata(tmp_path: Path) -> None:
    spec = build_native_tool_sandbox_spec(
        ["license-plist", "--output-path", "/out/licenses.json"],
        source_root=tmp_path,
    )

    assert spec.egress.block_metadata
    assert "169.254.169.254" in spec.egress.blocked_hosts
    assert spec.egress.block_private


def test_p3b_mobile_missing_sandbox_is_non_fatal(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "plugins { id 'com.android.application' }", encoding="utf-8"
    )
    package = PackageFact("fixture-lib", "1.0.0", "gradle", "fixture-repo", None, None)

    def runner(spec: SandboxSpec):
        del spec
        raise SandboxUnavailable("sandbox unavailable")

    outcome = enrich_mobile_native(
        package,
        detection=detect_mobile(tmp_path),
        source_root=tmp_path,
        sandbox_runner=runner,
    )

    assert outcome.candidate is None
    assert outcome.unresolved_anchor == "unresolved:mobile_sandbox_unavailable"


def test_p3b_scancode_rejects_broad_and_outside_targets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "manifest.txt").write_text("fixture-lib", encoding="utf-8")
    broad = PackageFact(
        "fixture-lib", "1.0.0", "python", "fixture-repo", None, None, ("manifest.txt",)
    )
    outside = PackageFact(
        "fixture-lib", "1.0.0", "python", "fixture-repo", None, None, ("../escape.py",)
    )

    with pytest.raises(ValueError):
        select_scancode_targets(broad, source_root)
    with pytest.raises(ValueError):
        select_scancode_targets(outside, source_root)

    package_dir = source_root / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")
    outside_license = tmp_path / "outside-license"
    outside_license.write_text("MIT", encoding="utf-8")
    (package_dir / "LICENSE").symlink_to(outside_license)

    targets = select_scancode_targets(
        PackageFact(
            "fixture-lib",
            "1.0.0",
            "python",
            "fixture-repo",
            None,
            None,
            ("vendor/fixture-lib/module.py",),
        ),
        source_root,
    )

    assert targets == (package_dir.resolve(),)


def test_p3b_scancode_runner_env_is_token_free() -> None:
    env = scrubbed_tool_env({"PATH": "/bin", "GITHUB_TOKEN": "ghp_" + "A" * 24})

    assert env == {"PATH": "/bin"}


def test_p3b_scancode_timeout_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    package_dir = source_root / "vendor" / "fixture-lib"
    package_dir.mkdir(parents=True)
    (package_dir / "module.py").write_text("", encoding="utf-8")
    package = PackageFact(
        "fixture-lib",
        "1.0.0",
        "python",
        "fixture-repo",
        None,
        None,
        ("vendor/fixture-lib/module.py",),
    )

    def runner(argv: list[str], *, timeout: float):
        raise subprocess.TimeoutExpired(argv, timeout)

    outcome = run_scancode_fallback(
        package,
        work_root=tmp_path,
        source_root=source_root,
        command_runner=runner,
        executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
    )

    assert outcome.spdx_id is None
    assert outcome.anchor == "unresolved:scancode_timeout"


def test_p3b_scancode_runs_only_for_unresolved_records(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    package_dir = source_root / "unknown"
    package_dir.mkdir(parents=True)
    (package_dir / "package.py").write_text("", encoding="utf-8")
    sbom = {
        "schema_version": "1.0",
        "repo": "fixture-ref",
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
    }
    calls: list[list[str]] = []
    records: list[dict[str, object]] = []

    def runner(argv: list[str], *, timeout: float):
        del timeout
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout='{"files":[{"license_expression_spdx":"Apache-2.0"}]}',
            stderr="",
        )

    def writer(
        work_root: str | Path,
        repo_ref: str,
        resolved_records: list[dict[str, object]],
    ) -> Path:
        del repo_ref
        records.extend(resolved_records)
        return Path(work_root) / "resolved.ndjson"

    run_resolve(
        tmp_path,
        "fixture-ref",
        source_root=source_root,
        adapters=[],
        scancode_runner=runner,
        scancode_executable_provider=lambda work_root: Path(work_root) / "tools" / "scancode",
        sbom_reader=lambda work_root, repo_ref: sbom,
        resolved_writer=writer,
    )

    assert records[0]["name"] == "declared-lib"
    assert records[0]["spdx_id"] == "MIT"
    assert records[0]["evidence"]["source_layer"] == "syft"
    assert records[1]["name"] == "unknown-lib"
    assert records[1]["spdx_id"] == "Apache-2.0"
    assert records[1]["evidence"]["source_layer"] == "scancode"
    assert len(calls) == 1
    assert str(package_dir) in calls[0]
    assert str(source_root / "declared") not in calls[0]
