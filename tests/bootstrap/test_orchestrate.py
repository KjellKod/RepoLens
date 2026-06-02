"""End-to-end orchestration tests (offline, injected runners)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap import errors, orchestrate
from repolens.bootstrap.orchestrate import EXIT_INTEGRITY, EXIT_OK, run, run_safe
from repolens.bootstrap.scancode import (
    SCANCODE_REQUIREMENTS_SOURCE_PREFIX,
    build_scancode_wrapper,
    requirements_sha256,
)

from .conftest import PLATFORM


def _write_test_pins(tmp_path: Path, test_pins) -> Path:
    """Serialize the in-memory test pins to a TOML file for run()."""
    import tomllib  # noqa: F401  (ensures 3.11+)

    syft = test_pins.tool("syft")
    cosign = test_pins.tool("cosign")
    sig = syft.signature
    syft_art = syft.artifact_for(PLATFORM)
    cosign_art = cosign.artifact_for(PLATFORM)
    text = f"""
schema = "repolens.pins/v1"
[base_image]
ref = "{test_pins.base_image}"
[tools.syft]
version = "1.18.1"
[tools.syft.platforms."{PLATFORM}"]
artifact = "{syft_art.artifact}"
sha256 = "{syft_art.sha256}"
[tools.syft.signature]
mechanism = "cosign-keyless"
checksums_file = "{sig.checksums_file}"
checksums_sig = "{sig.checksums_sig}"
checksums_cert = "{sig.checksums_cert}"
cert_identity_regex = "{sig.cert_identity_regex}"
cert_oidc_issuer = "{sig.cert_oidc_issuer}"
[tools.cosign]
version = "2.4.1"
[tools.cosign.platforms."{PLATFORM}"]
artifact = "{cosign_art.artifact}"
sha256 = "{cosign_art.sha256}"
[tools.scancode]
version = "32.3.1"
requirements = "scancode.requirements.txt"
[tools.git]
version = "2.47.1"
[tools.git.platforms."{PLATFORM}"]
artifact = "git.tar.gz"
sha256 = "{"a" * 64}"
[tools.gh]
version = "2.63.2"
[tools.gh.platforms."{PLATFORM}"]
artifact = "gh.tar.gz"
sha256 = "{"b" * 64}"
"""
    p = tmp_path / "pins.toml"
    p.write_text(text)
    return p


@pytest.fixture
def req_file(tmp_path: Path) -> Path:
    p = tmp_path / "scancode.requirements.txt"
    p.write_text(f"scancode-toolkit==32.3.1 --hash=sha256:{'c' * 64}\n")
    return p


def test_run_happy_path_writes_versions(
    test_pins, acquire_factory, accepting_cosign_runner, req_file, tmp_path
):
    pins_path = _write_test_pins(tmp_path, test_pins)
    versions_out = tmp_path / "tool_versions.json"
    make_exe = MagicMock()
    pip_runner = MagicMock(return_value=0)

    rc = run(
        pins_path=pins_path,
        dest_dir=tmp_path / "tools",
        versions_out=versions_out,
        acquire=acquire_factory(),
        make_executable=make_exe,
        cosign_runner=accepting_cosign_runner,
        pip_runner=pip_runner,
        requirements_path=req_file,
        platform_key=PLATFORM,
    )
    assert rc == EXIT_OK
    assert (tmp_path / "tools" / "syft").exists()
    assert (tmp_path / "tools" / "cosign").exists()
    scancode_wrapper = tmp_path / "tools" / "scancode"
    assert scancode_wrapper.exists()
    scancode_digest = requirements_sha256(req_file)
    assert scancode_wrapper.read_text(encoding="utf-8") == build_scancode_wrapper(
        "32.3.1", scancode_digest
    )
    payload = json.loads(versions_out.read_text())
    assert payload["tools"]["syft"]["version"] == "1.18.1"
    assert payload["tools"]["scancode"] == {
        "version": "32.3.1",
        "digest": scancode_digest,
        "source": f"{SCANCODE_REQUIREMENTS_SOURCE_PREFIX}{req_file.name}",
    }
    pip_runner.assert_called_once()
    assert scancode_wrapper in [call.args[0] for call in make_exe.mock_calls]


def test_run_tampered_syft_raises_integrity(
    test_pins, acquire_factory, syft_tampered_bytes, accepting_cosign_runner, req_file, tmp_path
):
    pins_path = _write_test_pins(tmp_path, test_pins)
    make_exe = MagicMock()
    pip_runner = MagicMock(return_value=0)

    with pytest.raises(errors.ChecksumMismatch):
        run(
            pins_path=pins_path,
            dest_dir=tmp_path / "tools",
            versions_out=tmp_path / "tv.json",
            acquire=acquire_factory(syft_override=syft_tampered_bytes),
            make_executable=make_exe,
            cosign_runner=accepting_cosign_runner,
            pip_runner=pip_runner,
            requirements_path=req_file,
            platform_key=PLATFORM,
        )
    # ScanCode pip step is after Syft; never reached on integrity failure.
    pip_runner.assert_not_called()
    assert not (tmp_path / "tv.json").exists()


def test_run_scancode_install_failure_raises_integrity(
    test_pins, acquire_factory, accepting_cosign_runner, req_file, tmp_path
):
    pins_path = _write_test_pins(tmp_path, test_pins)

    with pytest.raises(errors.IntegrityError, match="ScanCode install failed"):
        run(
            pins_path=pins_path,
            dest_dir=tmp_path / "tools",
            versions_out=tmp_path / "tv.json",
            acquire=acquire_factory(),
            make_executable=MagicMock(),
            cosign_runner=accepting_cosign_runner,
            pip_runner=MagicMock(return_value=1),
            requirements_path=req_file,
            platform_key=PLATFORM,
        )

    assert not (tmp_path / "tv.json").exists()


def test_run_safe_maps_integrity_to_exit_code(
    test_pins, acquire_factory, syft_tampered_bytes, accepting_cosign_runner, req_file, tmp_path
):
    pins_path = _write_test_pins(tmp_path, test_pins)
    rc = run_safe(
        pins_path=pins_path,
        dest_dir=tmp_path / "tools",
        versions_out=tmp_path / "tv.json",
        acquire=acquire_factory(syft_override=syft_tampered_bytes),
        make_executable=MagicMock(),
        cosign_runner=accepting_cosign_runner,
        pip_runner=MagicMock(return_value=0),
        requirements_path=req_file,
        platform_key=PLATFORM,
    )
    assert rc == EXIT_INTEGRITY


def test_dry_run_validates_only(test_pins, req_file, tmp_path):
    pins_path = _write_test_pins(tmp_path, test_pins)
    rc = run(
        pins_path=pins_path,
        dest_dir=tmp_path / "tools",
        versions_out=tmp_path / "tv.json",
        acquire=lambda name: (_ for _ in ()).throw(AssertionError("acquire called in dry-run")),
        cosign_runner=lambda argv: 0,
        pip_runner=lambda argv: 0,
        requirements_path=req_file,
        dry_run=True,
    )
    assert rc == EXIT_OK
    assert not (tmp_path / "tools").exists()


def test_default_make_executable_sets_x_bit(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"x")
    orchestrate.default_make_executable(f)
    import os
    import stat

    assert os.stat(f).st_mode & stat.S_IXUSR
