"""Tests for hash-pinned ScanCode install (AC #4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.bootstrap.errors import UnhashedRequirement
from repolens.bootstrap.scancode import (
    DEFAULT_REQUIREMENTS_PATH,
    build_pip_argv,
    build_scancode_hash_pinned_venv_wrapper,
    build_scancode_venv_wrapper,
    build_scancode_wrapper,
    install_scancode,
    install_scancode_hash_pinned_venv,
    install_scancode_venv,
    load_requirements,
    provision_scancode_work_root,
    requirements_sha256,
    scancode_hash_pinned_venv_source,
    scancode_venv_digest,
    validate_requirements,
)
from repolens.resolve.scancode import resolve_scancode_path

FIXTURES = Path(__file__).parent / "fixtures"


def test_shipped_requirements_all_hashed():
    # load_requirements validates; raises if any line is unhashed/unpinned.
    text = load_requirements(DEFAULT_REQUIREMENTS_PATH)
    assert "--hash=sha256:" in text
    assert "==" in text


def test_pip_argv_has_require_hashes():
    argv = build_pip_argv(Path("/tmp/r.txt"))
    assert "--require-hashes" in argv
    assert "--no-deps" in argv
    assert "--only-binary=:all:" in argv
    assert argv[-2:] == ["--requirement", "/tmp/r.txt"]


def test_scancode_wrapper_rejects_multiline_version():
    with pytest.raises(ValueError, match="single line"):
        build_scancode_wrapper("32.4.1\nmalicious", "a" * 64)


def test_unhashed_line_rejected():
    with pytest.raises(UnhashedRequirement, match="hash"):
        validate_requirements("acme-scanner==1.2.3\n")


def test_unpinned_but_hashed_line_rejected():
    with pytest.raises(UnhashedRequirement, match="=="):
        validate_requirements(f"acme-scanner --hash=sha256:{'a' * 64}\n")


def test_wildcard_version_pin_rejected():
    with pytest.raises(UnhashedRequirement, match="concrete version"):
        validate_requirements(f"acme-scanner==1.2.* --hash=sha256:{'a' * 64}\n")


def test_continuation_line_accepted():
    text = f"acme-scanner==1.2.3 \\\n    --hash=sha256:{'a' * 64}\n"
    validate_requirements(text)  # no raise


def test_comments_and_options_ignored():
    text = f"# a comment\n--require-hashes\nacme-scanner==1.0.0 --hash=sha256:{'a' * 64}\n"
    validate_requirements(text)  # no raise


def test_nohash_fixture_rejected():
    text = (FIXTURES / "requirements.nohash.bad.txt").read_text()
    with pytest.raises(UnhashedRequirement):
        validate_requirements(text)


def test_install_runs_runner_only_after_validation(tmp_path):
    req = tmp_path / "r.txt"
    req.write_text(f"acme-scanner==1.0.0 --hash=sha256:{'a' * 64}\n")
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    code = install_scancode(req, runner=runner)
    assert code == 0
    assert calls and "--require-hashes" in calls[0]


def test_scancode_venv_wrapper_uses_work_root_local_python() -> None:
    digest = scancode_venv_digest("32.4.1")
    wrapper = build_scancode_venv_wrapper("32.4.1", digest)

    assert "scancode-venv/bin/python" in wrapper
    assert "python3 -m scancode.cli" not in wrapper


def test_install_scancode_venv_creates_venv_then_installs_exact_version(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    install_scancode_venv(tmp_path / "venv", version="32.4.1", python="python-test", runner=runner)

    assert calls[0] == ["python-test", "-m", "venv", str(tmp_path / "venv")]
    assert calls[1][-2:] == ["--only-binary=:all:", "scancode-toolkit==32.4.1"]


def test_install_scancode_hash_pinned_venv_uses_closed_pip_argv(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            venv_python = Path(argv[-1]) / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    install_scancode_hash_pinned_venv(tmp_path / "venv", python="python-test", runner=runner)

    assert calls[0] == ["python-test", "-m", "venv", str(tmp_path / "venv")]
    assert "--require-hashes" in calls[1]
    assert "--no-deps" in calls[1]
    assert "--only-binary=:all:" in calls[1]
    assert calls[1][-2:] == ["--requirement", str(DEFAULT_REQUIREMENTS_PATH)]


def test_hash_pinned_venv_wrapper_uses_work_root_python_and_requirements_proof() -> None:
    digest = requirements_sha256(DEFAULT_REQUIREMENTS_PATH)
    source = scancode_hash_pinned_venv_source(DEFAULT_REQUIREMENTS_PATH)
    wrapper = build_scancode_hash_pinned_venv_wrapper(
        "32.4.1",
        digest,
        requirements_source=source,
    )

    assert "scancode-venv/bin/python" in wrapper
    assert f"requirements-source: {source}" in wrapper
    assert f"requirements-sha256: {digest}" in wrapper


def test_provision_scancode_work_root_writes_valid_verified_wrapper(tmp_path: Path) -> None:
    calls = _provision_with_fake_pip(tmp_path)

    wrapper = provision_scancode_work_root(
        tmp_path,
        python="python-test",
        runner=calls.runner,
        make_executable=_chmod,
    )

    assert wrapper == tmp_path / "tools" / "scancode"
    assert resolve_scancode_path(tmp_path) == wrapper
    assert (tmp_path / "tools" / "scancode-venv" / "bin" / "python").is_file()
    assert any("--require-hashes" in call for call in calls.argv)
    assert any("--no-deps" in call for call in calls.argv)


def test_provision_scancode_work_root_replaces_corrupt_partial_install(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "scancode").write_text("#!/bin/sh\necho unsafe\n", encoding="utf-8")
    (tools / "scancode").chmod(0o755)
    (tmp_path / "tool_versions.json").write_text('{"schema":"bad"}\n', encoding="utf-8")
    calls = _provision_with_fake_pip(tmp_path)

    wrapper = provision_scancode_work_root(
        tmp_path,
        python="python-test",
        runner=calls.runner,
        make_executable=_chmod,
    )

    assert resolve_scancode_path(tmp_path) == wrapper
    assert "echo unsafe" not in wrapper.read_text(encoding="utf-8")
    assert len(calls.argv) == 2


def test_provision_scancode_work_root_does_not_expose_wrapper_when_install_fails(
    tmp_path: Path,
) -> None:
    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            venv_python = Path(argv[-1]) / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 1, "", "pip failed")

    with pytest.raises(RuntimeError, match="pip failed"):
        provision_scancode_work_root(
            tmp_path,
            python="python-test",
            runner=runner,
            make_executable=_chmod,
        )

    assert not (tmp_path / "tools" / "scancode").exists()
    assert not (tmp_path / "tool_versions.json").exists()


def test_provision_scancode_work_root_writes_trust_marker_last_after_exposure_failure(
    tmp_path: Path,
) -> None:
    calls = _provision_with_fake_pip(tmp_path)
    fail_once = True

    def mover(src: Path, dst: Path) -> None:
        nonlocal fail_once
        if fail_once and dst.name == "tool_versions.json":
            fail_once = False
            raise RuntimeError("simulated crash before trust marker")
        from repolens.bootstrap.scancode import _replace_path

        _replace_path(src, dst)

    with pytest.raises(RuntimeError, match="simulated crash"):
        provision_scancode_work_root(
            tmp_path,
            python="python-test",
            runner=calls.runner,
            make_executable=_chmod,
            mover=mover,
        )

    assert not (tmp_path / "tool_versions.json").exists()
    provision_scancode_work_root(
        tmp_path,
        python="python-test",
        runner=calls.runner,
        make_executable=_chmod,
        mover=mover,
    )

    assert resolve_scancode_path(tmp_path) == tmp_path / "tools" / "scancode"
    assert len(calls.argv) == 4


def test_install_rejects_unhashed_without_running(tmp_path):
    req = FIXTURES / "requirements.nohash.bad.txt"
    runner_called = False

    def runner(argv: list[str]) -> int:
        nonlocal runner_called
        runner_called = True
        return 0

    with pytest.raises(UnhashedRequirement):
        install_scancode(req, runner=runner)
    assert runner_called is False


class _FakeProvisionCalls:
    def __init__(self) -> None:
        self.argv: list[list[str]] = []

    def runner(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.argv.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            venv_python = Path(argv[-1]) / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/bin/sh\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _provision_with_fake_pip(_tmp_path: Path) -> _FakeProvisionCalls:
    return _FakeProvisionCalls()


def _chmod(path: Path) -> None:
    path.chmod(path.stat().st_mode | 0o755)
