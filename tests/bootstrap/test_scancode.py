"""Tests for hash-pinned ScanCode install (AC #4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.bootstrap.errors import UnhashedRequirement
from repolens.bootstrap.scancode import (
    DEFAULT_REQUIREMENTS_PATH,
    build_pip_argv,
    build_scancode_venv_wrapper,
    build_scancode_wrapper,
    install_scancode,
    install_scancode_venv,
    load_requirements,
    scancode_venv_digest,
    validate_requirements,
)

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
