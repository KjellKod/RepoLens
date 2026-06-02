from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repolens.security.clone import (
    CloneOptions,
    _build_clone_command,
    _scrubbed_git_env,
    _validate_gitmodules,
    hardened_clone,
)
from repolens.security.errors import CloneSecurityError
from repolens.security.limits import SecurityLimits


def test_clone_uses_all_hardening_flags(tmp_path: Path) -> None:
    command = _build_clone_command(
        CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"),
        tmp_path / "clone",
    )
    joined = " ".join(command)
    assert "-c protocol.file.allow=never" in joined
    assert "-c core.hooksPath=/dev/null" in joined
    assert "-c core.symlinks=false" in joined
    assert "--depth=1" in command
    assert "--no-tags" in command
    assert "--single-branch" in command
    assert "--no-recurse-submodules" in command


def test_clone_scrubs_git_environment() -> None:
    token = "ghp_" + "acme" * 5
    env = _scrubbed_git_env(
        {
            "PATH": "/bin",
            "GIT_ASKPASS": "leak",
            "GITHUB_TOKEN": token,
            "GIT_CONFIG_GLOBAL": "/tmp/unsafe",
        }
    )
    assert env["PATH"] == "/bin"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_COUNT"] == "0"
    assert "GIT_ASKPASS" not in env
    assert "GITHUB_TOKEN" not in env


def test_clone_rejects_file_remote(tmp_path: Path) -> None:
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions("file:///tmp/acme.git", tmp_path / "dst"))


def test_clone_rejects_file_submodule_url(tmp_path: Path) -> None:
    gitmodules = tmp_path / ".gitmodules"
    gitmodules.write_text(
        '[submodule "acme-lib"]\n\tpath = vendor/acme-lib\n\turl = file:///tmp/acme-lib\n',
        encoding="utf-8",
    )
    with pytest.raises(CloneSecurityError):
        _validate_gitmodules(gitmodules)


def test_clone_rejects_git_config_dotted_submodule_url(tmp_path: Path) -> None:
    gitmodules = tmp_path / ".gitmodules"
    gitmodules.write_text(
        "[submodule.acme-lib]\n\tpath = vendor/acme-lib\n\turl = file:///tmp/acme-lib\n",
        encoding="utf-8",
    )
    with pytest.raises(CloneSecurityError):
        _validate_gitmodules(gitmodules)


def test_clone_cleans_tempdir_on_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="fatal: acme failure\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"))
    assert not list(tmp_path.glob(".dst.clone-*"))
    assert len(calls) == 2


def test_clone_failure_redacts_supported_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "ghp_" + "1234567890abcdef1234567890abcdef1234"

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr=f"fatal: Authentication failed for https://x:{token}@allowed.example/acme.git\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError) as exc_info:
        hardened_clone(CloneOptions("https://allowed.example/acme.git", tmp_path / "dst"))

    assert token not in str(exc_info.value)
    assert "[REDACTED_TOKEN]" in str(exc_info.value)


def test_clone_timeout_cleans_tempdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        raise subprocess.TimeoutExpired(command, timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    limits = SecurityLimits(clone_timeout_seconds=0.01)
    with pytest.raises(CloneSecurityError, match="timed out"):
        hardened_clone(
            CloneOptions("https://example.invalid/acme.git", tmp_path / "dst", limits=limits)
        )
    assert not list(tmp_path.glob(".dst.clone-*"))


def test_clone_rejects_old_git_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="git version 2.44.0\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError, match="below required"):
        hardened_clone(CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"))
