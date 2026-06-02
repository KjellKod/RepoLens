from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from repolens.security.clone import CloneOptions, build_hardened_clone_command, hardened_clone
from repolens.security.errors import CloneSecurityError


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_clone_args_hardened() -> None:
    invocation = build_hardened_clone_command("https://example.invalid/project.git", Path("dst"))

    assert "--no-recurse-submodules" in invocation.argv
    assert "--depth=1" in invocation.argv
    assert "--no-tags" in invocation.argv
    assert "--single-branch" in invocation.argv
    assert "protocol.file.allow=never" in invocation.argv
    assert "core.hooksPath=/dev/null" in invocation.argv
    assert invocation.env["GIT_TERMINAL_PROMPT"] == "0"
    assert invocation.env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert invocation.env["GIT_CONFIG_NOSYSTEM"] == "1"

    with pytest.raises(ValueError, match="https"):
        build_hardened_clone_command("file:///tmp/source.git", Path("dst"))
    with pytest.raises(ValueError, match="host"):
        build_hardened_clone_command("https:///project.git", Path("dst"))
    with pytest.raises(ValueError, match="credentials"):
        build_hardened_clone_command("https://token@example.invalid/project.git", Path("dst"))


def test_post_checkout_hook_does_not_execute(
    monkeypatch: pytest.MonkeyPatch,
    local_repo_factory,
    tmp_path: Path,
) -> None:
    source = local_repo_factory()
    sentinel = tmp_path / "acme-hook-fired"
    hooks = source / ".git" / "hooks"
    (hooks / "post-checkout").write_text(f"#!/bin/sh\nprintf fired > {sentinel}\n", encoding="utf-8")
    (hooks / "post-checkout").chmod(0o755)

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        assert "--no-recurse-submodules" in command
        assert "core.hooksPath=/dev/null" in command
        clone_path = Path(command[-1])
        shutil.copytree(source, clone_path, ignore=shutil.ignore_patterns(".git"))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    destination = hardened_clone(CloneOptions(str(source), tmp_path / "clone"))
    assert destination.exists()
    assert not sentinel.exists()


def test_submodule_is_not_checked_out_or_contacted(
    monkeypatch: pytest.MonkeyPatch,
    local_repo_factory,
    tmp_path: Path,
) -> None:
    source = local_repo_factory(
        gitmodules=(
            '[submodule "acme-lib"]\n'
            "\tpath = vendor/acme-lib\n"
            "\turl = https://attacker.example/acme-lib\n"
        )
    )

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        if command[:2] == ["git", "config"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="submodule.acme-lib.url https://attacker.example/acme-lib\n",
                stderr="",
            )
        clone_path = Path(command[-1])
        shutil.copytree(source, clone_path, ignore=shutil.ignore_patterns(".git"))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    destination = hardened_clone(CloneOptions(str(source), tmp_path / "clone"))
    assert (destination / ".gitmodules").exists()
    assert not (destination / "vendor" / "acme-lib").exists()


def test_file_protocol_submodule_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    local_repo_factory,
    tmp_path: Path,
) -> None:
    source = local_repo_factory(
        gitmodules=(
            '[submodule "acme-lib"]\n'
            "\tpath = vendor/acme-lib\n"
            "\turl = file:///etc/passwd\n"
        )
    )

    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        if command[:2] == ["git", "config"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="submodule.acme-lib.url file:///etc/passwd\n",
                stderr="",
            )
        clone_path = Path(command[-1])
        shutil.copytree(source, clone_path, ignore=shutil.ignore_patterns(".git"))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions(str(source), tmp_path / "clone"))
    assert not (tmp_path / "clone").exists()
    assert not list(tmp_path.glob(".clone.clone-*"))
