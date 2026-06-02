"""Hardened clone command construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class CloneInvocation:
    """Arguments and environment for a hardened clone operation."""

    argv: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)


def build_hardened_clone_command(remote_url: str, destination: Path | str) -> CloneInvocation:
    """Return a hardened git clone invocation without executing it."""

    if not remote_url.startswith("https://"):
        raise ValueError("clone remote must use https")

    destination_path = str(destination)
    argv = (
        "git",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "clone",
        "--depth=1",
        "--no-tags",
        "--single-branch",
        "--no-recurse-submodules",
        remote_url,
        destination_path,
    )
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return CloneInvocation(argv=argv, env=env)
