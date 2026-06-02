from pathlib import Path

import pytest

from repolens.security.clone import build_hardened_clone_command


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


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
    with pytest.raises(ValueError, match="credentials"):
        build_hardened_clone_command("https://token@example.invalid/project.git", Path("dst"))
