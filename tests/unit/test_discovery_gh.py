from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence

import pytest

from repolens.data.errors import LimitExceeded
from repolens.discovery.gh import GhRunResult, build_repo_list_command, list_repositories
from repolens.exit_codes import InputError


def test_build_repo_list_command_uses_gh_without_shell() -> None:
    assert build_repo_list_command("sentinel-owner", 25) == [
        "gh",
        "repo",
        "list",
        "sentinel-owner",
        "--json",
        "name,nameWithOwner,description,url,isArchived,isPrivate,repositoryTopics",
        "--limit",
        "25",
    ]


def test_list_repositories_parses_gh_json() -> None:
    commands: list[Sequence[str]] = []

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        commands.append(command)
        assert timeout_seconds == 30.0
        return GhRunResult(
            0,
            json.dumps(
                [
                    {
                        "name": "sentinel-alpha",
                        "nameWithOwner": "sentinel-owner/sentinel-alpha",
                        "description": "fixture repo",
                        "url": "https://example.invalid/sentinel-alpha",
                        "isArchived": False,
                        "isPrivate": True,
                        "repositoryTopics": [{"name": "runtime"}],
                    }
                ]
            ),
            "",
        )

    repositories = list_repositories("sentinel-owner", limit=25, runner=runner)

    assert list(commands[0])[:4] == ["gh", "repo", "list", "sentinel-owner"]
    assert repositories[0].name == "sentinel-alpha"
    assert repositories[0].topics == ("runtime",)
    assert repositories[0].private is True


def test_list_repositories_rejects_timeout() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise subprocess.TimeoutExpired(command, timeout_seconds)

    with pytest.raises(InputError, match="timed out"):
        list_repositories("sentinel-owner", runner=runner)


def test_list_repositories_rejects_oversize_stdout() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(0, "[{}]", "")

    with pytest.raises(LimitExceeded):
        list_repositories("sentinel-owner", runner=runner, stdout_max_bytes=2)


def test_list_repositories_redacts_failed_gh_stderr() -> None:
    token = "ghp_" + "a" * 20

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(1, "", f"failed with {token}")

    with pytest.raises(InputError) as excinfo:
        list_repositories("sentinel-owner", runner=runner)

    assert token not in str(excinfo.value)
    assert "[REDACTED_TOKEN]" in str(excinfo.value)
