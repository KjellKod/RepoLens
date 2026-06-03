from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence

import pytest

from repolens.data.errors import LimitExceeded
from repolens.discovery.gh import (
    GhRunner,
    GhRunResult,
    build_repo_list_command,
    build_repo_view_command,
    fetch_repositories,
    list_repositories,
    parse_repos_option,
)
from repolens.exit_codes import InputError
from repolens.githost import (
    GH_NOT_AUTHENTICATED_MESSAGE,
    GH_NOT_INSTALLED_MESSAGE,
    rate_limited_message,
)


def _no_sleep(_delay: float) -> None:
    return None


def _repo_view_runner(payload: dict[str, object]) -> tuple[list[list[str]], GhRunner]:
    commands: list[list[str]] = []

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        commands.append(list(command))
        name = command[3].split("/", 1)[1]
        body = dict(payload)
        body.setdefault("name", name)
        body.setdefault("nameWithOwner", f"sentinel-owner/{name}")
        return GhRunResult(0, json.dumps(body), "")

    return commands, runner


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


@pytest.mark.parametrize(
    "owner",
    [
        "--json",
        "-sentinel",
        "sentinel-",
        "sentinel_owner",
        "sentinel/owner",
        "sentinel owner",
        "a" * 40,
    ],
)
def test_list_repositories_rejects_owner_values_that_could_change_gh_args(owner: str) -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise AssertionError("invalid owners must not invoke gh")

    with pytest.raises(InputError, match="--owner"):
        list_repositories(owner, runner=runner)


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


# --- parse_repos_option --------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a,b", ("a", "b")),
        ("a, b ,c", ("a", "b", "c")),
        ("a,b,", ("a", "b")),
        ("a,a,b", ("a", "b")),
        ("repo.name_1-2", ("repo.name_1-2",)),
    ],
)
def test_parse_repos_option_splits_strips_dedupes(raw: str, expected: tuple) -> None:
    assert parse_repos_option(raw) == expected


@pytest.mark.parametrize("raw", ["", " , ", ",,"])
def test_parse_repos_option_rejects_empty_results(raw: str) -> None:
    with pytest.raises(InputError, match="at least one repo name"):
        parse_repos_option(raw)


def test_parse_repos_option_rejects_cross_owner_slug_with_clear_message() -> None:
    with pytest.raises(InputError, match="cross-owner"):
        parse_repos_option("a/b")


@pytest.mark.parametrize(
    "raw, match",
    [
        ("-evil", "dash or dot"),
        (".hidden", "dash or dot"),
        (".", r"'\.' or '\.\.'"),
        ("..", r"'\.' or '\.\.'"),
        ("bad name", "letters, numbers"),
        ("a" * 101, "at most 100"),
    ],
)
def test_parse_repos_option_rejects_invalid_tokens(raw: str, match: str) -> None:
    with pytest.raises(InputError, match=match):
        parse_repos_option(raw)


# --- build_repo_view_command --------------------------------------------


def test_build_repo_view_command_uses_gh_without_shell_or_limit() -> None:
    assert build_repo_view_command("sentinel-owner", "sentinel-alpha") == [
        "gh",
        "repo",
        "view",
        "sentinel-owner/sentinel-alpha",
        "--json",
        "name,nameWithOwner,description,url,isArchived,isPrivate,repositoryTopics",
    ]


# --- fetch_repositories --------------------------------------------------


def test_fetch_repositories_one_view_per_name_in_input_order() -> None:
    commands, runner = _repo_view_runner({"isPrivate": True})

    repositories = fetch_repositories(
        "sentinel-owner", ("sentinel-beta", "sentinel-alpha"), runner=runner
    )

    assert [list(cmd)[:4] for cmd in commands] == [
        ["gh", "repo", "view", "sentinel-owner/sentinel-beta"],
        ["gh", "repo", "view", "sentinel-owner/sentinel-alpha"],
    ]
    assert tuple(repo.name for repo in repositories) == ("sentinel-beta", "sentinel-alpha")


def test_fetch_repositories_nonexistent_repo_names_failing_token() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(
            1,
            "",
            "GraphQL: Could not resolve to a Repository with the name "
            "'sentinel-owner/sentinel-missing'",
        )

    with pytest.raises(InputError) as excinfo:
        fetch_repositories("sentinel-owner", ("sentinel-missing",), runner=runner)

    message = str(excinfo.value)
    assert "sentinel-missing" in message
    assert "could not resolve repo name" in message
    assert "sentinel-owner/sentinel-missing" not in message
    assert "[REDACTED_PATH]" not in message


def test_fetch_repositories_redacts_token_shaped_repo_name() -> None:
    token = "ghp_" + "a" * 20

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(1, "", f"no such repo {token}")

    with pytest.raises(InputError) as excinfo:
        fetch_repositories("sentinel-owner", (token,), runner=runner)

    assert token not in str(excinfo.value)
    assert "[REDACTED_TOKEN]" in str(excinfo.value)


def test_fetch_repositories_rejects_timeout() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise subprocess.TimeoutExpired(command, timeout_seconds)

    with pytest.raises(InputError, match="timed out"):
        fetch_repositories("sentinel-owner", ("sentinel-alpha",), runner=runner)


def test_fetch_repositories_rejects_oversize_stdout() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(0, "{}", "")

    with pytest.raises(LimitExceeded):
        fetch_repositories("sentinel-owner", ("sentinel-alpha",), runner=runner, stdout_max_bytes=1)


def test_fetch_repositories_rejects_more_than_max_limit() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise AssertionError("over-limit name lists must not invoke gh")

    names = tuple(f"sentinel-{index}" for index in range(5001))
    with pytest.raises(InputError, match="at most"):
        fetch_repositories("sentinel-owner", names, runner=runner)


def test_fetch_repositories_malformed_response_surfaces_view_wording() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(0, json.dumps([1, 2, 3]), "")

    with pytest.raises(InputError, match="gh repo view") as excinfo:
        fetch_repositories("sentinel-owner", ("sentinel-alpha",), runner=runner)

    assert "gh repo list" not in str(excinfo.value)


# --- gh not installed / not authenticated / transient retry --------------


def test_list_repositories_gh_not_installed_message() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise FileNotFoundError("gh")

    with pytest.raises(InputError) as excinfo:
        list_repositories("sentinel-owner", runner=runner)

    assert str(excinfo.value) == GH_NOT_INSTALLED_MESSAGE


def test_list_repositories_gh_not_authenticated_message() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(1, "", "gh: not logged into any GitHub hosts. Run gh auth login")

    with pytest.raises(InputError) as excinfo:
        list_repositories("sentinel-owner", runner=runner)

    assert str(excinfo.value) == GH_NOT_AUTHENTICATED_MESSAGE


def test_list_repositories_transient_retried_then_surfaced() -> None:
    calls = {"n": 0}

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        calls["n"] += 1
        return GhRunResult(1, "", "HTTP 429: API rate limit exceeded")

    with pytest.raises(InputError) as excinfo:
        list_repositories("sentinel-owner", runner=runner, sleep=_no_sleep, retry_max_attempts=3)

    assert calls["n"] == 3
    assert str(excinfo.value) == rate_limited_message(3)


def test_fetch_repositories_transient_detected_before_generic_rewrite() -> None:
    # item 3: the 429/secondary-rate-limit signal must be seen on the RAW result,
    # before fetch_repositories' generic "could not resolve repo name" rewrite.
    calls = {"n": 0}

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        calls["n"] += 1
        return GhRunResult(1, "", "You have exceeded a secondary rate limit. Please wait")

    with pytest.raises(InputError) as excinfo:
        fetch_repositories(
            "sentinel-owner",
            ("sentinel-alpha",),
            runner=runner,
            sleep=_no_sleep,
            retry_max_attempts=3,
        )

    assert calls["n"] == 3
    message = str(excinfo.value)
    assert message == rate_limited_message(3)
    assert "could not resolve repo name" not in message


def test_fetch_repositories_gh_not_authenticated_message() -> None:
    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(1, "", "gh: not logged into any GitHub hosts")

    with pytest.raises(InputError) as excinfo:
        fetch_repositories("sentinel-owner", ("sentinel-alpha",), runner=runner)

    assert str(excinfo.value) == GH_NOT_AUTHENTICATED_MESSAGE
