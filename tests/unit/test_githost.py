from __future__ import annotations

from repolens.githost import (
    GH_NOT_AUTHENTICATED_MESSAGE,
    GH_NOT_INSTALLED_MESSAGE,
    access_denied_message,
    is_gh_not_authenticated,
    is_gh_transient,
    private_repo_needs_auth_message,
    rate_limited_message,
    resolve_clone_credential,
    resolve_clone_credential_result,
)

TOKEN = "ghp_" + "A" * 36
ENV_TOKEN = "ghp_" + "B" * 36
GITHUB_ENV_TOKEN = "ghp_" + "C" * 36


def _no_sleep(_delay: float) -> None:
    return None


def test_gh_auth_token_used_when_present() -> None:
    def runner() -> tuple[int, str, str]:
        return (0, TOKEN + "\n", "")

    cred = resolve_clone_credential(gh_runner=runner, env={}, sleep=_no_sleep)

    assert cred is not None
    assert cred.secret == TOKEN
    # The token never leaks through the wrapper's repr.
    assert TOKEN not in repr(cred)


def test_falls_back_to_gh_token_env() -> None:
    def runner() -> tuple[int, str, str]:
        return (1, "", "not logged in")

    cred = resolve_clone_credential(gh_runner=runner, env={"GH_TOKEN": ENV_TOKEN}, sleep=_no_sleep)

    assert cred is not None and cred.secret == ENV_TOKEN


def test_falls_back_to_github_token_env() -> None:
    def runner() -> tuple[int, str, str]:
        return (1, "", "not logged in")

    cred = resolve_clone_credential(
        gh_runner=runner, env={"GITHUB_TOKEN": GITHUB_ENV_TOKEN}, sleep=_no_sleep
    )

    assert cred is not None and cred.secret == GITHUB_ENV_TOKEN


def test_blank_gh_token_env_falls_back_to_github_token_env() -> None:
    def runner() -> tuple[int, str, str]:
        return (1, "", "not logged in")

    cred = resolve_clone_credential(
        gh_runner=runner,
        env={"GH_TOKEN": "   ", "GITHUB_TOKEN": GITHUB_ENV_TOKEN},
        sleep=_no_sleep,
    )

    assert cred is not None and cred.secret == GITHUB_ENV_TOKEN


def test_gh_token_preferred_over_env() -> None:
    def runner() -> tuple[int, str, str]:
        return (0, TOKEN, "")

    cred = resolve_clone_credential(gh_runner=runner, env={"GH_TOKEN": ENV_TOKEN}, sleep=_no_sleep)

    assert cred is not None and cred.secret == TOKEN


def test_returns_none_when_no_credential_anywhere() -> None:
    def runner() -> tuple[int, str, str]:
        return (1, "", "not logged in")

    assert resolve_clone_credential(gh_runner=runner, env={}, sleep=_no_sleep) is None


def test_result_preserves_gh_not_installed_message_when_no_env_token() -> None:
    def runner() -> tuple[int, str, str]:
        return (127, "", "gh not found")

    result = resolve_clone_credential_result(gh_runner=runner, env={}, sleep=_no_sleep)

    assert result.credential is None
    assert result.unavailable_message == GH_NOT_INSTALLED_MESSAGE


def test_result_preserves_gh_not_authenticated_message_when_no_env_token() -> None:
    def runner() -> tuple[int, str, str]:
        return (1, "", "gh: not logged into any GitHub hosts")

    result = resolve_clone_credential_result(gh_runner=runner, env={}, sleep=_no_sleep)

    assert result.credential is None
    assert result.unavailable_message == GH_NOT_AUTHENTICATED_MESSAGE


def test_transient_gh_failure_retried_then_env_fallback() -> None:
    calls = {"n": 0}

    def runner() -> tuple[int, str, str]:
        calls["n"] += 1
        return (1, "", "You have exceeded a secondary rate limit")

    cred = resolve_clone_credential(
        gh_runner=runner,
        env={"GH_TOKEN": ENV_TOKEN},
        sleep=_no_sleep,
        max_attempts=3,
    )

    # Retried up to the cap, then fell through to the env token.
    assert calls["n"] == 3
    assert cred is not None and cred.secret == ENV_TOKEN


def test_not_authenticated_is_not_retried() -> None:
    calls = {"n": 0}

    def runner() -> tuple[int, str, str]:
        calls["n"] += 1
        return (1, "", "gh: not logged into any GitHub hosts")

    cred = resolve_clone_credential(gh_runner=runner, env={}, sleep=_no_sleep, max_attempts=3)

    # Not transient: a single attempt, no retry, falls straight through to env (None).
    assert calls["n"] == 1
    assert cred is None


def test_is_gh_transient_classifies_on_raw_result() -> None:
    assert is_gh_transient(1, "HTTP 429: too many requests") is True
    assert is_gh_transient(1, "The requested URL returned error: 503") is True
    assert is_gh_transient(1, "You have exceeded a secondary rate limit") is True
    assert is_gh_transient(1, "dial tcp: connection reset by peer") is True
    assert is_gh_transient(1, "could not resolve host: api.github.com") is True
    # Auth/not-authenticated is terminal, never transient.
    assert is_gh_transient(1, "gh: not logged into any GitHub hosts") is False
    # Bare incidental numbers are not enough to classify as transient.
    assert is_gh_transient(1, "processed 503 objects before a terminal auth failure") is False
    # A success is never transient.
    assert is_gh_transient(0, "rate limit") is False


def test_is_gh_not_authenticated_covers_common_gh_401_messages() -> None:
    assert is_gh_not_authenticated("Bad credentials") is True
    assert is_gh_not_authenticated("This endpoint requires you to be authenticated") is True
    assert is_gh_not_authenticated("HTTP 401: requires authentication") is True
    assert is_gh_not_authenticated("gh: not logged into any GitHub hosts") is True
    assert is_gh_not_authenticated("HTTP 429: rate limit exceeded") is False


def test_message_builders_match_brief_wording() -> None:
    assert GH_NOT_INSTALLED_MESSAGE == (
        "GitHub CLI (gh) not found. Install it (https://cli.github.com) and run "
        "`gh auth login`, or set GH_TOKEN."
    )
    assert GH_NOT_AUTHENTICATED_MESSAGE == (
        "GitHub CLI is not authenticated. Run `gh auth login` (or set GH_TOKEN)."
    )
    assert private_repo_needs_auth_message("sentinel-owner/sentinel-alpha") == (
        "private repo sentinel-owner/sentinel-alpha needs auth: run `gh auth login` "
        "or set GH_TOKEN."
    )
    assert access_denied_message("sentinel-owner/sentinel-alpha") == (
        "no access to sentinel-owner/sentinel-alpha with the current GitHub credential."
    )
    assert rate_limited_message(2) == "rate-limited after 2 retries - try again later"
