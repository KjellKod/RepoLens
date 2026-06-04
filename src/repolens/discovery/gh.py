"""``gh repo list`` and ``gh repo view`` orchestration for discovery."""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from repolens.data.errors import LimitExceeded
from repolens.data.limits import MAX_JSON_DEPTH, scan_depth
from repolens.exit_codes import InputError
from repolens.githost import (
    GH_NOT_AUTHENTICATED_MESSAGE,
    GH_NOT_INSTALLED_MESSAGE,
    GhTransientError,
    is_gh_not_authenticated,
    is_gh_transient,
    is_gh_transient_error,
    rate_limited_message,
)
from repolens.security.redaction import redact_tokens
from repolens.security.retry import DEFAULT_BASE_DELAY, DEFAULT_MAX_ATTEMPTS, retry_with_backoff

from .models import GhRepository

GH_REPO_LIST_FIELDS = (
    "name",
    "nameWithOwner",
    "description",
    "url",
    "isArchived",
    "isPrivate",
    "repositoryTopics",
)
DEFAULT_GH_TIMEOUT_SECONDS = 30.0
DEFAULT_GH_STDOUT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_GH_LIMIT = 1000
MAX_GH_LIMIT = 5000
OWNER_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
# GitHub repo names: first char alnum/underscore, remainder alnum plus . _ - .
REPO_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
MAX_REPO_NAME_LENGTH = 100


@dataclass(frozen=True)
class GhRunResult:
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[[Sequence[str], float], GhRunResult]

#: Retry budget for transient (429 / secondary-rate-limit / network) gh failures.
GH_RETRY_MAX_ATTEMPTS = DEFAULT_MAX_ATTEMPTS


def _run_gh_with_retry(
    execute: GhRunner,
    command: Sequence[str],
    timeout_seconds: float,
    *,
    sleep: Callable[[float], None],
    max_attempts: int,
) -> GhRunResult:
    """Run one gh invocation with bounded retry on RAW transient results.

    Transience is classified on the raw ``GhRunResult`` (returncode + stderr) BEFORE
    the caller redacts/rewrites the stderr — a rewrite (e.g. fetch_repositories'
    generic message) would otherwise erase the 429/secondary-rate-limit signal and
    make the retry a no-op (item 3). A transient result raises ``GhTransientError``
    so :func:`retry_with_backoff` (exception-based) can drive the retry; a
    non-transient result (success or terminal failure) is returned unchanged.
    ``subprocess.TimeoutExpired``/``OSError`` from ``execute`` propagate to the
    caller's existing handling (not retried).
    """

    def operation() -> GhRunResult:
        result = execute(command, timeout_seconds)
        if result.returncode != 0 and is_gh_transient(result.returncode, result.stderr):
            raise GhTransientError(redact_tokens(result.stderr))
        return result

    return retry_with_backoff(
        operation,
        is_transient=is_gh_transient_error,
        max_attempts=max_attempts,
        base_delay=DEFAULT_BASE_DELAY,
        sleep=sleep,
    )


def list_repositories(
    owner: str,
    *,
    limit: int = DEFAULT_GH_LIMIT,
    runner: GhRunner | None = None,
    timeout_seconds: float = DEFAULT_GH_TIMEOUT_SECONDS,
    stdout_max_bytes: int = DEFAULT_GH_STDOUT_MAX_BYTES,
    sleep: Callable[[float], None] = time.sleep,
    retry_max_attempts: int = GH_RETRY_MAX_ATTEMPTS,
) -> tuple[GhRepository, ...]:
    """Return repositories under ``owner`` by invoking ``gh repo list``."""

    normalized_owner = validate_owner(owner)
    if limit < 1 or limit > MAX_GH_LIMIT:
        raise InputError(f"discover --limit must be between 1 and {MAX_GH_LIMIT}")

    command = build_repo_list_command(normalized_owner, limit)
    execute = runner or subprocess_gh_runner
    try:
        result = _run_gh_with_retry(
            execute, command, timeout_seconds, sleep=sleep, max_attempts=retry_max_attempts
        )
    except subprocess.TimeoutExpired as exc:
        raise InputError("gh repo list timed out") from exc
    except FileNotFoundError as exc:
        raise InputError(GH_NOT_INSTALLED_MESSAGE) from exc
    except OSError as exc:
        raise InputError("gh repo list could not be started") from exc
    except GhTransientError as exc:
        raise InputError(rate_limited_message(retry_max_attempts)) from exc

    stdout = result.stdout.encode("utf-8", errors="replace")
    if len(stdout) > stdout_max_bytes:
        raise LimitExceeded(f"gh repo list output exceeds {stdout_max_bytes} bytes")
    if result.returncode != 0:
        if is_gh_not_authenticated(result.stderr):
            raise InputError(GH_NOT_AUTHENTICATED_MESSAGE)
        message = redact_tokens(result.stderr.strip() or "gh repo list failed")
        raise InputError(message)

    scan_depth(stdout, MAX_JSON_DEPTH)
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InputError("gh repo list did not return valid JSON") from exc
    if not isinstance(parsed, list):
        raise InputError("gh repo list JSON root must be an array")
    return tuple(_parse_repository(item, normalized_owner) for item in parsed)


def build_repo_list_command(owner: str, limit: int) -> list[str]:
    """Build the argv list for ``gh repo list`` without shell expansion."""

    return [
        "gh",
        "repo",
        "list",
        owner,
        "--json",
        ",".join(GH_REPO_LIST_FIELDS),
        "--limit",
        str(limit),
    ]


def validate_owner(owner: str) -> str:
    """Return a normalized GitHub owner name that cannot be parsed as a ``gh`` flag."""

    normalized_owner = owner.strip()
    if not normalized_owner:
        raise InputError("discover requires a non-empty --owner")
    if not OWNER_PATTERN.fullmatch(normalized_owner):
        raise InputError(
            "discover --owner must be a GitHub owner name using letters, numbers, "
            "and non-leading/non-trailing hyphens"
        )
    return normalized_owner


def validate_repo_name(name: str) -> str:
    """Return a normalized repo name that cannot be parsed as a ``gh`` flag.

    Mirrors :func:`validate_owner`'s fail-before-``gh`` posture: every rejection
    raises :class:`InputError` before any subprocess runs.
    """

    normalized = name.strip()
    if not normalized:
        raise InputError("discover --repos entries must be non-empty repo names")
    if "/" in normalized:
        raise InputError(
            "discover --repos takes repo names under a single --owner; cross-owner "
            "slugs like 'owner/name' are out of scope; pass one owner via --owner"
        )
    if normalized in (".", ".."):
        raise InputError("discover --repos entries must not be '.' or '..'")
    if normalized[0] in "-.":
        raise InputError("discover --repos entries must not begin with a dash or dot")
    if not REPO_NAME_PATTERN.fullmatch(normalized):
        raise InputError(
            "discover --repos entries must use letters, numbers, and "
            "non-leading dots, underscores, or hyphens"
        )
    if len(normalized) > MAX_REPO_NAME_LENGTH:
        raise InputError(
            f"discover --repos entries must be at most {MAX_REPO_NAME_LENGTH} characters"
        )
    return normalized


def parse_repos_option(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated ``--repos`` value into validated repo names.

    Splits on ``,``, strips each token, drops empties, validates each surviving
    token via :func:`validate_repo_name`, and dedupes preserving first-seen order.
    An empty result raises :class:`InputError`.
    """

    seen: list[str] = []
    for token in raw.split(","):
        stripped = token.strip()
        if not stripped:
            continue
        name = validate_repo_name(stripped)
        if name not in seen:
            seen.append(name)
    if not seen:
        raise InputError("discover --repos requires at least one repo name")
    return tuple(seen)


def build_repo_view_command(owner: str, name: str) -> list[str]:
    """Build the argv list for ``gh repo view`` without shell expansion."""

    return [
        "gh",
        "repo",
        "view",
        f"{owner}/{name}",
        "--json",
        ",".join(GH_REPO_LIST_FIELDS),
    ]


def fetch_repositories(
    owner: str,
    names: Sequence[str],
    *,
    runner: GhRunner | None = None,
    timeout_seconds: float = DEFAULT_GH_TIMEOUT_SECONDS,
    stdout_max_bytes: int = DEFAULT_GH_STDOUT_MAX_BYTES,
    sleep: Callable[[float], None] = time.sleep,
    retry_max_attempts: int = GH_RETRY_MAX_ATTEMPTS,
) -> tuple[GhRepository, ...]:
    """Return the named repositories under ``owner`` via one ``gh repo view`` each.

    Reuses the same guardrails as :func:`list_repositories` (owner validation,
    timeout, stdout cap, JSON-depth scan, token redaction, and ``_parse_repository``)
    and preserves input order.
    """

    normalized_owner = validate_owner(owner)
    normalized_names = tuple(validate_repo_name(name) for name in names)
    if not normalized_names:
        raise InputError("discover --repos requires at least one repo name")
    if len(normalized_names) > MAX_GH_LIMIT:
        raise InputError(f"discover --repos accepts at most {MAX_GH_LIMIT} repo names")

    execute = runner or subprocess_gh_runner
    repositories: list[GhRepository] = []
    for name in normalized_names:
        command = build_repo_view_command(normalized_owner, name)
        try:
            result = _run_gh_with_retry(
                execute, command, timeout_seconds, sleep=sleep, max_attempts=retry_max_attempts
            )
        except subprocess.TimeoutExpired as exc:
            raise InputError("gh repo view timed out") from exc
        except FileNotFoundError as exc:
            raise InputError(GH_NOT_INSTALLED_MESSAGE) from exc
        except OSError as exc:
            raise InputError("gh repo view could not be started") from exc
        except GhTransientError as exc:
            # Transient was classified on the RAW result before the generic rewrite
            # below could erase the 429/secondary-rate-limit signal (item 3).
            raise InputError(rate_limited_message(retry_max_attempts)) from exc

        stdout = result.stdout.encode("utf-8", errors="replace")
        if len(stdout) > stdout_max_bytes:
            raise LimitExceeded(f"gh repo view output exceeds {stdout_max_bytes} bytes")
        if result.returncode != 0:
            if is_gh_not_authenticated(result.stderr):
                raise InputError(GH_NOT_AUTHENTICATED_MESSAGE)
            # A token-shaped name passes REPO_NAME_PATTERN, so redact the whole
            # message before it reaches the user. Do not relay gh's raw owner/repo
            # stderr here; the CLI path redactor intentionally scrubs slash-shaped
            # text, which makes missing-repo messages harder to read.
            message = (
                f"discover --repos could not resolve repo name '{name}' under --owner; "
                "check the spelling and repository access"
            )
            raise InputError(redact_tokens(message))

        scan_depth(stdout, MAX_JSON_DEPTH)
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise InputError("gh repo view did not return valid JSON") from exc
        repositories.append(
            _parse_repository(parsed, normalized_owner, command_label="gh repo view")
        )
    return tuple(repositories)


def subprocess_gh_runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
    """Run ``gh`` with captured output and no shell."""

    completed = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    return GhRunResult(completed.returncode, completed.stdout, completed.stderr)


def _parse_repository(
    item: object, owner: str, *, command_label: str = "gh repo list"
) -> GhRepository:
    if not isinstance(item, dict):
        raise InputError(f"{command_label} entries must be objects")

    name = _required_text(item, "name", command_label=command_label)
    name_with_owner = _text(item.get("nameWithOwner")) or f"{owner}/{name}"
    return GhRepository(
        name=name,
        name_with_owner=name_with_owner,
        url=_text(item.get("url")),
        description=_text(item.get("description")),
        topics=_parse_topics(item.get("repositoryTopics")),
        archived=bool(item.get("isArchived")),
        private=bool(item.get("isPrivate")),
    )


def _required_text(
    item: dict[object, object], key: str, *, command_label: str = "gh repo list"
) -> str:
    value = _text(item.get(key))
    if not value:
        raise InputError(f"{command_label} entry missing {key}")
    return value


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _parse_topics(value: object) -> tuple[str, ...]:
    raw_topics: list[object]
    if isinstance(value, dict) and isinstance(value.get("nodes"), list):
        raw_topics = value["nodes"]
    elif isinstance(value, list):
        raw_topics = value
    else:
        raw_topics = []

    topics: list[str] = []
    for raw_topic in raw_topics:
        topic = ""
        if isinstance(raw_topic, str):
            topic = raw_topic
        elif isinstance(raw_topic, dict):
            topic_value = raw_topic.get("name")
            if isinstance(topic_value, str):
                topic = topic_value
            elif isinstance(raw_topic.get("topic"), dict):
                nested = raw_topic["topic"].get("name")
                if isinstance(nested, str):
                    topic = nested
        topic = topic.strip()
        if topic:
            topics.append(topic)
    return tuple(topics)
