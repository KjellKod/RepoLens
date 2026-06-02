"""``gh repo list`` orchestration for discovery."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from repolens.data.errors import LimitExceeded
from repolens.data.limits import MAX_JSON_DEPTH, scan_depth
from repolens.exit_codes import InputError
from repolens.security.redaction import redact_tokens

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


@dataclass(frozen=True)
class GhRunResult:
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[[Sequence[str], float], GhRunResult]


def list_repositories(
    owner: str,
    *,
    limit: int = DEFAULT_GH_LIMIT,
    runner: GhRunner | None = None,
    timeout_seconds: float = DEFAULT_GH_TIMEOUT_SECONDS,
    stdout_max_bytes: int = DEFAULT_GH_STDOUT_MAX_BYTES,
) -> tuple[GhRepository, ...]:
    """Return repositories under ``owner`` by invoking ``gh repo list``."""

    normalized_owner = validate_owner(owner)
    if limit < 1 or limit > MAX_GH_LIMIT:
        raise InputError(f"discover --limit must be between 1 and {MAX_GH_LIMIT}")

    command = build_repo_list_command(normalized_owner, limit)
    execute = runner or subprocess_gh_runner
    try:
        result = execute(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise InputError("gh repo list timed out") from exc
    except OSError as exc:
        raise InputError("gh repo list could not be started") from exc

    stdout = result.stdout.encode("utf-8", errors="replace")
    if len(stdout) > stdout_max_bytes:
        raise LimitExceeded(f"gh repo list output exceeds {stdout_max_bytes} bytes")
    if result.returncode != 0:
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


def _parse_repository(item: object, owner: str) -> GhRepository:
    if not isinstance(item, dict):
        raise InputError("gh repo list entries must be objects")

    name = _required_text(item, "name")
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


def _required_text(item: dict[object, object], key: str) -> str:
    value = _text(item.get(key))
    if not value:
        raise InputError(f"gh repo list entry missing {key}")
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
