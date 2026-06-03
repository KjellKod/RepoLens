"""GitHub credential resolution and shared gh/auth error messaging.

This module is the single home for two things both ``discover`` and ``scan`` need:

1. **Credential resolution** — :func:`resolve_clone_credential` resolves a read-only
   GitHub token from ``gh auth token`` first, then the ``GH_TOKEN`` / ``GITHUB_TOKEN``
   environment fallbacks. The token is wrapped in a :class:`CloneCredential` so it is
   never logged; this module never prints or returns the raw secret.
2. **Uniform error wording** — the four gh/auth messages from the brief, plus the
   shared rate-limit-exhaustion message, so discover and scan speak identically.

Import discipline: this module must NOT import the on-disk store (which pulls
``jsonschema``), so it stays usable under the lock-only security-canary env. It only
depends on the secret-free ``security.clone`` / ``security.retry`` primitives.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

from repolens.security.clone import CloneCredential
from repolens.security.retry import (
    DEFAULT_BASE_DELAY,
    DEFAULT_MAX_ATTEMPTS,
    retry_with_backoff,
)

#: A ``gh`` invocation seam returning ``(returncode, stdout, stderr)``. Injectable
#: so credential resolution is fully offline-testable.
GhTokenRunner = Callable[[], "tuple[int, str, str]"]


@dataclass(frozen=True)
class CloneCredentialResolution:
    """Result of scan credential resolution, including terminal miss reason."""

    credential: CloneCredential | None
    unavailable_message: str | None = None


# --- shared gh/auth messages (brief §5) ----------------------------------

GH_NOT_INSTALLED_MESSAGE = (
    "GitHub CLI (gh) not found. Install it (https://cli.github.com) and run "
    "`gh auth login`, or set GH_TOKEN."
)
GH_NOT_AUTHENTICATED_MESSAGE = (
    "GitHub CLI is not authenticated. Run `gh auth login` (or set GH_TOKEN)."
)


def private_repo_needs_auth_message(name: str) -> str:
    return f"private repo {name} needs auth: run `gh auth login` or set GH_TOKEN."


def access_denied_message(name: str) -> str:
    return f"no access to {name} with the current GitHub credential."


def rate_limited_message(retries: int) -> str:
    return f"rate-limited after {retries} retries - try again later"


# --- transient classification (shared by discover + credential resolve) ---

# Substrings that mark a retryable gh/network condition. Auth/not-authenticated
# failures are intentionally absent: those are terminal and must fall straight
# through to the env fallback (and then the clear not-authenticated message).
_GH_TRANSIENT_MARKERS = (
    "rate limit",
    "secondary rate limit",
    "connection reset",
    "could not resolve host",
    "couldn't resolve host",
    "timed out",
    "temporary failure",
    "failed to connect",
)
_GH_TRANSIENT_HTTP_STATUS_RE = re.compile(
    r"\b(?:http(?:/\d(?:\.\d)?)?|status(?: code)?|returned error|error)"
    r"\s*[:=]?\s*(?:429|500|502|503|504)\b"
)


def is_gh_transient(returncode: int, stderr: str) -> bool:
    """Return whether a raw ``gh`` failure (returncode + stderr) is retryable.

    Classifies on the RAW result, before any caller rewrites/redacts the stderr —
    a generic rewrite would lose the 429/secondary-rate-limit signal entirely.
    """

    if returncode == 0:
        return False
    text = (stderr or "").casefold()
    return _GH_TRANSIENT_HTTP_STATUS_RE.search(text) is not None or any(
        marker in text for marker in _GH_TRANSIENT_MARKERS
    )


class GhTransientError(Exception):
    """Raised at the raw ``gh`` boundary for a retryable transient failure.

    Exception-based so :func:`repolens.security.retry.retry_with_backoff` (which
    keys off raised exceptions) can drive the retry; carries no secret.
    """


def is_gh_transient_error(exc: BaseException) -> bool:
    return isinstance(exc, GhTransientError)


# --- credential resolution ------------------------------------------------


def _subprocess_gh_token_runner() -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except FileNotFoundError:
        # gh not installed: terminal for resolution, fall through to env tokens.
        return (127, "", "gh not found")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (124, "", f"gh auth token failed: {exc.__class__.__name__}")
    return (completed.returncode, completed.stdout, completed.stderr)


def resolve_clone_credential(
    *,
    gh_runner: GhTokenRunner | None = None,
    env: dict[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> CloneCredential | None:
    """Resolve a read-only GitHub credential, or ``None`` if none is available.

    Order: ``gh auth token`` (retried on transients, classified on the raw result),
    then ``GH_TOKEN``, then ``GITHUB_TOKEN``. A non-transient ``gh`` failure (not
    installed / not authenticated) is not retried — it simply falls through to the
    env fallback. The raw token is never logged; only a :class:`CloneCredential`
    (with a redacted repr) is returned.
    """

    return resolve_clone_credential_result(
        gh_runner=gh_runner,
        env=env,
        sleep=sleep,
        max_attempts=max_attempts,
    ).credential


def resolve_clone_credential_result(
    *,
    gh_runner: GhTokenRunner | None = None,
    env: dict[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> CloneCredentialResolution:
    """Resolve a clone credential plus a terminal miss reason for scan UX."""

    runner = gh_runner or _subprocess_gh_token_runner
    environ = os.environ if env is None else env

    gh_resolution = _resolve_gh_token(runner, sleep=sleep, max_attempts=max_attempts)
    token = gh_resolution.token
    if not token:
        token = environ.get("GH_TOKEN") or environ.get("GITHUB_TOKEN") or ""
    token = token.strip()
    if token:
        return CloneCredentialResolution(CloneCredential(token))
    return CloneCredentialResolution(None, gh_resolution.unavailable_message)


@dataclass(frozen=True)
class _GhTokenResolution:
    token: str = ""
    unavailable_message: str | None = None


def _resolve_gh_token(
    runner: GhTokenRunner,
    *,
    sleep: Callable[[float], None],
    max_attempts: int,
) -> _GhTokenResolution:
    def operation() -> _GhTokenResolution:
        returncode, stdout, stderr = runner()
        if returncode == 0:
            return _GhTokenResolution(token=stdout.strip())
        if is_gh_transient(returncode, stderr):
            raise GhTransientError("gh auth token transient failure")
        # Non-transient: fall through to env, carrying a precise miss reason
        # when the caller needs to explain a private-repo scan failure.
        text = (stderr or "").casefold()
        if returncode == 127 or "gh not found" in text:
            return _GhTokenResolution(unavailable_message=GH_NOT_INSTALLED_MESSAGE)
        if _is_gh_not_authenticated(stderr):
            return _GhTokenResolution(unavailable_message=GH_NOT_AUTHENTICATED_MESSAGE)
        return _GhTokenResolution()

    try:
        return retry_with_backoff(
            operation,
            is_transient=is_gh_transient_error,
            max_attempts=max_attempts,
            base_delay=DEFAULT_BASE_DELAY,
            sleep=sleep,
        )
    except GhTransientError:
        # Exhausted retries on a transient gh failure: still try env tokens.
        return _GhTokenResolution(unavailable_message=rate_limited_message(max_attempts))


def _is_gh_not_authenticated(stderr: str) -> bool:
    text = (stderr or "").casefold()
    return any(
        marker in text
        for marker in (
            "not logged into",
            "not authenticated",
            "authentication required",
            "gh auth login",
        )
    )
