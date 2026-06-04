"""Hardened git clone helpers for untrusted repositories."""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from repolens.security.errors import (
    CloneAccessDenied,
    CloneAuthRequired,
    CloneRateLimited,
    CloneSecurityError,
    CloneTransient,
)
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.redaction import redact_tokens

MIN_GIT_VERSION = (2, 45, 0)
_GIT_VERSION_RE = re.compile(r"git version (\d+)\.(\d+)\.(\d+)")
_SAFE_ENV_KEYS = {
    "HOME",
    "PATH",
    "SYSTEMROOT",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
}
_HARDENING_CONFIG = (
    ("protocol.file.allow", "never"),
    ("core.hooksPath", "/dev/null"),
    ("core.symlinks", "false"),
)
_CLONE_FLAGS = (
    "--depth=1",
    "--no-tags",
    "--single-branch",
    "--no-recurse-submodules",
)


#: git extraheader config key that scopes the injected credential to github.com.
_GITHUB_EXTRAHEADER_KEY = "http.https://github.com/.extraheader"


@dataclass(frozen=True)
class CloneCredential:
    """A read-only GitHub credential injected into the clone subprocess only.

    The secret is never placed in argv, never persisted to a git config file, and
    never logged: ``repr``/``str`` are overridden so the token (and its base64
    header form) cannot leak through a stack trace, an f-string, or
    ``CloneOptions``' repr. The credential is injected via process-scoped
    ``GIT_CONFIG_*`` env entries (honoured since git 2.31) so it lives only inside
    the hook-disabled fetch subprocess and is gone when ``hardened_clone`` returns.
    """

    secret: str = field(repr=False)

    def __repr__(self) -> str:
        return "CloneCredential(<redacted>)"

    __str__ = __repr__

    def extraheader_env(self) -> dict[str, str]:
        """Return the ``GIT_CONFIG_*`` entries injecting the Authorization header.

        Mirrors GitHub Actions' checkout: ``Basic base64("x-access-token:" + token)``
        attached only to ``https://github.com/`` requests.
        """

        encoded = base64.b64encode(f"x-access-token:{self.secret}".encode()).decode("ascii")
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": _GITHUB_EXTRAHEADER_KEY,
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {encoded}",
        }


@dataclass(frozen=True)
class CloneInvocation:
    """Arguments and environment for a hardened clone operation."""

    argv: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CloneOptions:
    """Options for a hardened clone operation."""

    remote_url: str
    destination: Path
    branch: str | None = None
    limits: SecurityLimits = DEFAULT_LIMITS
    git_executable: str = "git"
    min_git_version: tuple[int, int, int] = MIN_GIT_VERSION
    #: Optional read-only credential injected into the fetch subprocess only.
    #: ``CloneCredential`` guards its own repr, so ``CloneOptions`` repr is safe.
    credential: CloneCredential | None = None


def build_hardened_clone_command(remote_url: str, destination: Path | str) -> CloneInvocation:
    """Return a hardened git clone invocation without executing it."""

    _validate_https_remote(remote_url)
    command = _build_clone_command(
        CloneOptions(remote_url=remote_url, destination=Path(destination)),
        Path(destination),
    )
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return CloneInvocation(argv=tuple(command), env=env)


def hardened_clone(options: CloneOptions) -> Path:
    """Clone a repository with mandatory git hardening and cleanup."""

    _reject_file_remote(options.remote_url)
    destination = Path(options.destination)
    if destination.exists():
        raise CloneSecurityError(f"destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    _assert_git_version(
        options.git_executable,
        minimum=options.min_git_version,
        timeout=options.limits.fetch_timeout_seconds,
    )

    temp_parent = destination.parent
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{destination.name}.clone-", dir=temp_parent))
    clone_path = temp_dir / "repo"
    try:
        command = _build_clone_command(options, clone_path)
        # The credential (when present) is injected ONLY here, into the child env
        # of the hook-disabled fetch subprocess. _assert_git_version and
        # _validate_gitmodules deliberately stay credential-free.
        completed = subprocess.run(
            command,
            env=_scrubbed_git_env(credential=options.credential),
            capture_output=True,
            text=True,
            timeout=options.limits.clone_timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            message = _safe_git_error(completed.stderr)
            raise classify_git_failure(completed.returncode, completed.stderr)(message)

        _validate_gitmodules(clone_path / ".gitmodules", git_executable=options.git_executable)
        shutil.move(str(clone_path), str(destination))
        return destination
    except subprocess.TimeoutExpired as exc:
        # A hung/slow fetch is a network-class condition: surface it as transient
        # so the runner's bounded retry + max_elapsed budget engage (AC#5).
        raise CloneTransient("git clone timed out") from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _build_clone_command(options: CloneOptions, clone_path: Path) -> list[str]:
    command = [options.git_executable]
    for key, value in _HARDENING_CONFIG:
        command.extend(["-c", f"{key}={value}"])
    command.append("clone")
    command.extend(_CLONE_FLAGS)
    if options.branch:
        command.extend(["--branch", options.branch])
    command.extend(["--", options.remote_url, str(clone_path)])
    return command


def _scrubbed_git_env(
    source: dict[str, str] | None = None,
    *,
    credential: CloneCredential | None = None,
) -> dict[str, str]:
    source = os.environ if source is None else source
    clean = {key: value for key, value in source.items() if key in _SAFE_ENV_KEYS}
    clean.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
        }
    )
    if credential is not None:
        # Process-scoped header injection: GIT_CONFIG_COUNT becomes 1 and the
        # extraheader entry attaches the Authorization header to github.com only.
        # Nothing is written to any git config file.
        clean.update(credential.extraheader_env())
    return clean


# Ordered stderr-substring classifiers. Auth/access are evaluated BEFORE
# rate-limit/transient so an ambiguous "403 ... rate limit" stays non-retryable
# (a 403 is an access decision, never a transient condition).
_AUTH_REQUIRED_MARKERS = (
    "could not read username",
    "authentication failed",
    "terminal prompts disabled",
    "could not read password",
)
_ACCESS_DENIED_MARKERS = (
    "permission denied",
    "access denied",
    "repository not found",
)
_RATE_LIMITED_MARKERS = (
    "rate limit",
    "secondary rate limit",
    "you have exceeded a secondary rate limit",
)
_TRANSIENT_MARKERS = (
    "connection reset",
    "could not resolve host",
    "couldn't resolve host",
    "connection timed out",
    "timed out",
    "operation timed out",
    "temporary failure",
    "failed to connect",
)
_HTTP_STATUS_RE_TEMPLATE = (
    r"\b(?:http(?:/\d(?:\.\d)?)?|status(?: code)?|returned error|error)"
    r"\s*[:=]?\s*(?:{codes})\b"
)


def _has_http_status(text: str, *codes: int) -> bool:
    alternatives = "|".join(str(code) for code in codes)
    return re.search(_HTTP_STATUS_RE_TEMPLATE.format(codes=alternatives), text) is not None


def classify_git_failure(returncode: int, stderr: str) -> type[CloneSecurityError]:
    """Map a failed clone's raw stderr onto the right ``CloneSecurityError`` subclass.

    Precedence is deliberate: auth/access markers win over rate-limit/transient so
    an authentication or 403 failure is never misrouted into the retryable classes
    (``CloneAuthRequired``/``CloneAccessDenied`` must never be retried). Anything
    unrecognised stays a generic ``CloneSecurityError``.
    """

    del returncode  # classification is on stderr text; returncode kept for symmetry
    text = (stderr or "").casefold()
    if any(marker in text for marker in _AUTH_REQUIRED_MARKERS):
        return CloneAuthRequired
    if _has_http_status(text, 403, 404) or any(marker in text for marker in _ACCESS_DENIED_MARKERS):
        return CloneAccessDenied
    if _has_http_status(text, 429) or any(marker in text for marker in _RATE_LIMITED_MARKERS):
        return CloneRateLimited
    if _has_http_status(text, 500, 502, 503, 504) or any(
        marker in text for marker in _TRANSIENT_MARKERS
    ):
        return CloneTransient
    return CloneSecurityError


def _assert_git_version(
    git_executable: str,
    *,
    minimum: tuple[int, int, int] = MIN_GIT_VERSION,
    timeout: float = 5.0,
) -> None:
    try:
        completed = subprocess.run(
            [git_executable, "--version"],
            env=_scrubbed_git_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CloneSecurityError("unable to check git version") from exc
    if completed.returncode != 0:
        raise CloneSecurityError("unable to check git version")
    match = _GIT_VERSION_RE.search(completed.stdout.strip())
    if not match:
        raise CloneSecurityError("unable to parse git version")
    version = tuple(int(part) for part in match.groups())
    if version < minimum:
        required = ".".join(str(part) for part in minimum)
        found = ".".join(str(part) for part in version)
        raise CloneSecurityError(f"git version {found} is below required {required}")


def _validate_https_remote(remote_url: str) -> None:
    parsed = urlparse(remote_url)
    if parsed.scheme != "https":
        raise ValueError("clone remote must use https")
    if not parsed.hostname:
        raise ValueError("clone remote must include a host")
    if parsed.username or parsed.password:
        raise ValueError("clone remote must not embed credentials")


def _reject_file_remote(remote_url: str) -> None:
    parsed = urlparse(remote_url)
    if parsed.scheme.lower() == "file":
        raise CloneSecurityError("file:// remotes are blocked")


def _validate_gitmodules(path: Path, *, git_executable: str = "git") -> None:
    if not path.exists():
        return
    try:
        completed = subprocess.run(
            [
                git_executable,
                "config",
                "--file",
                str(path),
                "--get-regexp",
                r"^submodule\..*\.url$",
            ],
            env=_scrubbed_git_env(),
            capture_output=True,
            text=True,
            timeout=DEFAULT_LIMITS.fetch_timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CloneSecurityError("invalid .gitmodules") from exc
    if completed.returncode not in {0, 1}:
        raise CloneSecurityError("invalid .gitmodules")
    for line in completed.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        url = parts[1].strip()
        if urlparse(url).scheme.lower() == "file":
            raise CloneSecurityError("file:// submodule URLs are blocked")


def _safe_git_error(stderr: str) -> str:
    text = (stderr or "git clone failed").strip().splitlines()
    return redact_tokens(text[-1])[:500] if text else "git clone failed"
