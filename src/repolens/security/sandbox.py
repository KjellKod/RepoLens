"""Sandbox command specifications for execution-bearing tool paths."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from repolens.security.limits import DEFAULT_LIMITS

SAFE_ENV_KEYS = ("HOME", "PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "USERPROFILE")
TOKEN_ENV_FRAGMENTS = ("TOKEN", "AUTH", "SECRET", "PASSWORD", "CREDENTIAL", "KEY")
METADATA_IP = "169.254.169.254"


class SandboxUnavailable(RuntimeError):
    """Raised when no configured sandbox backend can execute a spec."""


class SandboxExecutionError(RuntimeError):
    """Raised when a sandboxed command fails."""


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Network policy carried by sandbox specs."""

    allowed_hosts: frozenset[str] = frozenset()
    block_private: bool = True
    block_link_local: bool = True
    block_metadata: bool = True
    blocked_hosts: frozenset[str] = frozenset({METADATA_IP})


@dataclass(frozen=True, slots=True)
class ReadOnlyMount:
    """A host path mounted read-only inside the sandbox."""

    host_path: Path
    sandbox_path: str


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    """A complete command request for a sandbox backend."""

    argv: tuple[str, ...]
    read_only_mounts: tuple[ReadOnlyMount, ...]
    workdir: str
    env: dict[str, str]
    timeout_seconds: float
    egress: EgressPolicy


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """Minimal sandbox process result."""

    returncode: int
    stdout: str
    stderr: str


SandboxRunner = Callable[[SandboxSpec], SandboxResult]


def scrubbed_tool_env(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return a small token-free environment for tool subprocesses."""

    env_source = os.environ if source is None else source
    safe: dict[str, str] = {}
    for key in SAFE_ENV_KEYS:
        value = env_source.get(key)
        if value is not None:
            safe[key] = value
    return {
        key: value
        for key, value in safe.items()
        if not any(fragment in key.upper() for fragment in TOKEN_ENV_FRAGMENTS)
    }


def build_native_tool_sandbox_spec(
    argv: Sequence[str],
    *,
    source_root: Path,
    timeout_seconds: float = DEFAULT_LIMITS.clone_timeout_seconds,
    allowed_hosts: frozenset[str] = frozenset(),
    env_source: dict[str, str] | None = None,
) -> SandboxSpec:
    """Build a sandbox spec for mobile native tool execution."""

    resolved_source = source_root.resolve()
    return SandboxSpec(
        argv=tuple(argv),
        read_only_mounts=(ReadOnlyMount(resolved_source, "/workspace"),),
        workdir="/workspace",
        env=scrubbed_tool_env(env_source),
        timeout_seconds=timeout_seconds,
        egress=EgressPolicy(allowed_hosts=allowed_hosts),
    )


def unavailable_runner(spec: SandboxSpec) -> SandboxResult:
    """Default runner: fail closed instead of executing without a sandbox."""

    del spec
    raise SandboxUnavailable("sandbox backend is not configured")
