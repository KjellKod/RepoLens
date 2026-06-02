"""Central exit-code contract for the CLI."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    FINDINGS_OPEN = 1
    USAGE_OR_INPUT_ERROR = 2


class RepoLensError(Exception):
    """Base exception for expected CLI failures."""


class InputError(RepoLensError):
    """Raised when CLI input or local config is invalid."""


class InternalError(RepoLensError):
    """Raised for controlled internal failures that should map to exit 1."""
