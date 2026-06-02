"""Shared resource limits for security primitives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


class TimeBudgetExceeded(TimeoutError):
    """Raised when an operation exceeds its assigned budget."""


class TimeBudget:
    """Wall-clock budget using an injectable clock for deterministic tests."""

    def __init__(self, now: Callable[[], float], budget_seconds: float) -> None:
        if budget_seconds <= 0:
            raise ValueError("budget_seconds must be positive")
        self._now = now
        self._budget_seconds = budget_seconds
        self._started_at = now()

    @property
    def elapsed_seconds(self) -> float:
        return self._now() - self._started_at

    def expired(self) -> bool:
        return self.elapsed_seconds >= self._budget_seconds

    def raise_if_expired(self) -> None:
        if self.expired():
            raise TimeBudgetExceeded("operation exceeded time budget")


@dataclass(frozen=True, slots=True)
class SecurityLimits:
    """Immutable defaults for untrusted-input boundaries."""

    max_fetch_bytes: int = 2 * 1024 * 1024
    fetch_timeout_seconds: float = 5.0
    clone_timeout_seconds: float = 300.0
    max_parse_bytes: int = 5 * 1024 * 1024
    parse_timeout_seconds: float = 2.0
    max_structure_depth: int = 64
    max_structure_nodes: int = 100_000
    max_yaml_alias_tokens: int = 32
    max_archive_entries: int = 1_000
    max_archive_total_uncompressed_bytes: int = 500 * 1024 * 1024
    max_archive_entry_uncompressed_bytes: int = 100 * 1024 * 1024
    max_archive_compression_ratio: float = 100.0
    license_text_bytes: int = 32 * 1024
    readme_excerpt_bytes: int = 8 * 1024
    description_bytes: int = 512


DEFAULT_LIMITS = SecurityLimits()
