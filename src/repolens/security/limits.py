"""Deterministic time-budget helpers."""

from __future__ import annotations

from collections.abc import Callable


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
