"""Bounded retry/backoff for network-class operations.

A pure, secret-free helper used to wrap the network boundaries RepoLens touches
(``gh auth token`` resolution, discover ``gh`` calls, and the hardened clone).
Transience is decided entirely by the injected ``is_transient`` predicate, so this
module never inspects tokens or stderr itself and carries no credential handling.

The decision path has no wall-clock dependence beyond the optional ``max_elapsed``
budget, and both ``sleep`` and ``monotonic`` are injectable, so callers (and tests)
get deterministic behaviour with a no-op sleeper and a fake clock.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

#: Default backoff knobs for the gh / non-timeout transient classes.
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 0.5


def retry_with_backoff(
    operation: Callable[[], T],
    *,
    is_transient: Callable[[BaseException], bool],
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    max_elapsed: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> T:
    """Run ``operation`` with bounded exponential backoff on transient failures.

    ``operation`` is called up to ``max_attempts`` times. After a transient
    exception (``is_transient(exc)`` is true) the helper sleeps
    ``base_delay * 2 ** (attempt - 1)`` and retries; any non-transient exception
    re-raises immediately. When ``max_elapsed`` is set, a retry is skipped (and the
    last exception re-raised) if the elapsed wall-clock plus the next delay would
    exceed the budget — this bounds the worst-case cost of a class whose individual
    attempts are themselves slow (e.g. clone timeouts).
    """

    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    started_at = monotonic()
    attempt = 0
    while True:
        attempt += 1
        try:
            return operation()
        except BaseException as exc:  # noqa: BLE001 - re-raised unless transient
            if attempt >= max_attempts or not is_transient(exc):
                raise
            delay = base_delay * (2 ** (attempt - 1))
            if max_elapsed is not None and (monotonic() - started_at) + delay > max_elapsed:
                raise
            sleep(delay)
