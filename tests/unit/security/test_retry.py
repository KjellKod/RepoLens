from __future__ import annotations

import pytest

from repolens.security.retry import retry_with_backoff


class _Transient(Exception):
    pass


class _Fatal(Exception):
    pass


def _always_transient(exc: BaseException) -> bool:
    return isinstance(exc, _Transient)


def test_retries_transient_then_succeeds() -> None:
    calls = {"n": 0}
    slept: list[float] = []

    def operation() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise _Transient("boom")
        return "ok"

    result = retry_with_backoff(
        operation,
        is_transient=_always_transient,
        max_attempts=5,
        base_delay=0.5,
        sleep=slept.append,
    )

    assert result == "ok"
    assert calls["n"] == 3
    # Growing exponential delays, no real waiting.
    assert slept == [0.5, 1.0]


def test_reraises_after_max_attempts() -> None:
    calls = {"n": 0}

    def operation() -> None:
        calls["n"] += 1
        raise _Transient("still failing")

    with pytest.raises(_Transient):
        retry_with_backoff(
            operation,
            is_transient=_always_transient,
            max_attempts=3,
            sleep=lambda _delay: None,
        )

    assert calls["n"] == 3


def test_non_transient_is_not_retried() -> None:
    calls = {"n": 0}

    def operation() -> None:
        calls["n"] += 1
        raise _Fatal("nope")

    with pytest.raises(_Fatal):
        retry_with_backoff(
            operation,
            is_transient=_always_transient,
            max_attempts=5,
            sleep=lambda _delay: None,
        )

    assert calls["n"] == 1


def test_max_elapsed_budget_stops_retries_early() -> None:
    calls = {"n": 0}
    clock = {"t": 0.0}

    def fake_monotonic() -> float:
        return clock["t"]

    def operation() -> None:
        calls["n"] += 1
        # Each attempt "takes" 1.0s of wall clock.
        clock["t"] += 1.0
        raise _Transient("slow")

    # Budget of 1.4s: after the first attempt (elapsed 1.0) the next delay (0.5)
    # would push elapsed to 1.5 > 1.4, so the retry is skipped and we fail fast.
    with pytest.raises(_Transient):
        retry_with_backoff(
            operation,
            is_transient=_always_transient,
            max_attempts=5,
            base_delay=0.5,
            sleep=lambda _delay: None,
            max_elapsed=1.4,
            monotonic=fake_monotonic,
        )

    assert calls["n"] == 1
