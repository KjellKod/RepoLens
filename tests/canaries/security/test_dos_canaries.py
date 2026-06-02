import pytest

from repolens.security.limits import TimeBudget, TimeBudgetExceeded


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_x2_dos_time_budget_aborts() -> None:
    clock = FakeClock()
    budget = TimeBudget(now=clock, budget_seconds=300.0)

    budget.raise_if_expired()
    clock.advance(600.0)

    with pytest.raises(TimeBudgetExceeded):
        budget.raise_if_expired()
