from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

from repolens.security.clone import CloneOptions, hardened_clone
from repolens.security.errors import CloneSecurityError, FetchSecurityError, ParseSecurityError
from repolens.security.http_client import HttpFetchOptions, fetch_url
from repolens.security.limits import SecurityLimits, TimeBudget, TimeBudgetExceeded
from repolens.security.parsers import parse_json_bytes
from tests.unit.security.test_http_client import FakeConnection, FakeResponse, patch_dns


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_x2_dos_time_budget_aborts() -> None:
    clock = FakeClock()
    budget = TimeBudget(now=clock, budget_seconds=300.0)

    budget.raise_if_expired()
    clock.advance(600.0)

    with pytest.raises(TimeBudgetExceeded):
        budget.raise_if_expired()


def test_fetch_body_cap_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    class LargeConnection(FakeConnection):
        def getresponse(self):
            return FakeResponse([b"abc", b"def"])

    patch_dns(monkeypatch, "93.184.216.34")
    monkeypatch.setattr("repolens.security.http_client._PinnedHTTPSConnection", LargeConnection)
    with pytest.raises(FetchSecurityError):
        fetch_url(
            "https://allowed.example/acme",
            HttpFetchOptions(
                allowed_hosts=frozenset({"allowed.example"}),
                limits=SecurityLimits(max_fetch_bytes=4),
            ),
        )


def test_fetch_timeout_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    class TimeoutConnection(FakeConnection):
        def getresponse(self):
            raise TimeoutError("slow")

    patch_dns(monkeypatch, "93.184.216.34")
    monkeypatch.setattr("repolens.security.http_client._PinnedHTTPSConnection", TimeoutConnection)
    with pytest.raises(FetchSecurityError):
        fetch_url(
            "https://allowed.example/acme",
            HttpFetchOptions(allowed_hosts=frozenset({"allowed.example"})),
        )


def test_parse_timeout_aborts_before_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(func, limits):
        raise ParseSecurityError("parse timed out")

    monkeypatch.setattr("repolens.security.parsers._run_with_timeout", timeout)
    with pytest.raises(ParseSecurityError, match="timed out"):
        parse_json_bytes(b'{"acme": true}', SecurityLimits(parse_timeout_seconds=0.01))


def test_parse_timeout_contract_blocks_worker_thread_parsing() -> None:
    errors: list[Exception] = []

    def parse_in_worker() -> None:
        try:
            parse_json_bytes(b'{"acme": true}')
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=parse_in_worker)
    worker.start()
    worker.join()

    assert errors
    assert isinstance(errors[0], ParseSecurityError)
    assert "main-thread" in str(errors[0])


def test_clone_tempdir_cleanup_runs_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(command, **kwargs):
        if command == ["git", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="git version 2.52.0\n", stderr="")
        raise subprocess.TimeoutExpired(command, timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(CloneSecurityError):
        hardened_clone(CloneOptions("https://example.invalid/acme.git", tmp_path / "dst"))
    assert not list(tmp_path.glob(".dst.clone-*"))
