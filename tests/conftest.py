from __future__ import annotations

import socket
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def block_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("live network is disabled for security tests")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_connect)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def synthetic_fixture_root(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "synthetic"


@pytest.fixture(scope="session")
def fixture_manifest_path(synthetic_fixture_root: Path) -> Path:
    return synthetic_fixture_root / "fixture_manifest.json"
