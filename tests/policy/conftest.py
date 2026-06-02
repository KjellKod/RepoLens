"""Shared test fixtures for policy tests."""

import socket

import pytest


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args: object, **_kwargs: object) -> socket.socket:
        raise RuntimeError("Network access is disabled for offline policy tests.")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
