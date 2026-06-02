import socket

import pytest


@pytest.fixture(autouse=True)
def block_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise RuntimeError("live network is disabled for security tests")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    monkeypatch.setattr(socket.socket, "connect", fail_connect)
