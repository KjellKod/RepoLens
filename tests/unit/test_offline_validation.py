from __future__ import annotations

import socket
from typing import NoReturn

import pytest

from repolens.data.validation import validate_artifact


def test_validation_works_with_network_disabled(
    sbom: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_socket(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("schema validation attempted network access")

    monkeypatch.setattr(socket, "socket", fail_socket)

    validate_artifact(sbom, "sbom")
