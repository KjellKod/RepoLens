"""Tests for the shared Syft cache ensure path."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import MagicMock

import pytest

from repolens.bootstrap.cache import (
    _read_pinned_response,
    cached_syft_path,
    ensure_syft_cached,
    load_syft_pin,
    syft_cache_path,
)
from repolens.bootstrap.errors import (
    ChecksumMismatch,
    IntegrityError,
    SignatureVerificationError,
    UsageError,
)

from .conftest import PLATFORM, SYFT_BINARY_BYTES
from .test_orchestrate import _write_test_pins


def test_cache_miss_fetches_verifies_and_writes_proof(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path
) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)
    make_exe = MagicMock()

    result = ensure_syft_cached(
        pins_path=pins_path,
        cache_home=tmp_path / "cache",
        acquire=acquire_factory(),
        cosign_runner=accepting_cosign_runner,
        make_executable=make_exe,
        platform_key=PLATFORM,
    )

    assert result.acquired is True
    assert result.path == syft_cache_path(result.pin, cache_home=tmp_path / "cache")
    assert result.path.read_bytes() == SYFT_BINARY_BYTES
    proof = json.loads((result.path.parent / "syft.proof.json").read_text(encoding="utf-8"))
    assert proof["version"] == result.pin.version
    assert proof["artifact_sha256"] == result.pin.artifact_sha256
    assert proof["binary_sha256"] != result.pin.artifact_sha256


def test_cache_hit_uses_proof_without_fetch(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path
) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)
    first = ensure_syft_cached(
        pins_path=pins_path,
        cache_home=tmp_path / "cache",
        acquire=acquire_factory(),
        cosign_runner=accepting_cosign_runner,
        platform_key=PLATFORM,
    )

    second = ensure_syft_cached(
        pins_path=pins_path,
        cache_home=tmp_path / "cache",
        acquire=lambda name: (_ for _ in ()).throw(AssertionError(f"fetch {name}")),
        cosign_runner=lambda argv: 0,
        platform_key=PLATFORM,
    )

    assert second.acquired is False
    assert second.path == first.path


def test_offline_empty_cache_fails_without_fetch(test_pins, tmp_path) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)

    with pytest.raises(UsageError, match="verified shared cache"):
        ensure_syft_cached(
            pins_path=pins_path,
            cache_home=tmp_path / "cache",
            acquire=lambda name: (_ for _ in ()).throw(AssertionError(f"fetch {name}")),
            cosign_runner=lambda argv: 0,
            platform_key=PLATFORM,
            offline=True,
        )


def test_tampered_syft_fails_before_cache_write(
    test_pins, acquire_factory, syft_tampered_bytes, accepting_cosign_runner, tmp_path
) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)
    pin = load_syft_pin(pins_path, platform_key=PLATFORM)

    with pytest.raises(ChecksumMismatch):
        ensure_syft_cached(
            pins_path=pins_path,
            cache_home=tmp_path / "cache",
            acquire=acquire_factory(syft_override=syft_tampered_bytes),
            cosign_runner=accepting_cosign_runner,
            platform_key=PLATFORM,
        )

    assert not syft_cache_path(pin, cache_home=tmp_path / "cache").exists()


def test_signature_failure_fails_before_cache_write(
    test_pins, acquire_factory, rejecting_cosign_runner, tmp_path
) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)
    pin = load_syft_pin(pins_path, platform_key=PLATFORM)

    with pytest.raises(SignatureVerificationError):
        ensure_syft_cached(
            pins_path=pins_path,
            cache_home=tmp_path / "cache",
            acquire=acquire_factory(),
            cosign_runner=rejecting_cosign_runner,
            platform_key=PLATFORM,
        )

    assert not syft_cache_path(pin, cache_home=tmp_path / "cache").exists()


def test_cache_proof_rejects_modified_binary(
    test_pins, acquire_factory, accepting_cosign_runner, tmp_path
) -> None:
    pins_path = _write_test_pins(tmp_path, test_pins)
    result = ensure_syft_cached(
        pins_path=pins_path,
        cache_home=tmp_path / "cache",
        acquire=acquire_factory(),
        cosign_runner=accepting_cosign_runner,
        platform_key=PLATFORM,
    )

    result.path.write_bytes(b"modified")

    assert cached_syft_path(result.pin, cache_home=tmp_path / "cache") is None


def test_pinned_artifact_read_is_capped() -> None:
    response = BytesIO(b"abcde")

    with pytest.raises(IntegrityError, match="too large"):
        _read_pinned_response(response, "syft.tar.gz", max_bytes=4)
