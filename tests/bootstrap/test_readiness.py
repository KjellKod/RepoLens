from __future__ import annotations

from pathlib import Path

import pytest

from repolens.bootstrap import readiness
from repolens.bootstrap.cache import SyftCacheResult
from repolens.bootstrap.readiness import (
    ToolPreflightOptions,
    ToolStatus,
    check_required_tools,
    ensure_required_tools,
)
from repolens.exit_codes import InputError


def test_syft_present_status_uses_verified_cache_without_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    syft = tmp_path / "syft"
    monkeypatch.setattr(readiness, "load_syft_pin", lambda: object())
    monkeypatch.setattr(readiness, "cached_syft_path", lambda _pin: syft)

    status = check_required_tools(("syft",), _options(tmp_path))[0]

    assert status.status is ToolStatus.PRESENT
    assert status.path == syft


def test_syft_offline_missing_is_unprovisionable_without_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(readiness, "load_syft_pin", lambda: object())
    monkeypatch.setattr(readiness, "cached_syft_path", lambda _pin: None)

    def fail_fetch(**_kwargs: object) -> object:
        raise AssertionError("offline missing readiness must not acquire Syft")

    monkeypatch.setattr(readiness, "ensure_syft_cached", fail_fetch)
    options = _options(tmp_path, offline=True)

    status = check_required_tools(("syft",), options)[0]

    assert status.status is ToolStatus.MISSING_UNPROVISIONABLE
    with pytest.raises(InputError, match="offline mode"):
        ensure_required_tools(("syft",), options)


def test_scancode_present_status_uses_resolve_scancode_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scancode = tmp_path / "tools" / "scancode"
    monkeypatch.setattr(readiness, "resolve_scancode_path", lambda _work_root: scancode)

    status = check_required_tools(("scancode",), _options(tmp_path))[0]

    assert status.status is ToolStatus.PRESENT
    assert status.path == scancode


def test_scancode_missing_online_auto_is_provisionable_then_ready(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scancode = tmp_path / "tools" / "scancode"
    calls: list[str] = []

    def missing(_work_root: Path) -> Path:
        raise InputError("tool_versions.json not found")

    def provision(work_root: Path) -> Path:
        calls.append(str(work_root))
        return scancode

    monkeypatch.setattr(readiness, "resolve_scancode_path", missing)
    monkeypatch.setattr(readiness, "provision_scancode_work_root", provision)
    options = _options(tmp_path)

    status = check_required_tools(("scancode",), options)[0]
    paths = ensure_required_tools(("scancode",), options)

    assert status.status is ToolStatus.PROVISIONABLE
    assert paths["scancode"] == scancode
    assert calls == [str(tmp_path)]


def test_scancode_missing_offline_is_unprovisionable_and_does_not_provision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        readiness,
        "resolve_scancode_path",
        lambda _work_root: (_ for _ in ()).throw(InputError("tool_versions.json not found")),
    )
    monkeypatch.setattr(
        readiness,
        "provision_scancode_work_root",
        lambda _work_root: (_ for _ in ()).throw(
            AssertionError("offline readiness must not provision")
        ),
    )
    options = _options(tmp_path, offline=True)

    status = check_required_tools(("scancode",), options)[0]

    assert status.status is ToolStatus.MISSING_UNPROVISIONABLE
    with pytest.raises(InputError, match="ScanCode is required"):
        ensure_required_tools(("scancode",), options)


def test_scancode_corrupt_present_dir_is_reprovisioned_online(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scancode = tmp_path / "tools" / "scancode"
    monkeypatch.setattr(
        readiness,
        "resolve_scancode_path",
        lambda _work_root: (_ for _ in ()).throw(InputError("wrapper does not match proof")),
    )
    monkeypatch.setattr(readiness, "provision_scancode_work_root", lambda _work_root: scancode)

    paths = ensure_required_tools(("scancode",), _options(tmp_path))

    assert paths["scancode"] == scancode


def test_syft_online_missing_provisions_through_verified_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    syft = tmp_path / "syft"
    pin = object()
    monkeypatch.setattr(readiness, "load_syft_pin", lambda: pin)
    monkeypatch.setattr(readiness, "cached_syft_path", lambda _pin: None)

    def ensure(**kwargs: object) -> SyftCacheResult:
        assert kwargs["offline"] is False
        return SyftCacheResult(path=syft, pin=pin, acquired=True)

    monkeypatch.setattr(readiness, "ensure_syft_cached", ensure)

    assert ensure_required_tools(("syft",), _options(tmp_path))["syft"] == syft


def _options(
    work_root: Path,
    *,
    offline: bool = False,
    auto_bootstrap: bool = True,
) -> ToolPreflightOptions:
    return ToolPreflightOptions(
        work_root=work_root,
        offline=offline,
        auto_bootstrap=auto_bootstrap,
    )
