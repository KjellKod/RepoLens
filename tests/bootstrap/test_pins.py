"""Tests for the pins manifest loader/validator (AC #1, #6)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from repolens.bootstrap.errors import InvalidPin
from repolens.bootstrap.pins import (
    DEFAULT_PINS_PATH,
    current_platform,
    load_pins,
    load_pins_data,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _valid_data() -> dict:
    return {
        "schema": "repolens.pins/v1",
        "base_image": {"ref": "registry/img@sha256:" + "a" * 64},
        "tools": {
            "syft": {
                "version": "1.18.1",
                "platforms": {"linux/amd64": {"artifact": "s.tar.gz", "sha256": "a" * 64}},
                "signature": {
                    "mechanism": "cosign-keyless",
                    "checksums_file": "c.txt",
                    "checksums_sig": "c.txt.sig",
                    "checksums_cert": "c.txt.pem",
                    "cert_identity_regex": ".*",
                    "cert_oidc_issuer": "https://issuer",
                },
            },
            "cosign": {
                "version": "2.4.1",
                "platforms": {"linux/amd64": {"artifact": "cosign", "sha256": "b" * 64}},
            },
            "scancode": {"version": "32.3.1", "requirements": "r.txt"},
            "git": {
                "version": "2.47.1",
                "platforms": {"linux/amd64": {"artifact": "g.tar.gz", "sha256": "c" * 64}},
            },
            "gh": {
                "version": "2.63.2",
                "platforms": {"linux/amd64": {"artifact": "gh.tar.gz", "sha256": "d" * 64}},
            },
        },
    }


def test_loads_real_manifest():
    pins = load_pins(DEFAULT_PINS_PATH)
    assert pins.schema == "repolens.pins/v1"
    for name in ("syft", "scancode", "git", "gh", "cosign"):
        assert name in pins.tools
    assert "@sha256:" in pins.base_image
    assert pins.tool("syft").signature is not None


def test_valid_in_memory_data_loads():
    pins = load_pins_data(_valid_data())
    assert pins.tool("syft").version == "1.18.1"


def test_rejects_latest():
    data = _valid_data()
    data["tools"]["syft"]["version"] = "latest"
    with pytest.raises(InvalidPin, match="floating/unpinned"):
        load_pins_data(data)


@pytest.mark.parametrize("bad", ["^1.0.0", "~1.2", ">=1.0", "*", ""])
def test_rejects_floating_version(bad):
    data = _valid_data()
    data["tools"]["git"]["version"] = bad
    with pytest.raises(InvalidPin):
        load_pins_data(data)


def test_requires_base_image_digest():
    data = _valid_data()
    data["base_image"]["ref"] = "registry/img:latest"
    with pytest.raises(InvalidPin):
        load_pins_data(data)


def test_rejects_base_image_without_digest():
    data = _valid_data()
    data["base_image"]["ref"] = "registry/img:1.2.3"
    with pytest.raises(InvalidPin, match="@sha256:"):
        load_pins_data(data)


def test_rejects_bad_sha256():
    data = _valid_data()
    data["tools"]["syft"]["platforms"]["linux/amd64"]["sha256"] = "nothex"
    with pytest.raises(InvalidPin, match="sha256"):
        load_pins_data(data)


def test_rejects_missing_required_tool():
    data = _valid_data()
    del data["tools"]["cosign"]
    with pytest.raises(InvalidPin, match="cosign"):
        load_pins_data(data)


def test_rejects_syft_without_signature():
    data = _valid_data()
    del data["tools"]["syft"]["signature"]
    with pytest.raises(InvalidPin, match="signature"):
        load_pins_data(data)


def test_latest_fixture_file_rejected():
    with pytest.raises(InvalidPin):
        load_pins(FIXTURES / "pins.latest.bad.toml")


def test_resolves_current_platform_artifact():
    data = _valid_data()
    plat = current_platform()
    # Inject an artifact for the host platform so resolution succeeds offline.
    data["tools"]["syft"]["platforms"][plat] = {"artifact": "host.tar.gz", "sha256": "e" * 64}
    pins = load_pins_data(data)
    art = pins.tool("syft").artifact_for(plat)
    assert art.artifact == "host.tar.gz"


def test_unknown_platform_raises():
    pins = load_pins_data(_valid_data())
    with pytest.raises(InvalidPin, match="no artifact pinned"):
        pins.tool("syft").artifact_for("solaris/sparc")


def test_unsupported_schema_rejected():
    data = copy.deepcopy(_valid_data())
    data["schema"] = "repolens.pins/v999"
    with pytest.raises(InvalidPin, match="schema"):
        load_pins_data(data)
