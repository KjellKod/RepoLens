from __future__ import annotations

from pathlib import Path

import pytest

from repolens.exit_codes import InputError
from repolens.presence.scan_js_bundle import npm_package_name_from_purl, scan_js_bundle


def test_bundle_marker_matches_package_and_hash(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.js"
    bundle.write_text("require('node_modules/acme-attrib-lib/index.js')", encoding="utf-8")

    result = scan_js_bundle(bundle, ["acme-attrib-lib", "acme-missing"], target="js-bundle")

    assert "acme-attrib-lib" in result.matched
    assert "acme-missing" not in result.matched
    assert result.artifact.kind == "js-bundle"
    assert result.artifact.hash is not None
    assert result.artifact.hash.startswith("sha256:")


def test_sourcemap_marker_matches(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.js"
    bundle.write_text("minified", encoding="utf-8")
    (tmp_path / "bundle.js.map").write_text("node_modules/acme-map-lib/index.js", encoding="utf-8")

    result = scan_js_bundle(bundle, ["acme-map-lib"], target="cloudflare-worker")

    assert result.matched["acme-map-lib"] == ("node_modules/acme-map-lib/",)


def test_scoped_package_matches(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.js"
    bundle.write_text("node_modules/@acme/widget/index.js", encoding="utf-8")

    result = scan_js_bundle(bundle, ["@acme/widget"], target="js-bundle")

    assert "@acme/widget" in result.matched


def test_missing_artifact_rejected(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        scan_js_bundle(tmp_path / "missing.js", ["acme-lib"], target="js-bundle")


def test_npm_identity_comes_from_purl_only() -> None:
    assert npm_package_name_from_purl("pkg:npm/%40acme/widget@1.0.0") == "@acme/widget"
    assert npm_package_name_from_purl("pkg:pypi/acme-lib@1.0.0") is None
    assert npm_package_name_from_purl(None) is None
