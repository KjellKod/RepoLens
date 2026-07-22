"""Helpers for loading the synthetic fixture contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.presence.models import Presence

DEFAULT_FIXTURE_MANIFEST = Path("tests/fixtures/synthetic/fixture_manifest.json")


def load_fixture_manifest(path: str | Path = DEFAULT_FIXTURE_MANIFEST) -> dict[str, Any]:
    """Load a fixture manifest from a caller-provided path."""
    manifest_path = Path(path)
    with manifest_path.open(encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)

    if not isinstance(manifest, dict):
        msg = f"{manifest_path} must contain a JSON object"
        raise ValueError(msg)
    return manifest


def synthetic_fixture_root(manifest_path: str | Path = DEFAULT_FIXTURE_MANIFEST) -> Path:
    """Return the directory containing the synthetic fixture manifest."""
    return Path(manifest_path).resolve().parent


def build_release_demo_work_root(root: Path) -> Path:
    """Create an offline release-pilot fixture work root and bundle artifact."""

    work_root = Path(root)
    repo_ref = "acme-sketch2md-demo"
    records = [
        _release_record("acme-attrib-lib", "CC-BY-4.0", repo_ref),
        _release_record("acme-mit-lib", "MIT", repo_ref),
        _release_record("acme-choice-lib", "(AFL-2.1 OR BSD-3-Clause)", repo_ref),
        _release_record(
            "acme-native-optional",
            "LGPL-3.0-only",
            repo_ref,
            presence=Presence(
                install_state="lockfile_only",
                delivery_state="not_scanned",
                relation="optional",
                source="syft",
            ).to_dict(),
        ),
    ]
    store.write_resolved(work_root, repo_ref, records)
    bundle = work_root / "dist" / "worker.js"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.write_text(
        "\n".join(
            (
                "/* offline release pilot bundle */",
                "require('node_modules/acme-attrib-lib/index.js');",
                "require('node_modules/acme-mit-lib/index.js');",
                "require('node_modules/acme-choice-lib/index.js');",
            )
        ),
        encoding="utf-8",
    )
    return work_root


def _release_record(
    name: str,
    spdx_id: str,
    repo_ref: str,
    *,
    presence: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "name": name,
        "version": "1.0.0",
        "repo": repo_ref,
        "purl": f"pkg:npm/{name}@1.0.0",
        "declared_license_raw": spdx_id,
        "spdx_id": spdx_id,
        "evidence": {
            "source_layer": "syft",
            "url": f"https://repolens.example/packages/{name}",
            "anchor": spdx_id,
        },
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "presence": presence
        or Presence(
            install_state="installed",
            delivery_state="not_scanned",
            relation="direct",
            source="syft",
        ).to_dict(),
        "modified": "unknown",
    }
