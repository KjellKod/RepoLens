from __future__ import annotations

import json
from pathlib import Path

from repolens.data.validation import validate_artifact
from repolens.presence.models import Presence
from repolens.release.evaluate import evaluate_release
from repolens.release.writers import (
    remove_withheld_outputs,
    write_release_licenses,
    write_release_notices,
    write_release_policy,
    write_release_review,
)


def test_policy_json_validates_and_is_deterministic(tmp_path: Path) -> None:
    evaluation = evaluate_release([_record("acme-mit", "MIT", delivered=True)])

    first = write_release_policy(tmp_path, evaluation).read_bytes()
    second = write_release_policy(tmp_path, evaluation).read_bytes()

    assert first == second
    payload = json.loads(first)
    validate_artifact(payload, "release_policy")
    assert "generated_at" not in payload


def test_notices_and_manifest_include_attribution_and_mit(tmp_path: Path) -> None:
    evaluation = evaluate_release(
        [
            _record("acme-attrib-lib", "CC-BY-4.0", delivered=True),
            _record("acme-mit-lib", "MIT", delivered=True),
            _record(
                "acme-native-optional",
                "LGPL-3.0-only",
                delivered=False,
                install_state="lockfile_only",
                relation="optional",
            ),
        ]
    )

    licenses = json.loads(write_release_licenses(tmp_path, evaluation).read_text())
    notices_md, notices_txt = write_release_notices(tmp_path, evaluation)
    review = write_release_review(tmp_path, evaluation).read_text(encoding="utf-8")

    assert [entry["name"] for entry in licenses["entries"]] == [
        "acme-attrib-lib",
        "acme-mit-lib",
    ]
    assert licenses["entries"][0]["actions"]["public_notice"] == "required"
    assert "Attribution:" in notices_md.read_text(encoding="utf-8")
    assert "acme-mit-lib" in notices_txt.read_text(encoding="utf-8")
    assert "acme-native-optional" not in notices_md.read_text(encoding="utf-8")
    assert "acme-native-optional" in review


def test_blocked_run_deletes_stale_notices(tmp_path: Path) -> None:
    for filename in ("release.licenses.json", "release.notices.md", "release.notices.txt"):
        (tmp_path / filename).write_text("stale", encoding="utf-8")

    remove_withheld_outputs(tmp_path)

    assert not (tmp_path / "release.licenses.json").exists()
    assert not (tmp_path / "release.notices.md").exists()
    assert not (tmp_path / "release.notices.txt").exists()


def _record(
    name: str,
    spdx_id: str,
    *,
    delivered: bool,
    install_state: str = "installed",
    relation: str = "direct",
) -> dict[str, object]:
    return {
        "name": name,
        "version": "1.0.0",
        "repo": "acme-alpha",
        "purl": f"pkg:npm/{name}@1.0.0",
        "spdx_id": spdx_id,
        "evidence": {"source_layer": "syft", "url": f"https://repolens.example/{name}"},
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "presence": Presence(
            install_state=install_state,  # type: ignore[arg-type]
            delivery_state="delivered" if delivered else "not_scanned",
            relation=relation,  # type: ignore[arg-type]
            source="syft",
        ).to_dict(),
        "modified": "unknown",
    }
