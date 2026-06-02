from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "verify_tool_pins.py"


def write_minimal_tree(root: Path, workflow_uses: str, requirements: str, manifest: dict) -> None:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "\n".join(
            [
                "name: test",
                "on: workflow_dispatch",
                "jobs:",
                "  t:",
                "    steps:",
                f"      - uses: {workflow_uses}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "requirements-dev.txt").write_text(requirements, encoding="utf-8")
    (root / ".github" / "tool-pins.json").write_text(json.dumps(manifest), encoding="utf-8")


def run_verify(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT.as_posix(), "--root", root.as_posix()],
        text=True,
        capture_output=True,
        check=False,
    )


def test_verify_tool_pins_rejects_latest_or_missing_checksum(tmp_path: Path) -> None:
    full_sha = "a" * 40
    write_minimal_tree(
        tmp_path,
        f"synthetic/action@{full_sha}",
        "pytest==8.4.1\n",
        {
            "github_actions": [{"uses": "synthetic/action", "version": "v1", "sha": full_sha}],
            "external_tools": [{"name": "synthetic-tool", "version": "1.0"}],
        },
    )

    proc = run_verify(tmp_path)

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any("missing a sha256 hash" in error for error in payload["errors"])
    assert any("missing checksum_sha256" in error for error in payload["errors"])
    assert any("missing signature metadata" in error for error in payload["errors"])


def test_verify_tool_pins_rejects_workflow_action_tags(tmp_path: Path) -> None:
    write_minimal_tree(
        tmp_path,
        "synthetic/action@v4",
        "pytest==8.4.1 --hash=sha256:" + "b" * 64 + "\n",
        {
            "github_actions": [{"uses": "synthetic/action", "version": "v4", "sha": "b" * 40}],
            "external_tools": [],
        },
    )

    proc = run_verify(tmp_path)

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any("unpinned action ref" in error for error in payload["errors"])
    assert any("floating action ref" in error for error in payload["errors"])


def test_verify_tool_pins_checks_yaml_workflows(tmp_path: Path) -> None:
    full_sha = "a" * 40
    write_minimal_tree(
        tmp_path,
        f"synthetic/action@{full_sha}",
        "pytest==8.4.1 --hash=sha256:" + "b" * 64 + "\n",
        {
            "github_actions": [{"uses": "synthetic/action", "version": "v1", "sha": full_sha}],
            "external_tools": [],
        },
    )
    yaml_workflow = tmp_path / ".github" / "workflows" / "extra.yaml"
    yaml_workflow.write_text(
        "\n".join(
            [
                "name: yaml",
                "on: workflow_dispatch",
                "jobs:",
                "  t:",
                "    steps:",
                "      - uses: synthetic/other@v1",
                "",
            ]
        ),
        encoding="utf-8",
    )

    proc = run_verify(tmp_path)

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any(
        ".github/workflows/extra.yaml uses unpinned action ref" in error
        for error in payload["errors"]
    )
    assert any(
        ".github/workflows/extra.yaml uses floating action ref" in error
        for error in payload["errors"]
    )


def test_verify_tool_pins_rejects_known_annotated_tag_object_sha(tmp_path: Path) -> None:
    tag_object_sha = "c" * 40
    write_minimal_tree(
        tmp_path,
        f"synthetic/action@{tag_object_sha}",
        "pytest==8.4.1 --hash=sha256:" + "d" * 64 + "\n",
        {
            "github_actions": [
                {
                    "uses": "synthetic/action",
                    "version": "v1",
                    "sha": tag_object_sha,
                    "tag_object_sha": tag_object_sha,
                }
            ],
            "external_tools": [],
        },
    )

    proc = run_verify(tmp_path)

    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any("annotated tag object" in error for error in payload["errors"])
