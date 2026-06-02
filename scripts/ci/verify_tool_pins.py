#!/usr/bin/env python3
"""Validate workflow action pins, hash-locked requirements, and tool metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^#\s]+)", re.MULTILINE)
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _error(errors: list[str], message: str) -> None:
    errors.append(message)


def action_ref_parts(value: str) -> tuple[str, str] | None:
    if value.startswith("./") or value.startswith("docker://"):
        return None
    if "@" not in value:
        return value, ""
    action, ref = value.rsplit("@", 1)
    return action, ref


def validate_workflow_refs(root: Path, errors: list[str]) -> set[str]:
    observed: set[str] = set()
    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        content = workflow.read_text(encoding="utf-8")
        for match in WORKFLOW_USES_RE.finditer(content):
            uses_value = match.group(1).strip().strip('"').strip("'")
            parts = action_ref_parts(uses_value)
            if parts is None:
                continue
            action, ref = parts
            observed.add(uses_value)
            if not FULL_SHA_RE.fullmatch(ref):
                _error(
                    errors, f"{workflow.relative_to(root)} uses unpinned action ref: {uses_value}"
                )
            if ref in {"latest", "main", "master"} or ref.startswith("v"):
                _error(
                    errors, f"{workflow.relative_to(root)} uses floating action ref: {uses_value}"
                )
            if not action:
                _error(
                    errors, f"{workflow.relative_to(root)} has malformed uses value: {uses_value}"
                )
    return observed


def _logical_requirement_lines(path: Path) -> list[str]:
    logical_lines: list[str] = []
    current = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1].strip() + " "
            continue
        logical_lines.append((current + stripped).strip())
        current = ""
    if current:
        logical_lines.append(current.strip())
    return logical_lines


def validate_requirements(root: Path, errors: list[str]) -> None:
    requirements = root / "requirements-dev.txt"
    if not requirements.exists():
        _error(errors, "requirements-dev.txt is missing")
        return
    for line in _logical_requirement_lines(requirements):
        requirement = line.split()[0]
        if requirement.startswith("-"):
            _error(errors, f"unsupported requirements directive: {requirement}")
            continue
        if "==" not in requirement:
            _error(errors, f"dependency is not exactly pinned: {requirement}")
        if not HASH_RE.search(line):
            _error(errors, f"dependency is missing a sha256 hash: {requirement}")


def validate_manifest(root: Path, observed_uses: set[str], errors: list[str]) -> None:
    manifest_path = root / ".github" / "tool-pins.json"
    if not manifest_path.exists():
        _error(errors, ".github/tool-pins.json is missing")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    action_entries = manifest.get("github_actions", [])
    if not isinstance(action_entries, list):
        _error(errors, "github_actions must be a list")
        return

    manifest_uses: set[str] = set()
    for entry in action_entries:
        if not isinstance(entry, dict):
            _error(errors, "github_actions entries must be objects")
            continue
        uses = entry.get("uses")
        sha = entry.get("sha")
        version = entry.get("version")
        if not isinstance(uses, str) or not isinstance(sha, str) or not isinstance(version, str):
            _error(errors, "github_actions entries require uses, version, and sha strings")
            continue
        if not FULL_SHA_RE.fullmatch(sha):
            _error(errors, f"github action {uses} is missing a full sha pin")
        tag_object_sha = entry.get("tag_object_sha")
        if tag_object_sha is not None:
            if not isinstance(tag_object_sha, str) or not FULL_SHA_RE.fullmatch(tag_object_sha):
                _error(errors, f"github action {uses} has invalid tag_object_sha metadata")
            elif sha == tag_object_sha:
                _error(errors, f"github action {uses} is pinned to an annotated tag object")
        manifest_uses.add(f"{uses}@{sha}")

    missing = observed_uses - manifest_uses
    for uses in sorted(missing):
        _error(errors, f"workflow action is not listed in .github/tool-pins.json: {uses}")

    for entry in manifest.get("external_tools", []):
        if not isinstance(entry, dict):
            _error(errors, "external_tools entries must be objects")
            continue
        name = entry.get("name", "<unnamed>")
        checksum = entry.get("checksum_sha256")
        signature = entry.get("signature")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            _error(errors, f"external tool {name} is missing checksum_sha256")
        if not isinstance(signature, str) or not signature:
            _error(errors, f"external tool {name} is missing signature metadata")


def run(root: Path) -> tuple[int, dict[str, object]]:
    errors: list[str] = []
    observed_uses = validate_workflow_refs(root, errors)
    validate_requirements(root, errors)
    validate_manifest(root, observed_uses, errors)
    return (1 if errors else 0), {"passed": not errors, "errors": errors}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        exit_code, result = run(args.root.resolve())
    except (OSError, json.JSONDecodeError) as exc:
        exit_code, result = 1, {"passed": False, "errors": [str(exc)]}
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
