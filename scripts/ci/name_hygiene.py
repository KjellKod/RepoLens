#!/usr/bin/env python3
"""Fail when runtime-supplied forbidden names appear in committed text files."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SKIPPED_SEGMENTS = {
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".quest",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".worktrees",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "venv",
}


@dataclass(frozen=True)
class Finding:
    path: str
    token: str

    def to_public_dict(self) -> dict[str, str]:
        token_hash = hashlib.sha256(self.token.encode("utf-8")).hexdigest()
        return {"path": self.path, "token_id": f"sha256:{token_hash[:16]}"}


def parse_env_tokens(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace(",", "\n")
    return [line.strip() for line in normalized.splitlines() if line.strip()]


def load_local_config(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not fnmatch.fnmatch(path.name, "*.local.*"):
        raise ValueError("local denylist config path must match '*.local.*'")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        values = payload.get("forbidden_names", [])
    else:
        raise ValueError("local denylist config must be a JSON list or object")
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError("forbidden_names must be a list of strings")
    return [item.strip() for item in values if item.strip()]


def _git_files(root: Path) -> list[Path]:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
            text=False,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [root / item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        rel_root = Path(current_root).relative_to(root)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in SKIPPED_SEGMENTS and not fnmatch.fnmatch(dirname, "*.local.*")
        ]
        for filename in filenames:
            path = rel_root / filename
            if should_scan(path):
                files.append(root / path)
    return files


def should_scan(relative_path: Path, *, tracked: bool = False) -> bool:
    if any(part in SKIPPED_SEGMENTS for part in relative_path.parts):
        return False
    if tracked:
        return True
    return not fnmatch.fnmatch(relative_path.name, "*.local.*")


def iter_candidate_files(root: Path) -> list[Path]:
    tracked_files = _git_files(root)
    if tracked_files:
        return [path for path in tracked_files if should_scan(path.relative_to(root), tracked=True)]
    return _walk_files(root)


def scan_file(path: Path, root: Path, tokens: list[str]) -> list[Finding]:
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    relative = path.relative_to(root).as_posix()
    return [Finding(relative, token) for token in tokens if token in content]


def run(root: Path, tokens: list[str], require_denylist: bool) -> tuple[int, dict[str, object]]:
    if not tokens:
        result = {
            "denylist_status": "absent",
            "files_scanned": 0,
            "findings": [],
            "passed": not require_denylist,
        }
        return (1 if require_denylist else 0), result

    findings: list[Finding] = []
    files = iter_candidate_files(root)
    for path in files:
        findings.extend(scan_file(path, root, tokens))

    result = {
        "denylist_status": "present",
        "files_scanned": len(files),
        "findings": [finding.to_public_dict() for finding in findings],
        "passed": not findings,
    }
    return (1 if findings else 0), result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--forbidden-name", action="append", default=[])
    parser.add_argument("--local-config", type=Path)
    parser.add_argument("--require-denylist", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()

    try:
        tokens = [
            *args.forbidden_name,
            *parse_env_tokens(os.environ.get("RPL_FORBIDDEN_NAMES")),
            *load_local_config(args.local_config),
        ]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True))
        return 1

    exit_code, result = run(
        root=root, tokens=sorted(set(tokens)), require_denylist=args.require_denylist
    )
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
