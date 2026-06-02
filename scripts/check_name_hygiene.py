#!/usr/bin/env python3
"""Check tracked text files for name-hygiene leaks."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ENV_VAR = "REPOLENS_FORBIDDEN_NAMES"
TEXT_EXTENSIONS = {
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".rst",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {".gitignore", "Dockerfile", "LICENSE", "Makefile"}
STRUCTURAL_SEGMENTS = {"docs", "schemas", "schema", "fixtures", "fixture"}
NEUTRAL_HOSTS = {
    "127.0.0.1",
    "::1",
    "example.com",
    "example.net",
    "example.org",
    "json-schema.org",
    "localhost",
}
NEUTRAL_SUFFIXES = (".example", ".invalid", ".localhost", ".test")

CLASSIC_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
FINE_GRAINED_GITHUB_TOKEN_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>)\"']+", re.IGNORECASE)
KEYED_DOMAIN_RE = re.compile(
    r"\b(?:domain|host|hostname|homepage|site|url|uri|website)\b"
    r"\s*[:=]\s*['\"]?(?P<value>(?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    check: str
    detail: str


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [Path(item) for item in result.stdout.decode().split("\0") if item]


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILENAMES


def is_structural_candidate(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return bool(parts & STRUCTURAL_SEGMENTS)


def read_text(path: Path) -> str | None:
    if not is_text_candidate(path) or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def forbidden_names_from_env() -> list[str]:
    raw = os.environ.get(ENV_VAR, "")
    values = re.split(r"[,\n]", raw)
    return [value.strip() for value in values if value.strip()]


def neutral_host(host: str) -> bool:
    normalized = host.strip("[]").rstrip(".").lower()
    return normalized in NEUTRAL_HOSTS or normalized.endswith(NEUTRAL_SUFFIXES)


def host_from_domain_value(value: str) -> str:
    if value.lower().startswith(("http://", "https://")):
        return urlsplit(value).hostname or ""
    return value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def structural_findings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for regex, check in (
        (CLASSIC_GITHUB_TOKEN_RE, "github-token"),
        (FINE_GRAINED_GITHUB_TOKEN_RE, "github-token"),
    ):
        for match in regex.finditer(text):
            findings.append(
                Finding(path, line_number(text, match.start()), check, match.group(0)[:12])
            )

    if not is_structural_candidate(path):
        return findings

    for match in URL_RE.finditer(text):
        host = urlsplit(match.group(0)).hostname or ""
        if host and not neutral_host(host):
            findings.append(
                Finding(path, line_number(text, match.start()), "non-neutral-url", host)
            )

    for match in KEYED_DOMAIN_RE.finditer(text):
        host = host_from_domain_value(match.group("value"))
        if host and not neutral_host(host):
            findings.append(
                Finding(path, line_number(text, match.start()), "non-neutral-domain", host)
            )

    return findings


def env_findings(path: Path, text: str, forbidden_names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for forbidden_name in forbidden_names:
        start = 0
        while True:
            offset = text.find(forbidden_name, start)
            if offset == -1:
                break
            findings.append(
                Finding(path, line_number(text, offset), "forbidden-literal", forbidden_name)
            )
            start = offset + max(1, len(forbidden_name))
    return findings


def check_paths(paths: list[Path]) -> list[Finding]:
    forbidden_names = forbidden_names_from_env()
    findings: list[Finding] = []
    for path in paths:
        text = read_text(path)
        if text is None:
            continue
        findings.extend(structural_findings(path, text))
        findings.extend(env_findings(path, text, forbidden_names))
    return findings


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv] if argv else tracked_files()
    findings = check_paths(paths)
    if not findings:
        return 0

    for finding in findings:
        print(
            f"{finding.path}:{finding.line}: {finding.check}: {finding.detail}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
