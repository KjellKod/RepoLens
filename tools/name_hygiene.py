#!/usr/bin/env python3
"""Name-hygiene guard — fail the build on any forbidden owner/org/company literal.

The forbidden-token DENYLIST is NEVER committed: it is read from the env var
``RPL_HYGIENE_DENYLIST`` (comma/newline-separated) or from a file named in
``RPL_HYGIENE_DENYLIST_FILE``. A real name therefore never enters git: the repo
holds only the matcher logic; the actual forbidden names live in CI secrets/vars.

The guard is **fail-closed**. It refuses to run as a silent no-op: if no denylist
is configured, ``main`` exits non-zero (a misconfigured gate is a failed gate).
Set ``RPL_HYGIENE_DENYLIST`` as a repo/org variable in CI (see docs/usage.md).

Usage:
    python3 tools/name_hygiene.py [PATH ...]      # defaults to the repo tree
Exit codes: 0 = clean, 1 = a forbidden literal found, 2 = usage/config error
(includes an unconfigured/empty denylist — the gate must never pass vacuously).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

#: The only sanctioned invented namespace for fixtures/examples.
ALLOWED_NAMESPACE = "acme"

#: Suffixes known to be genuine binaries; skipped without sniffing. Every other
#: file (including extension-less ones) is treated as text unless a content
#: sniff says otherwise — so a real name in an extension-less file is still caught.
_BINARY_SUFFIXES = {
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".so",
    ".dylib",
    ".o",
    ".a",
    ".class",
    ".jar",
    ".pyc",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".wasm",
}

#: Bytes sampled to decide whether an unknown file is binary (NUL byte = binary).
_SNIFF_BYTES = 8192

_DENY_SPLIT = re.compile(r"[,\n]+")


def load_denylist(
    env: dict[str, str] | None = None,
) -> list[str]:
    """Read the forbidden tokens from env/file. Returns a list (possibly empty)."""
    env = env if env is not None else dict(os.environ)
    tokens: list[str] = []

    inline = env.get("RPL_HYGIENE_DENYLIST", "")
    if inline:
        tokens.extend(t.strip() for t in _DENY_SPLIT.split(inline))

    file_ref = env.get("RPL_HYGIENE_DENYLIST_FILE", "")
    if file_ref:
        path = Path(file_ref)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    tokens.append(line)

    # De-dupe, drop empties, keep order.
    seen: set[str] = set()
    out: list[str] = []
    for tok in tokens:
        low = tok.lower()
        if tok and low not in seen:
            seen.add(low)
            out.append(tok)
    return out


def _compile_matchers(denylist: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(re.escape(tok), re.IGNORECASE) for tok in denylist]


def scan_text(
    text: str,
    matchers: list[re.Pattern[str]],
    *,
    source: str,
) -> list[str]:
    """Return findings (``source:line: token``) for forbidden literals in text."""
    findings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for matcher in matchers:
            if matcher.search(line):
                findings.append(f"{source}:{lineno}: forbidden literal {matcher.pattern!r}")
    return findings


def _iter_tracked_files(root: Path) -> list[Path]:
    """List git-tracked files under ``root`` (falls back to a walk if not a repo)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
        )
        names = [n for n in out.stdout.split("\0") if n]
        return [root / n for n in names]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [p for p in root.rglob("*") if p.is_file()]


def _is_text_file(path: Path) -> bool:
    """True if ``path`` should be scanned as text.

    Known-binary suffixes are skipped outright. Everything else — including
    extension-less and unknown-suffix files — is sniffed: a NUL byte in the first
    few KB marks it binary, otherwise it is scanned as text. This catches a real
    name embedded in an extension-less or odd-suffixed file.
    """
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return False
    try:
        with path.open("rb") as fh:
            chunk = fh.read(_SNIFF_BYTES)
    except OSError:
        return False
    return b"\x00" not in chunk


def scan_paths(
    paths: list[Path],
    denylist: list[str],
) -> list[str]:
    """Scan files/dirs for forbidden literals. Returns findings (empty == clean).

    An empty denylist matches nothing here; refusing to run as a no-op is the
    caller's (``main``) responsibility so the library stays composable.
    """
    matchers = _compile_matchers(denylist)
    if not matchers:
        return []

    findings: list[str] = []
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(f for f in p.rglob("*") if f.is_file())
        elif p.is_file():
            files.append(p)

    for f in files:
        if not _is_text_file(f):
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(scan_text(text, matchers, source=str(f)))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    denylist = load_denylist()

    # Fail-closed: an unconfigured denylist makes this gate a silent no-op, so
    # refuse to run. CI must set RPL_HYGIENE_DENYLIST (repo/org variable) or
    # RPL_HYGIENE_DENYLIST_FILE. Exit 2 (config error), never a vacuous pass.
    if not denylist:
        print(
            "name-hygiene: ERROR no denylist configured — set RPL_HYGIENE_DENYLIST "
            "(comma/newline-separated) or RPL_HYGIENE_DENYLIST_FILE. Refusing to run "
            "as a no-op so the gate cannot pass vacuously.",
            file=sys.stderr,
        )
        return 2

    paths = [Path(a) for a in args] if args else _iter_tracked_files(_REPO_ROOT)

    findings = scan_paths(paths, denylist)
    if findings:
        for f in findings:
            print(f"name-hygiene: FAIL {f}", file=sys.stderr)
        return 1

    print(f"name-hygiene: OK ({len(denylist)} denylist token(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
