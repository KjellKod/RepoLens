"""Hash-pinned ScanCode install (orchestrate pip; never reimplement it).

We generate/validate a ``--require-hashes`` requirements file and construct the
pip argv. We do NOT run pip here: the runner is injected, and tests assert the
argv + the rejection of any unhashed line. ``--require-hashes`` forces every
installed distribution (including transitive deps) to be hashed, so the shipped
requirements file must be fully transitively pinned and is paired with
``--no-deps`` to keep the resolution closed.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from .errors import UnhashedRequirement

#: Runs the pip argv, returning its exit code. Injected so tests stay offline.
PipRunner = Callable[[list[str]], int]

#: Path of the hash-pinned requirements file shipped with the package.
DEFAULT_REQUIREMENTS_PATH = Path(__file__).with_name("scancode.requirements.txt")

_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def _logical_lines(text: str) -> list[str]:
    """Join pip line-continuations (``\\``) into one logical requirement each."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _is_requirement(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    # Global pip options (e.g. --require-hashes, --no-deps) are not requirements.
    return not stripped.startswith("-")


def _require_exact_pin(line: str) -> None:
    requirement = line.strip().split(";", 1)[0].split()[0]
    if "==" not in requirement:
        raise UnhashedRequirement(
            f"requirement {requirement!r} is not exactly version-pinned with '=='"
        )

    name, version = requirement.split("==", 1)
    if not name or not version or version.startswith("=") or "*" in version or "," in version:
        raise UnhashedRequirement(
            f"requirement {requirement!r} is not exactly version-pinned with a concrete version"
        )


def validate_requirements(text: str) -> None:
    """Raise :class:`UnhashedRequirement` if any pinned requirement lacks a hash.

    Also requires every requirement to be exactly version-pinned (``==``) so the
    set cannot float.
    """
    for line in _logical_lines(text):
        if not _is_requirement(line):
            continue
        if not _HASH_RE.search(line):
            name = line.strip().split()[0]
            raise UnhashedRequirement(f"requirement {name!r} has no --hash=sha256:<...> pin")
        _require_exact_pin(line)


def load_requirements(path: Path | str = DEFAULT_REQUIREMENTS_PATH) -> str:
    """Read + validate the shipped requirements file, returning its text."""
    text = Path(path).read_text(encoding="utf-8")
    validate_requirements(text)
    return text


def build_pip_argv(requirements_path: Path | str, *, python: str = "python3") -> list[str]:
    """Construct the hash-pinned ``pip install`` argv for ScanCode.

    Flags:
      * ``--require-hashes`` — every dist must be hashed in the requirements file.
      * ``--no-deps`` — the requirements file is the complete, transitively
        pinned set; pip must not resolve anything outside it.
      * ``--only-binary=:all:`` — refuse to build from sdists (no arbitrary
        ``setup.py`` execution at install time).
    """
    return [
        python,
        "-m",
        "pip",
        "install",
        "--require-hashes",
        "--no-deps",
        "--only-binary=:all:",
        "--requirement",
        str(requirements_path),
    ]


def install_scancode(
    requirements_path: Path | str,
    *,
    runner: PipRunner,
    python: str = "python3",
) -> int:
    """Validate the requirements file, then run the injected pip runner.

    Validation happens BEFORE the runner is invoked: an unhashed line raises and
    the runner is never called.
    """
    text = Path(requirements_path).read_text(encoding="utf-8")
    validate_requirements(text)
    argv = build_pip_argv(requirements_path, python=python)
    return runner(argv)
