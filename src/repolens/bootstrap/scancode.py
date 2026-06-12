"""Hash-pinned ScanCode install (orchestrate pip; never reimplement it).

We generate/validate a ``--require-hashes`` requirements file and construct the
pip argv. We do NOT run pip here: the runner is injected, and tests assert the
argv + the rejection of any unhashed line. ``--require-hashes`` forces every
installed distribution (including transitive deps) to be hashed, so the shipped
requirements file must be fully transitively pinned and is paired with
``--no-deps`` to keep the resolution closed.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from .errors import UnhashedRequirement
from .pins import DEFAULT_PINS_PATH, load_pins
from .record import write_tool_versions
from .syft import ResolvedTool

#: Runs the pip argv, returning its exit code. Injected so tests stay offline.
PipRunner = Callable[[list[str]], int]
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
MakeExecutable = Callable[[Path], None]
PathMover = Callable[[Path, Path], None]

#: Path of the hash-pinned requirements file shipped with the package.
DEFAULT_REQUIREMENTS_PATH = Path(__file__).with_name("scancode.requirements.txt")
SCANCODE_REQUIREMENTS_SOURCE_PREFIX = "hash-pinned-requirements:"
SCANCODE_VENV_SOURCE_PREFIX = "exact-pip-venv:"
SCANCODE_WRAPPER_MARKER = "repolens-scancode-wrapper/v1"

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


def requirements_sha256(path: Path | str) -> str:
    """Return the SHA-256 of a validated hash-pinned requirements file."""

    req = Path(path)
    validate_requirements(req.read_text(encoding="utf-8"))
    return hashlib.sha256(req.read_bytes()).hexdigest()


def build_scancode_wrapper(version: str, requirements_digest: str) -> str:
    """Build the canonical bootstrap-produced ScanCode command wrapper."""

    clean_version = version.strip()
    if not clean_version:
        raise ValueError("ScanCode version must be non-empty")
    if "\n" in clean_version or "\r" in clean_version:
        raise ValueError("ScanCode version must be a single line")
    if not _HASH_RE.fullmatch(f"--hash=sha256:{requirements_digest}"):
        raise ValueError("ScanCode requirements digest must be a lowercase sha256")
    return (
        "#!/bin/sh\n"
        f"# {SCANCODE_WRAPPER_MARKER}\n"
        f"# scancode-version: {clean_version}\n"
        f"# requirements-sha256: {requirements_digest}\n"
        'exec python3 -m scancode.cli "$@"\n'
    )


def scancode_venv_source(version: str) -> str:
    """Return the recorded source string for the user-facing venv bootstrap."""

    return f"{SCANCODE_VENV_SOURCE_PREFIX}scancode-toolkit=={_clean_version(version)}"


def scancode_hash_pinned_venv_source(requirements_path: Path | str) -> str:
    """Return the recorded source string for a hash-pinned work-root venv."""

    requirements_name = Path(requirements_path).name
    if not requirements_name or "\n" in requirements_name or "\r" in requirements_name:
        raise ValueError("ScanCode requirements source must be a single filename")
    return f"{SCANCODE_REQUIREMENTS_SOURCE_PREFIX}{requirements_name}"


def scancode_venv_digest(version: str) -> str:
    """Return a stable digest for the exact ScanCode venv install spec."""

    return hashlib.sha256(scancode_venv_source(version).encode("utf-8")).hexdigest()


def build_scancode_venv_wrapper(version: str, install_digest: str) -> str:
    """Build the canonical work-root-local ScanCode venv wrapper."""

    clean_version = _clean_version(version)
    if not _HASH_RE.fullmatch(f"--hash=sha256:{install_digest}"):
        raise ValueError("ScanCode install digest must be a lowercase sha256")
    return (
        "#!/bin/sh\n"
        f"# {SCANCODE_WRAPPER_MARKER}\n"
        f"# scancode-version: {clean_version}\n"
        f"# install-source: {scancode_venv_source(clean_version)}\n"
        f"# install-sha256: {install_digest}\n"
        'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        'exec "$SCRIPT_DIR/scancode-venv/bin/python" -m scancode.cli "$@"\n'
    )


def build_scancode_hash_pinned_venv_wrapper(
    version: str,
    requirements_digest: str,
    *,
    requirements_source: str,
) -> str:
    """Build the canonical hash-pinned work-root ScanCode venv wrapper."""

    clean_version = _clean_version(version)
    if not _HASH_RE.fullmatch(f"--hash=sha256:{requirements_digest}"):
        raise ValueError("ScanCode requirements digest must be a lowercase sha256")
    if not requirements_source.startswith(SCANCODE_REQUIREMENTS_SOURCE_PREFIX):
        raise ValueError("ScanCode requirements source must be hash-pinned")
    if "\n" in requirements_source or "\r" in requirements_source:
        raise ValueError("ScanCode requirements source must be a single line")
    return (
        "#!/bin/sh\n"
        f"# {SCANCODE_WRAPPER_MARKER}\n"
        f"# scancode-version: {clean_version}\n"
        f"# requirements-source: {requirements_source}\n"
        f"# requirements-sha256: {requirements_digest}\n"
        'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        'exec "$SCRIPT_DIR/scancode-venv/bin/python" -m scancode.cli "$@"\n'
    )


def write_scancode_venv_wrapper(
    dest: Path | str,
    *,
    version: str,
    install_digest: str,
    make_executable: Callable[[Path], None],
) -> Path:
    """Write the canonical venv-backed ScanCode wrapper and mark it executable."""

    wrapper = Path(dest)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(build_scancode_venv_wrapper(version, install_digest), encoding="utf-8")
    make_executable(wrapper)
    return wrapper


def write_scancode_hash_pinned_venv_wrapper(
    dest: Path | str,
    *,
    version: str,
    requirements_digest: str,
    requirements_source: str,
    make_executable: Callable[[Path], None],
) -> Path:
    """Write the canonical hash-pinned venv-backed wrapper and mark it executable."""

    wrapper = Path(dest)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        build_scancode_hash_pinned_venv_wrapper(
            version,
            requirements_digest,
            requirements_source=requirements_source,
        ),
        encoding="utf-8",
    )
    make_executable(wrapper)
    return wrapper


def write_scancode_wrapper(
    dest: Path | str,
    *,
    version: str,
    requirements_digest: str,
    make_executable: Callable[[Path], None],
) -> Path:
    """Write the canonical ScanCode wrapper and mark it executable."""

    wrapper = Path(dest)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(build_scancode_wrapper(version, requirements_digest), encoding="utf-8")
    make_executable(wrapper)
    return wrapper


def install_scancode_venv(
    venv_dir: Path | str,
    *,
    version: str,
    python: str = sys.executable,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Create a work-root-local venv and install the exact pinned ScanCode version."""

    venv = Path(venv_dir)
    run = runner or _run_command
    _run_checked(run, [python, "-m", "venv", str(venv)], "create ScanCode virtualenv")
    venv_python = venv / "bin" / "python"
    _run_checked(
        run,
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--only-binary=:all:",
            f"scancode-toolkit=={_clean_version(version)}",
        ],
        "install ScanCode",
    )


def install_scancode_hash_pinned_venv(
    venv_dir: Path | str,
    *,
    requirements_path: Path | str = DEFAULT_REQUIREMENTS_PATH,
    python: str = sys.executable,
    runner: CommandRunner | None = None,
) -> None:
    """Create a work-root venv and install ScanCode from closed hash-pinned requirements."""

    req = Path(requirements_path)
    load_requirements(req)
    venv = Path(venv_dir)
    run = runner or _run_command
    _run_checked(run, [python, "-m", "venv", str(venv)], "create ScanCode virtualenv")
    venv_python = venv / "bin" / "python"
    _run_checked(
        run,
        build_pip_argv(req, python=str(venv_python)),
        "install ScanCode",
    )


def provision_scancode_work_root(
    work_root: Path | str,
    *,
    python: str = sys.executable,
    runner: CommandRunner | None = None,
    make_executable: MakeExecutable | None = None,
    requirements_path: Path | str = DEFAULT_REQUIREMENTS_PATH,
    pins_path: Path | str = DEFAULT_PINS_PATH,
    mover: PathMover | None = None,
) -> Path:
    """Provision canonical ``<WORK>/tools/scancode`` through hash-pinned requirements.

    ``<WORK>/tool_versions.json`` is the trust marker used by ``resolve_scancode_path``.
    It is exposed last so partial installs are treated as missing/corrupt on the next run.
    """

    from repolens.exit_codes import InputError
    from repolens.resolve.scancode import resolve_scancode_path

    from .orchestrate import default_make_executable

    root = Path(work_root)
    try:
        return resolve_scancode_path(root)
    except InputError:
        pass

    chmod = make_executable or default_make_executable
    move = mover or _replace_path
    pins = load_pins(pins_path)
    version = pins.tool("scancode").version
    requirements = Path(requirements_path)
    digest = requirements_sha256(requirements)
    source = scancode_hash_pinned_venv_source(requirements)
    tools_dir = root / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".scancode-bootstrap-", dir=tools_dir) as tmp:
        staging_root = Path(tmp) / "root"
        staging_tools = staging_root / "tools"
        staging_venv = staging_tools / "scancode-venv"
        install_scancode_hash_pinned_venv(
            staging_venv,
            requirements_path=requirements,
            python=python,
            runner=runner,
        )
        wrapper = write_scancode_hash_pinned_venv_wrapper(
            staging_tools / "scancode",
            version=version,
            requirements_digest=digest,
            requirements_source=source,
            make_executable=chmod,
        )
        write_tool_versions(
            pins,
            [
                ResolvedTool(
                    name="scancode",
                    version=version,
                    digest=digest,
                    path=wrapper,
                    source=source,
                )
            ],
            staging_root / "tool_versions.json",
        )
        resolve_scancode_path(staging_root)

        move(staging_venv, tools_dir / "scancode-venv")
        move(staging_tools / "scancode", tools_dir / "scancode")
        move(staging_root / "tool_versions.json", root / "tool_versions.json")

    return resolve_scancode_path(root)


def _replace_path(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.is_dir() and not dst.is_symlink():
        shutil.rmtree(dst)
    elif dst.exists() or dst.is_symlink():
        dst.unlink()
    shutil.move(str(src), str(dst))


def _run_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _run_checked(
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
    argv: list[str],
    action: str,
) -> None:
    completed = runner(argv)
    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"failed to {action}{detail}")


def _clean_version(version: str) -> str:
    clean_version = version.strip()
    if not clean_version:
        raise ValueError("ScanCode version must be non-empty")
    if "\n" in clean_version or "\r" in clean_version:
        raise ValueError("ScanCode version must be a single line")
    return clean_version


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
