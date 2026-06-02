"""ScanCode fallback orchestration for unresolved packages."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from repolens.bootstrap.record import VERSIONS_SCHEMA
from repolens.bootstrap.scancode import (
    SCANCODE_REQUIREMENTS_SOURCE_PREFIX,
    build_scancode_wrapper,
)
from repolens.exit_codes import InputError
from repolens.policy.config import load_default_policy
from repolens.policy.spdx import normalize_license
from repolens.resolve.models import PackageFact
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.redaction import redact_tokens
from repolens.security.sandbox import scrubbed_tool_env

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ExecutableProvider = Callable[[str | Path], Path]
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ScanCodeOutcome:
    """Result of ScanCode fallback."""

    spdx_id: str | None
    anchor: str


class ScanCodeUnavailable(RuntimeError):
    """Raised when the canonical ScanCode executable is unavailable."""


class ScanCodeTargetError(ValueError):
    """Raised when no safe package-local target can be derived."""


def resolve_scancode_path(work_root: str | Path) -> Path:
    """Return the canonical bootstrap-produced ScanCode executable path."""

    root = Path(work_root)
    path = root / "tools" / "scancode"
    versions_path = root / "tool_versions.json"
    if not versions_path.exists():
        raise InputError("tool_versions.json not found; ScanCode bootstrap record is required.")
    try:
        payload = json.loads(versions_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError("tool_versions.json is not readable.") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError("tool_versions.json is not valid JSON.") from exc
    if not isinstance(payload, dict) or payload.get("schema") != VERSIONS_SCHEMA:
        raise InputError("tool_versions.json does not use the supported tool-versions schema.")
    tools = payload.get("tools") if isinstance(payload, dict) else None
    scancode = tools.get("scancode") if isinstance(tools, dict) else None
    if not isinstance(scancode, dict):
        raise InputError("tool_versions.json does not record a pinned ScanCode version.")
    version = scancode.get("version")
    digest = scancode.get("digest")
    source = scancode.get("source")
    if not isinstance(version, str) or not version.strip():
        raise InputError("tool_versions.json does not record a pinned ScanCode version.")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise InputError("tool_versions.json does not record a ScanCode requirements digest.")
    if not isinstance(source, str) or not source.startswith(SCANCODE_REQUIREMENTS_SOURCE_PREFIX):
        raise InputError("tool_versions.json does not record a ScanCode requirements source.")
    if not path.is_file():
        raise InputError(
            "ScanCode wrapper not found under <work-root>/tools/scancode; run the "
            "bootstrap step first (it installs ScanCode from hash-pinned requirements)."
        )
    try:
        wrapper = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError("ScanCode wrapper is not readable.") from exc
    except UnicodeDecodeError as exc:
        raise InputError("ScanCode wrapper is not valid UTF-8.") from exc
    if wrapper != build_scancode_wrapper(version, digest):
        raise InputError("ScanCode wrapper does not match the recorded bootstrap proof.")
    if not os.access(path, os.X_OK):
        raise InputError("ScanCode wrapper is not executable.")
    return path


def select_scancode_targets(package: PackageFact, source_root: str | Path) -> tuple[Path, ...]:
    """Select one package-local directory and LICENSE files for ``package``."""

    root = Path(source_root)
    if not root.is_dir():
        raise ScanCodeTargetError("source root is not a directory")
    root = root.resolve()
    package_dir: Path | None = None
    for location in package.locations:
        candidate = _contained_path(root, location)
        if candidate is None:
            continue
        directory = candidate if candidate.is_dir() else candidate.parent
        directory = directory.resolve()
        if directory == root:
            continue
        package_dir = directory
        break
    if package_dir is None:
        raise ScanCodeTargetError("no package-local target")

    targets = [package_dir]
    targets.extend(_safe_license_targets(root, package_dir))
    return tuple(dict.fromkeys(targets))


def _safe_license_targets(root: Path, package_dir: Path) -> tuple[Path, ...]:
    targets: list[Path] = []
    for path in sorted(package_dir.glob("LICENSE*")):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if _is_relative_to(resolved, root) and _is_relative_to(resolved, package_dir):
            targets.append(resolved)
    return tuple(targets)


def run_scancode_fallback(
    package: PackageFact,
    *,
    work_root: str | Path,
    source_root: str | Path | None,
    command_runner: CommandRunner | None = None,
    executable_provider: ExecutableProvider = resolve_scancode_path,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> ScanCodeOutcome:
    """Run ScanCode for one unresolved package using package-local targets only."""

    if source_root is None:
        return ScanCodeOutcome(None, "unresolved:scancode_no_source_root")
    try:
        executable = executable_provider(work_root)
    except (InputError, ScanCodeUnavailable):
        return ScanCodeOutcome(None, "unresolved:scancode_tool_unavailable")
    try:
        targets = select_scancode_targets(package, source_root)
    except ScanCodeTargetError:
        return ScanCodeOutcome(None, "unresolved:scancode_no_target")
    runner = command_runner or _default_command_runner
    argv = [
        str(executable),
        "--license",
        "--json",
        "-",
        *(str(target) for target in targets),
    ]
    try:
        completed = runner(argv, timeout=limits.clone_timeout_seconds)
    except subprocess.TimeoutExpired:
        return ScanCodeOutcome(None, "unresolved:scancode_timeout")
    except OSError:
        return ScanCodeOutcome(None, "unresolved:scancode_tool_unavailable")
    if completed.returncode != 0:
        return ScanCodeOutcome(None, "unresolved:scancode_failed")
    try:
        return _outcome_from_document(json.loads(completed.stdout), targets)
    except (json.JSONDecodeError, ValueError):
        return ScanCodeOutcome(None, "unresolved:scancode_malformed_output")


def _default_command_runner(
    argv: Sequence[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        env=scrubbed_tool_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _outcome_from_document(document: object, targets: tuple[Path, ...]) -> ScanCodeOutcome:
    values = tuple(dict.fromkeys(_normalized_license_values(document)))
    if not values:
        return ScanCodeOutcome(None, "unresolved:scancode_no_license")
    if len(values) > 1:
        return ScanCodeOutcome("CONFLICT", "conflict:scancode_disagreement")
    target_name = redact_tokens(targets[0].name)
    return ScanCodeOutcome(values[0], f"scancode:{values[0]}:{target_name}")


def _normalized_license_values(document: object) -> tuple[str, ...]:
    policy = load_default_policy()
    out: list[str] = []
    for value in _license_strings(document):
        normalized = normalize_license(value, policy)
        if normalized.spdx_id is not None:
            out.append(normalized.spdx_id)
    return tuple(out)


def _license_strings(value: object) -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, dict):
        for key in (
            "license_expression_spdx",
            "license_expression",
            "spdx_license_key",
            "spdx_id",
            "key",
        ):
            child = value.get(key)
            if isinstance(child, str) and child.strip():
                found.append(child.strip())
        for child in value.values():
            found.extend(_license_strings(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_license_strings(child))
    return tuple(found)


def _contained_path(root: Path, location: str) -> Path | None:
    candidate = (root / location).resolve()
    if not _is_relative_to(candidate, root):
        return None
    return candidate


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
