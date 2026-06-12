"""Shared readiness preflight for RepoLens-owned tools."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from repolens.exit_codes import InputError
from repolens.resolve.scancode import resolve_scancode_path

from .cache import SyftCacheProgress, cached_syft_path, ensure_syft_cached, load_syft_pin
from .errors import BootstrapError, UsageError
from .scancode import provision_scancode_work_root

ToolName = Literal["syft", "scancode"]


class ToolStatus(StrEnum):
    PRESENT = "present"
    PROVISIONABLE = "provisionable"
    MISSING_UNPROVISIONABLE = "missing-and-unprovisionable"


@dataclass(frozen=True, slots=True)
class ToolReadiness:
    tool: ToolName
    status: ToolStatus
    path: Path | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class ToolPreflightOptions:
    work_root: Path
    offline: bool
    auto_bootstrap: bool
    quiet: bool = False


def check_required_tools(
    tools: Sequence[ToolName],
    options: ToolPreflightOptions,
) -> tuple[ToolReadiness, ...]:
    """Report trust/provisioning status for each required tool."""

    return tuple(_check_tool(tool, options) for tool in tools)


def ensure_required_tools(
    tools: Sequence[ToolName],
    options: ToolPreflightOptions,
    *,
    syft_progress: SyftCacheProgress | None = None,
) -> Mapping[ToolName, Path]:
    """Return trusted tool paths, provisioning missing tools only when allowed."""

    paths: dict[ToolName, Path] = {}
    for readiness in check_required_tools(tools, options):
        if readiness.status is ToolStatus.PRESENT:
            if readiness.path is None:
                raise InputError(f"{readiness.tool} readiness reported present without a path")
            paths[readiness.tool] = readiness.path
            continue
        if readiness.status is ToolStatus.MISSING_UNPROVISIONABLE:
            raise InputError(_missing_tool_message(readiness, options))
        if readiness.tool == "syft":
            try:
                result = ensure_syft_cached(offline=options.offline, progress=syft_progress)
            except UsageError as exc:
                raise InputError(str(exc)) from exc
            paths["syft"] = result.path
            continue
        if readiness.tool == "scancode":
            try:
                paths["scancode"] = provision_scancode_work_root(options.work_root)
            except (BootstrapError, OSError, RuntimeError, ValueError) as exc:
                raise InputError(
                    f"ScanCode bootstrap failed for {options.work_root}: {exc}\n"
                    "Hint: make sure Python venv/pip can run, network access is available, "
                    "and the pinned hash-locked ScanCode requirements support this "
                    "Python/platform; then rerun `repolens bootstrap --work-root <WORK>`."
                ) from exc
            continue
        raise InputError(f"unsupported required tool: {readiness.tool}")
    return paths


def _check_tool(tool: ToolName, options: ToolPreflightOptions) -> ToolReadiness:
    if tool == "syft":
        pin = load_syft_pin()
        cached = cached_syft_path(pin)
        if cached is not None:
            return ToolReadiness(tool, ToolStatus.PRESENT, cached, None)
        return _missing_readiness(tool, options, "verified shared Syft cache is missing")
    if tool == "scancode":
        try:
            path = resolve_scancode_path(options.work_root)
        except InputError as exc:
            return _missing_readiness(tool, options, str(exc))
        return ToolReadiness(tool, ToolStatus.PRESENT, path, None)
    raise InputError(f"unsupported required tool: {tool}")


def _missing_readiness(
    tool: ToolName,
    options: ToolPreflightOptions,
    reason: str,
) -> ToolReadiness:
    if options.offline:
        return ToolReadiness(
            tool,
            ToolStatus.MISSING_UNPROVISIONABLE,
            None,
            f"{reason}; offline mode requires a verified pre-seeded tool",
        )
    if not options.auto_bootstrap:
        return ToolReadiness(
            tool,
            ToolStatus.MISSING_UNPROVISIONABLE,
            None,
            f"{reason}; auto-bootstrap disabled",
        )
    return ToolReadiness(tool, ToolStatus.PROVISIONABLE, None, reason)


def _missing_tool_message(readiness: ToolReadiness, options: ToolPreflightOptions) -> str:
    reason = readiness.reason or "tool is missing"
    if readiness.tool == "syft":
        return f"Syft is required but not ready: {reason}"
    return (
        f"ScanCode is required but not ready for this work root: {reason}\n"
        f"Fix: repolens bootstrap --work-root {options.work_root}"
    )
