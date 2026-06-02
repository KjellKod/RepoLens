"""RepoLens tool bootstrap (F4).

Pins exact tool versions/digests and verifies the Syft binary by checksum +
cosign signature BEFORE it is ever made executable or run (fail-closed). Installs
ScanCode via hash-pinned pip requirements and records resolved tool versions.

Orchestration only: external tools (Syft, ScanCode, cosign, pip, git, gh) are
constructed/verified here, never reimplemented; their execution is injected.
"""

from __future__ import annotations

from .errors import (
    BootstrapError,
    ChecksumMismatch,
    ChecksumProvenanceError,
    IntegrityError,
    InvalidPin,
    SignatureVerificationError,
    UnhashedRequirement,
    UsageError,
)
from .orchestrate import EXIT_INTEGRITY, EXIT_OK, EXIT_USAGE, run, run_safe
from .pins import Pins, ToolPin, current_platform, load_pins
from .record import write_tool_versions
from .scancode import build_pip_argv, install_scancode, validate_requirements
from .syft import ResolvedTool, bootstrap_cosign, bootstrap_syft
from .verify import (
    build_cosign_argv,
    compute_sha256,
    verify_checksum,
)

__all__ = [
    "BootstrapError",
    "ChecksumMismatch",
    "ChecksumProvenanceError",
    "IntegrityError",
    "InvalidPin",
    "SignatureVerificationError",
    "UnhashedRequirement",
    "UsageError",
    "EXIT_OK",
    "EXIT_INTEGRITY",
    "EXIT_USAGE",
    "run",
    "run_safe",
    "Pins",
    "ToolPin",
    "current_platform",
    "load_pins",
    "write_tool_versions",
    "build_pip_argv",
    "install_scancode",
    "validate_requirements",
    "ResolvedTool",
    "bootstrap_cosign",
    "bootstrap_syft",
    "build_cosign_argv",
    "compute_sha256",
    "verify_checksum",
]
