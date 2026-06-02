"""Top-level orchestration: wire the gates in fail-closed order.

``run()`` is the single entry point that ``__main__`` and a future
``repolens bootstrap`` subcommand call. All side-effecting steps (acquire,
cosign run, pip run, chmod) are injected so the whole flow is testable offline.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

from .errors import BootstrapError, IntegrityError, UsageError
from .pins import DEFAULT_PINS_PATH, Pins, current_platform, load_pins
from .record import write_tool_versions
from .scancode import DEFAULT_REQUIREMENTS_PATH, install_scancode
from .syft import (
    Acquire,
    CommandRunner,
    MakeExecutable,
    ResolvedTool,
    bootstrap_cosign,
    bootstrap_syft,
)
from .verify import CosignVerifier

# Exit codes (consistent with rpl_decisions.md CLI scheme).
EXIT_OK = 0
EXIT_INTEGRITY = 1
EXIT_USAGE = 2


def default_make_executable(path: Path) -> None:
    """Real chmod +x for owner/group/other read+execute."""
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def run(
    *,
    pins_path: Path | str = DEFAULT_PINS_PATH,
    dest_dir: Path | str,
    versions_out: Path | str,
    acquire: Acquire,
    make_executable: MakeExecutable = default_make_executable,
    cosign_runner: CommandRunner,
    pip_runner: CommandRunner,
    syft_runner: CommandRunner | None = None,
    requirements_path: Path | str = DEFAULT_REQUIREMENTS_PATH,
    platform_key: str | None = None,
    dry_run: bool = False,
) -> int:
    """Run the full bootstrap; return an exit code.

    Order: load_pins -> bootstrap cosign (checksum-gated) -> bootstrap syft
    (checksum -> signature -> provenance) -> install scancode (hash-pinned) ->
    record versions. Any integrity failure aborts before the next step.
    """
    plat = platform_key or current_platform()
    dest_dir = Path(dest_dir)

    try:
        pins: Pins = load_pins(pins_path)

        if dry_run:
            # Validate-only: prove the manifest loads and requirements validate.
            from .scancode import load_requirements

            load_requirements(requirements_path)
            return EXIT_OK

        resolved: list[ResolvedTool] = []

        # 1. cosign first — it is the trust anchor for Syft's signature, so it is
        #    acquired + checksum-verified before it is ever run.
        cosign_tool = bootstrap_cosign(
            pins,
            dest_dir / "cosign",
            acquire=acquire,
            make_executable=make_executable,
            platform_key=plat,
        )
        resolved.append(cosign_tool)

        verifier = CosignVerifier(cosign_tool.path, cosign_runner)

        # 2. Syft — checksum -> signature -> provenance -> write+chmod.
        syft_tool = bootstrap_syft(
            pins,
            dest_dir / "syft",
            acquire=acquire,
            verifier=verifier,
            make_executable=make_executable,
            runner=syft_runner,
            platform_key=plat,
            workdir=dest_dir,
        )
        resolved.append(syft_tool)

        # 3. ScanCode — hash-pinned pip install (runner injected).
        install_scancode(requirements_path, runner=pip_runner)

        # 4. Record versions.
        write_tool_versions(pins, resolved, versions_out)
        return EXIT_OK

    except IntegrityError:
        # Fail closed: any tamper/verification failure is an integrity exit.
        raise
    except UsageError:
        raise
    except BootstrapError:
        raise


def run_safe(**kwargs) -> int:
    """Like :func:`run` but maps exceptions to exit codes (for the CLI)."""
    try:
        return run(**kwargs)
    except IntegrityError as exc:
        print(f"integrity failure: {exc}")
        return EXIT_INTEGRITY
    except UsageError as exc:
        print(f"usage error: {exc}")
        return EXIT_USAGE
    except BootstrapError as exc:
        print(f"bootstrap error: {exc}")
        return EXIT_INTEGRITY


# Type alias retained for callers that want to plug a different runner factory.
RunnerFactory = Callable[[], CommandRunner]
