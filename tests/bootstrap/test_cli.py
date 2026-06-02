"""Tests for the python -m repolens.bootstrap CLI (dry-run validation)."""

from __future__ import annotations

from repolens.bootstrap.__main__ import main
from repolens.bootstrap.orchestrate import EXIT_OK, EXIT_USAGE
from repolens.bootstrap.pins import DEFAULT_PINS_PATH
from repolens.bootstrap.scancode import DEFAULT_REQUIREMENTS_PATH

FIXTURES_DIR = "tests/bootstrap/fixtures"


def test_cli_dry_run_validates_shipped_manifest():
    rc = main(
        [
            "--dry-run",
            "--pins",
            str(DEFAULT_PINS_PATH),
            "--requirements",
            str(DEFAULT_REQUIREMENTS_PATH),
        ]
    )
    assert rc == EXIT_OK


def test_cli_invalid_manifest_is_usage_error():
    rc = main(
        [
            "--dry-run",
            "--pins",
            f"{FIXTURES_DIR}/pins.latest.bad.toml",
            "--requirements",
            str(DEFAULT_REQUIREMENTS_PATH),
        ]
    )
    assert rc == EXIT_USAGE


def test_cli_live_mode_requires_injected_runners():
    # Without --dry-run the CLI cannot acquire/verify (no network in F4 runtime).
    rc = main(
        [
            "--pins",
            str(DEFAULT_PINS_PATH),
            "--requirements",
            str(DEFAULT_REQUIREMENTS_PATH),
        ]
    )
    assert rc == EXIT_USAGE
