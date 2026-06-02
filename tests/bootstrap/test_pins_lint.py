"""Tests for the standalone pins-lint CI gate (AC #6)."""

from __future__ import annotations

import sys
from pathlib import Path

from repolens.bootstrap.pins import DEFAULT_PINS_PATH
from tools import pins_lint

FIXTURES = Path(__file__).parent / "fixtures"


def test_script_adds_src_layout_root():
    src_root = Path(pins_lint.__file__).resolve().parent.parent / "src"
    assert str(src_root) in sys.path


def test_lint_passes_real_manifest():
    assert pins_lint.main([str(DEFAULT_PINS_PATH)]) == 0


def test_lint_fails_on_latest_fixture():
    assert pins_lint.main([str(FIXTURES / "pins.latest.bad.toml")]) == 1


def test_lint_missing_file_is_usage_error():
    assert pins_lint.main([str(FIXTURES / "does_not_exist.toml")]) == 2


def test_lint_path_returns_errors():
    errs = pins_lint.lint_path(FIXTURES / "pins.latest.bad.toml")
    assert errs and "floating" in errs[0].lower()
