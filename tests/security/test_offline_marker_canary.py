from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.offline, pytest.mark.security]

X1_PYTEST_MODULES = (
    Path("tests/integration/test_fixture_manifest.py"),
    Path("tests/integration/test_watermark_canary.py"),
    Path("tests/security/test_name_hygiene_guard.py"),
    Path("tests/security/test_offline_marker_canary.py"),
)


def test_x1_pytest_modules_declare_offline_marker(repo_root):
    test_files = [repo_root / path for path in X1_PYTEST_MODULES]
    unmarked = [path for path in test_files if not _module_declares_offline_marker(path)]

    assert unmarked == []


def test_offline_marker_audit_rejects_unmarked_module(tmp_path):
    unmarked_test = tmp_path / "test_unmarked.py"
    unmarked_test.write_text(
        "def test_unmarked():\n    assert True\n",
        encoding="utf-8",
    )

    assert not _module_declares_offline_marker(unmarked_test)


def _module_declares_offline_marker(path: Path) -> bool:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "pytestmark":
                    return _contains_offline_marker(node.value)
    return False


def _contains_offline_marker(node: ast.AST) -> bool:
    if _is_pytest_offline_marker(node):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_contains_offline_marker(element) for element in node.elts)
    return False


def _is_pytest_offline_marker(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "offline"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "pytest"
    )
