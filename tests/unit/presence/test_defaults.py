from __future__ import annotations

import ast
from pathlib import Path

from repolens.presence.defaults import build_presence


def test_default_delivery_is_not_scanned_without_artifact_evidence() -> None:
    presence = build_presence(tags={"scope": "runtime", "distribution": "server"})

    assert presence.install_state == "installed"
    assert presence.delivery_state == "not_scanned"


def test_not_delivered_requires_artifact_absent_evidence() -> None:
    presence = build_presence(
        tags={"scope": "runtime", "distribution": "server"},
        artifact_scanned=True,
        artifact_present=False,
    )

    assert presence.delivery_state == "not_delivered"


def test_not_delivered_assignment_is_only_in_defaults_module(repo_root: Path) -> None:
    offenders: list[Path] = []
    for path in (repo_root / "src" / "repolens").rglob("*.py"):
        if "data/schemas" in path.as_posix():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _sets_delivery_state_to_not_delivered(tree):
            offenders.append(path.relative_to(repo_root))

    assert offenders == [Path("src/repolens/presence/defaults.py")]


def _sets_delivery_state_to_not_delivered(tree: ast.AST) -> bool:
    not_delivered_names = _names_assigned_not_delivered(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _assignment_sets_delivery_state(
            node.targets,
            node.value,
            not_delivered_names,
        ):
            return True
        if (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and _assignment_sets_delivery_state(
                [node.target],
                node.value,
                not_delivered_names,
            )
        ):
            return True
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "delivery_state" and _is_not_delivered_value(
                    keyword.value,
                    not_delivered_names,
                ):
                    return True
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if _literal_text(key) == "delivery_state" and _is_not_delivered_value(
                    value,
                    not_delivered_names,
                ):
                    return True
    return False


def _names_assigned_not_delivered(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_literal_not_delivered(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
            and _is_literal_not_delivered(node.value)
        ):
            names.add(node.target.id)
    return names


def _assignment_sets_delivery_state(
    targets: list[ast.expr],
    value: ast.expr,
    not_delivered_names: set[str],
) -> bool:
    if not _is_not_delivered_value(value, not_delivered_names):
        return False
    return any(_target_sets_delivery_state(target) for target in targets)


def _target_sets_delivery_state(target: ast.expr) -> bool:
    if isinstance(target, ast.Name):
        return target.id == "delivery_state"
    if isinstance(target, ast.Attribute):
        return target.attr == "delivery_state"
    if isinstance(target, ast.Subscript):
        return _literal_text(target.slice) == "delivery_state"
    return False


def _is_not_delivered_value(node: ast.expr, not_delivered_names: set[str]) -> bool:
    return _is_literal_not_delivered(node) or (
        isinstance(node, ast.Name) and node.id in not_delivered_names
    )


def _is_literal_not_delivered(node: ast.expr) -> bool:
    return _literal_text(node) == "not_delivered"


def _literal_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
