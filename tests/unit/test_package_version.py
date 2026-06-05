from __future__ import annotations

import tomllib
from pathlib import Path


def test_package_version_is_derived_from_git_tags() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    project = pyproject["project"]
    assert "version" not in project
    assert project["dynamic"] == ["version"]

    build_requires = pyproject["build-system"]["requires"]
    assert any(requirement.startswith("setuptools-scm") for requirement in build_requires)

    setuptools_scm = pyproject["tool"]["setuptools_scm"]
    assert setuptools_scm["tag_regex"] == r"^(?P<version>\d+\.\d+\.\d+)$"
    assert setuptools_scm["version_scheme"] == "guess-next-dev"
    assert setuptools_scm["local_scheme"] == "no-local-version"
    assert setuptools_scm["version_file"] == "src/repolens/_version.py"
