"""RepoLens CLI package."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]


def _package_version() -> str:
    try:
        return version("repolens")
    except PackageNotFoundError:
        try:
            from repolens._version import __version__ as generated_version
        except ModuleNotFoundError:
            return "0+unknown"
        return generated_version


__version__ = _package_version()
