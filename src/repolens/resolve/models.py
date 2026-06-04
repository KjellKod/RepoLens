"""Typed records for the resolve stage."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from repolens.security.http_client import FetchResult, HttpFetchOptions


@dataclass(frozen=True, slots=True)
class PackageFact:
    """Minimal package identity extracted from a Syft SBOM artifact."""

    name: str
    version: str
    package_type: str
    repo: str
    purl: str | None
    declared_license_raw: str | None
    locations: tuple[str, ...] = ()
    declared_version_status: str | None = None


@dataclass(frozen=True, slots=True)
class ApiCandidate:
    """Candidate SPDX resolution returned by an unauthenticated metadata API."""

    spdx_id: str
    evidence_url: str
    evidence_anchor: str


FetchFunction = Callable[[str, HttpFetchOptions], FetchResult]


class ResolveAdapter(Protocol):
    """A deterministic API lookup adapter."""

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        """Return a candidate or ``None`` when the adapter cannot resolve."""


class AdapterFactory(Protocol):
    """Factory used by tests to inject deterministic adapter chains."""

    def __call__(self, fetcher: FetchFunction) -> Iterable[ResolveAdapter]:
        """Build adapters with the supplied fetcher."""


class ScancodeExecutableProvider(Protocol):
    """Return the canonical production ScanCode executable."""

    def __call__(self, work_root: str | Path) -> Path:
        """Return a verified ScanCode executable path."""
