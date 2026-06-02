"""Typed records for the discover stage."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GhRepository:
    """Repository metadata returned by ``gh repo list``."""

    name: str
    name_with_owner: str
    url: str
    description: str
    topics: tuple[str, ...]
    archived: bool
    private: bool


@dataclass(frozen=True)
class CategorizedRepository:
    """A discovered repository plus local taxonomy classification."""

    repo: GhRepository
    category: str
    category_source: str
    hard_exclusion_reason: str | None = None

    @property
    def hard_excluded(self) -> bool:
        return self.hard_exclusion_reason is not None
