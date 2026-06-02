"""Deterministic tag folds over the records in one dedup group.

All four tags are folded from values already present on the resolved records — P4
infers nothing new (no first-party detection, no new config). See plan §5.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from repolens.data.models import Distribution, Modified, Origin, Scope

_THIRD_PARTY_OSS: Origin = "third-party-oss"
_UNKNOWN = "unknown"


def fold_origin(origins: Iterable[str]) -> Origin:
    """Fold ``tags.origin`` over a group; mixed origins collapse to the conservative value.

    A group that agrees keeps its single value; a mixed group folds to
    ``third-party-oss`` (the disclosure-relevant, more conservative choice). P4 adds no
    name/config inference — it carries forward whatever ``tags.origin`` each record holds.
    """

    unique = set(origins)
    if len(unique) == 1:
        return cast(Origin, next(iter(unique)))
    return _THIRD_PARTY_OSS


def fold_scope(scopes: Iterable[str]) -> Scope:
    """Fold ``tags.scope``: the single agreed value, else ``unknown``."""

    return cast(Scope, _agree_or_unknown(scopes))


def fold_distribution(distributions: Iterable[str]) -> Distribution:
    """Fold ``tags.distribution``: the single agreed value, else ``unknown``."""

    return cast(Distribution, _agree_or_unknown(distributions))


def fold_modified(values: Iterable[Modified]) -> Modified:
    """Fold ``modified``: ``True`` if any record is modified, else ``unknown`` if any is
    unknown, else ``False``."""

    materialized = list(values)
    if any(value is True for value in materialized):
        return True
    if any(value == _UNKNOWN for value in materialized):
        return _UNKNOWN
    return False


def _agree_or_unknown(values: Iterable[str]) -> str:
    unique = set(values)
    if len(unique) == 1:
        return next(iter(unique))
    return _UNKNOWN
