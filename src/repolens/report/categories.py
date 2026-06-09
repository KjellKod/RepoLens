"""Category join and occurrence-level report routing."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from repolens.exit_codes import InputError
from repolens.presence.sections import MONITOR_APPENDIX_LABEL, routes_to_monitor_appendix

FIRST_PARTY_APPENDIX = "first-party"
BUILD_CI_APPENDIX = "build-ci"
NOT_CURRENTLY_DELIVERED_APPENDIX = MONITOR_APPENDIX_LABEL
MISSING_CATEGORY_GAP = "missing_category"


@dataclass(frozen=True)
class RoutedRecord:
    """A resolved occurrence plus routing-only coverage metadata."""

    record: dict[str, Any]
    extra_coverage_gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReportSplit:
    """Resolved occurrences partitioned before report aggregation."""

    main_records: tuple[RoutedRecord, ...]
    appendix_records_by_label: Mapping[str, tuple[RoutedRecord, ...]]


def build_category_index(discovered: Mapping[str, object]) -> dict[str, str]:
    """Index discovered repositories by exact trimmed name and name_with_owner."""

    raw_repositories = discovered.get("repositories", [])
    if not isinstance(raw_repositories, list):
        raise InputError("discovered.repositories must be an array")

    index: dict[str, str] = {}
    for position, raw_repo in enumerate(raw_repositories):
        if not isinstance(raw_repo, Mapping):
            raise InputError(f"discovered.repositories[{position}] must be an object")
        category = _required_text(
            raw_repo.get("category"),
            f"discovered.repositories[{position}].category",
        )
        for key_name in ("name", "name_with_owner"):
            key = _normalized_key(raw_repo.get(key_name))
            if not key:
                raise InputError(
                    f"discovered.repositories[{position}].{key_name} must be non-empty"
                )
            existing = index.get(key)
            if existing is not None and existing != category:
                raise InputError(f"conflicting category mapping for repository key {key!r}")
            index[key] = category
    return index


def category_for_repo(repo: object, index: Mapping[str, str], default: str) -> tuple[str, bool]:
    """Return the category for a resolved repo and whether the discovered join missed."""

    key = _normalized_key(repo)
    if key and key in index:
        return index[key], False
    return default, True


def route_occurrences(
    records: Iterable[dict[str, Any]],
    category_index: Mapping[str, str],
    selection: Sequence[str] | None,
    default_category: str,
) -> ReportSplit:
    """Partition resolved occurrences into main and appendix buckets."""

    included_categories = None if selection is None else set(selection)
    main_records: list[RoutedRecord] = []
    appendix_records: dict[str, list[RoutedRecord]] = {}

    for record in records:
        category, missing_category = category_for_repo(
            record.get("repo"),
            category_index,
            default_category,
        )
        extra_gaps = (MISSING_CATEGORY_GAP,) if missing_category else ()
        routed = RoutedRecord(record=dict(record), extra_coverage_gaps=extra_gaps)

        tags = record.get("tags")
        if not isinstance(tags, Mapping):
            raise InputError("resolved record tags must be an object")
        origin = str(tags.get("origin"))
        scope = str(tags.get("scope"))
        distribution = str(tags.get("distribution"))
        if scope == "build" and distribution == "not-distributed":
            appendix_records.setdefault(BUILD_CI_APPENDIX, []).append(routed)
        elif origin == "first-party":
            appendix_records.setdefault(FIRST_PARTY_APPENDIX, []).append(routed)
        elif routes_to_monitor_appendix(record.get("presence")):
            appendix_records.setdefault(NOT_CURRENTLY_DELIVERED_APPENDIX, []).append(routed)
        elif included_categories is None or category in included_categories:
            main_records.append(routed)
        else:
            appendix_records.setdefault(category, []).append(routed)

    return ReportSplit(
        main_records=tuple(main_records),
        appendix_records_by_label={
            label: tuple(items)
            for label, items in sorted(
                appendix_records.items(),
                key=lambda item: (item[0].casefold(), item[0]),
            )
        },
    )


def _normalized_key(value: object) -> str:
    return str(value).strip()


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label} must be a non-empty string")
    return value.strip()
