from __future__ import annotations

import pytest

from repolens.exit_codes import InputError
from repolens.report.categories import build_category_index, route_occurrences


def test_category_join_hits_name_key() -> None:
    index = build_category_index(_discovered_repo(name="acme-alpha", category="runtime"))

    category, missing = _category(index, "acme-alpha")

    assert category == "runtime"
    assert missing is False


def test_category_join_hits_name_with_owner_key() -> None:
    index = build_category_index(
        _discovered_repo(
            name="alpha",
            name_with_owner="acme/alpha",
            category="customer-facing",
        )
    )

    category, missing = _category(index, "acme/alpha")

    assert category == "customer-facing"
    assert missing is False


def test_category_join_rejects_conflicting_keys() -> None:
    discovered = {
        "repositories": [
            _repo(name="shared", name_with_owner="acme/shared", category="runtime"),
            _repo(name="other", name_with_owner="shared", category="tools"),
        ]
    }

    with pytest.raises(InputError, match="conflicting category mapping"):
        build_category_index(discovered)


def test_missing_category_uses_default_and_records_gap() -> None:
    split = route_occurrences(
        [_record(repo="unknown-repo")],
        category_index={},
        selection=("uncategorized",),
        default_category="uncategorized",
    )

    assert len(split.main_records) == 1
    assert split.main_records[0].extra_coverage_gaps == ("missing_category",)


def test_included_and_excluded_categories_split() -> None:
    index = build_category_index(
        {
            "repositories": [
                _repo(name="acme-alpha", category="runtime"),
                _repo(name="acme-beta", category="tools"),
            ]
        }
    )

    split = route_occurrences(
        [_record(repo="acme-alpha"), _record(repo="acme-beta")],
        category_index=index,
        selection=("runtime",),
        default_category="uncategorized",
    )

    assert [record.record["repo"] for record in split.main_records] == ["acme-alpha"]
    assert [record.record["repo"] for record in split.appendix_records_by_label["tools"]] == [
        "acme-beta"
    ]


def test_first_party_routes_to_first_party_appendix_even_when_category_included() -> None:
    index = build_category_index(_discovered_repo(name="acme-alpha", category="runtime"))

    split = route_occurrences(
        [_record(repo="acme-alpha", origin="first-party")],
        category_index=index,
        selection=("runtime",),
        default_category="uncategorized",
    )

    assert split.main_records == ()
    assert split.appendix_records_by_label["first-party"][0].record["repo"] == "acme-alpha"


def _category(index: dict[str, str], repo: str) -> tuple[str, bool]:
    from repolens.report.categories import category_for_repo

    return category_for_repo(repo, index, "uncategorized")


def _discovered_repo(
    *,
    name: str,
    category: str,
    name_with_owner: str | None = None,
) -> dict[str, object]:
    return {"repositories": [_repo(name=name, name_with_owner=name_with_owner, category=category)]}


def _repo(
    *,
    name: str,
    category: str,
    name_with_owner: str | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "name_with_owner": name_with_owner or f"acme/{name}",
        "category": category,
    }


def _record(*, repo: str, origin: str = "third-party-oss") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "name": "acme-lib",
        "version": "1.0.0",
        "repo": repo,
        "evidence": {"source_layer": "syft"},
        "tags": {"origin": origin, "scope": "runtime", "distribution": "server"},
        "modified": "unknown",
    }
