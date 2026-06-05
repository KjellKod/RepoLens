from __future__ import annotations

import pytest

from repolens.config import Config
from repolens.discovery.models import GhRepository
from repolens.discovery.taxonomy import (
    categorize_repositories,
    categorize_repository,
    taxonomy_from_config,
)
from repolens.exit_codes import InputError


def repo(
    name: str,
    *,
    topics: tuple[str, ...] = (),
    archived: bool = False,
) -> GhRepository:
    return GhRepository(
        name=name,
        name_with_owner=f"sentinel-owner/{name}",
        url=f"https://example.invalid/{name}",
        description="",
        topics=topics,
        archived=archived,
        private=False,
    )


def taxonomy_config() -> Config:
    return Config(
        values={
            "discover": {
                "taxonomy": {
                    "default_category": "default-bucket",
                    "explicit": {"sentinel-owner/sentinel-explicit": "explicit-bucket"},
                    "patterns": [{"glob": "tool-*", "category": "pattern-bucket"}],
                    "topics": {"runtime": "topic-bucket"},
                    "exclude_patterns": [{"glob": "internal-*", "reason": "internal-only repo"}],
                    "dead": {"sentinel-dead": "retired by local approval"},
                }
            }
        },
        sources=(),
    )


def test_taxonomy_precedence_explicit_pattern_topic_default() -> None:
    taxonomy = taxonomy_from_config(taxonomy_config())

    categorized = categorize_repositories(
        [
            repo("sentinel-explicit", topics=("runtime",)),
            repo("tool-alpha", topics=("runtime",)),
            repo("sentinel-topic", topics=("runtime",)),
            repo("sentinel-default"),
        ],
        taxonomy,
    )

    assert [item.category for item in categorized] == [
        "explicit-bucket",
        "pattern-bucket",
        "topic-bucket",
        "default-bucket",
    ]
    assert categorized[0].category_source.startswith("explicit:")


def test_categories_do_not_hard_exclude() -> None:
    taxonomy = taxonomy_from_config(taxonomy_config())

    categorized = categorize_repository(repo("tool-alpha"), taxonomy)

    assert categorized.category == "pattern-bucket"
    assert categorized.hard_excluded is False


def test_exclude_patterns_hard_exclude_with_visible_reason() -> None:
    taxonomy = taxonomy_from_config(taxonomy_config())

    categorized = categorize_repository(repo("internal-api"), taxonomy)

    assert categorized.category == "default-bucket"
    assert categorized.hard_exclusion_reason == "internal-only repo"


def test_archived_and_dead_repos_get_visible_hard_exclusion_reasons() -> None:
    taxonomy = taxonomy_from_config(taxonomy_config())

    archived = categorize_repository(repo("sentinel-archived", archived=True), taxonomy)
    dead = categorize_repository(repo("sentinel-dead"), taxonomy)

    assert archived.hard_exclusion_reason == "archived by GitHub"
    assert dead.hard_exclusion_reason == "retired by local approval"


def test_invalid_taxonomy_config_rejected() -> None:
    config = Config(values={"discover": {"taxonomy": {"patterns": "bad"}}}, sources=())

    with pytest.raises(InputError, match="patterns"):
        taxonomy_from_config(config)


def test_invalid_exclude_pattern_config_rejected() -> None:
    config = Config(
        values={"discover": {"taxonomy": {"exclude_patterns": [{"glob": "internal-*"}]}}},
        sources=(),
    )

    with pytest.raises(InputError, match="exclude_patterns"):
        taxonomy_from_config(config)
