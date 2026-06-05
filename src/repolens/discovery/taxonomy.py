"""Local taxonomy categorization for discovered repositories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

from repolens.config import Config
from repolens.exit_codes import InputError

from .models import CategorizedRepository, GhRepository

DEFAULT_CATEGORY = "uncategorized"


@dataclass(frozen=True)
class PatternRule:
    glob: str
    category: str


@dataclass(frozen=True)
class ExclusionPatternRule:
    glob: str
    reason: str


@dataclass(frozen=True)
class Taxonomy:
    default_category: str
    explicit: Mapping[str, str]
    patterns: tuple[PatternRule, ...]
    topics: Mapping[str, str]
    exclude_patterns: tuple[ExclusionPatternRule, ...]
    dead: Mapping[str, str]


def taxonomy_from_config(config: Config) -> Taxonomy:
    """Load ``discover.taxonomy`` from local config values."""

    discover = config.values.get("discover", {})
    if discover is None:
        discover = {}
    if not isinstance(discover, Mapping):
        raise InputError("config discover must be an object")
    raw_taxonomy = discover.get("taxonomy", {})
    if raw_taxonomy is None:
        raw_taxonomy = {}
    if not isinstance(raw_taxonomy, Mapping):
        raise InputError("config discover.taxonomy must be an object")

    default_category = _optional_text(raw_taxonomy.get("default_category"), DEFAULT_CATEGORY)
    return Taxonomy(
        default_category=default_category,
        explicit=_string_mapping(raw_taxonomy.get("explicit"), "discover.taxonomy.explicit"),
        patterns=_patterns(raw_taxonomy.get("patterns")),
        topics={
            key.lower(): value
            for key, value in _string_mapping(
                raw_taxonomy.get("topics"), "discover.taxonomy.topics"
            ).items()
        },
        exclude_patterns=_exclude_patterns(raw_taxonomy.get("exclude_patterns")),
        dead=_string_mapping(raw_taxonomy.get("dead"), "discover.taxonomy.dead"),
    )


def categorize_repositories(
    repositories: Sequence[GhRepository],
    taxonomy: Taxonomy,
) -> tuple[CategorizedRepository, ...]:
    """Assign categories and visible hard-exclusion reasons."""

    return tuple(categorize_repository(repo, taxonomy) for repo in repositories)


def categorize_repository(repo: GhRepository, taxonomy: Taxonomy) -> CategorizedRepository:
    category, source = _category_for(repo, taxonomy)
    exclusion_reason = _hard_exclusion_reason(repo, taxonomy)
    return CategorizedRepository(
        repo=repo,
        category=category,
        category_source=source,
        hard_exclusion_reason=exclusion_reason,
    )


def _category_for(repo: GhRepository, taxonomy: Taxonomy) -> tuple[str, str]:
    for key in (repo.name_with_owner, repo.name):
        category = taxonomy.explicit.get(key)
        if category:
            return category, f"explicit:{key}"

    for rule in taxonomy.patterns:
        if fnmatchcase(repo.name, rule.glob) or fnmatchcase(repo.name_with_owner, rule.glob):
            return rule.category, f"pattern:{rule.glob}"

    for topic in repo.topics:
        category = taxonomy.topics.get(topic.lower())
        if category:
            return category, f"topic:{topic}"

    return taxonomy.default_category, "default"


def _hard_exclusion_reason(repo: GhRepository, taxonomy: Taxonomy) -> str | None:
    if repo.archived:
        return "archived by GitHub"
    for key in (repo.name_with_owner, repo.name):
        reason = taxonomy.dead.get(key)
        if reason:
            return reason
    for rule in taxonomy.exclude_patterns:
        if fnmatchcase(repo.name, rule.glob) or fnmatchcase(repo.name_with_owner, rule.glob):
            return rule.reason
    return None


def _patterns(value: object) -> tuple[PatternRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise InputError("config discover.taxonomy.patterns must be an array")

    rules: list[PatternRule] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise InputError(f"config discover.taxonomy.patterns[{index}] must be an object")
        glob = _required_text(item.get("glob"), f"discover.taxonomy.patterns[{index}].glob")
        category = _required_text(
            item.get("category"), f"discover.taxonomy.patterns[{index}].category"
        )
        rules.append(PatternRule(glob=glob, category=category))
    return tuple(rules)


def _exclude_patterns(value: object) -> tuple[ExclusionPatternRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise InputError("config discover.taxonomy.exclude_patterns must be an array")

    rules: list[ExclusionPatternRule] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise InputError(
                f"config discover.taxonomy.exclude_patterns[{index}] must be an object"
            )
        glob = _required_text(item.get("glob"), f"discover.taxonomy.exclude_patterns[{index}].glob")
        reason = _required_text(
            item.get("reason"), f"discover.taxonomy.exclude_patterns[{index}].reason"
        )
        rules.append(ExclusionPatternRule(glob=glob, reason=reason))
    return tuple(rules)


def _string_mapping(value: object, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise InputError(f"config {label} must be an object")
    result: dict[str, str] = {}
    for key, child in value.items():
        if not isinstance(key, str) or not key.strip():
            raise InputError(f"config {label} keys must be non-empty strings")
        result[key] = _required_text(child, f"{label}.{key}")
    return result


def _optional_text(value: object, default: str) -> str:
    if value is None:
        return default
    return _required_text(value, "discover.taxonomy.default_category")


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"config {label} must be a non-empty string")
    return value.strip()
