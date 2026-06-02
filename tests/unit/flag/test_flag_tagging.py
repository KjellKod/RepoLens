from __future__ import annotations

from repolens.flag.tagging import fold_distribution, fold_modified, fold_origin, fold_scope


def test_scope_distribution_fold_to_unknown_when_mixed() -> None:
    assert fold_scope(["runtime", "runtime"]) == "runtime"
    assert fold_scope(["runtime", "dev"]) == "unknown"
    assert fold_distribution(["server", "server"]) == "server"
    assert fold_distribution(["server", "client-or-mobile"]) == "unknown"


def test_origin_tie_break_prefers_third_party_oss() -> None:
    assert fold_origin(["third-party-oss", "first-party"]) == "third-party-oss"


def test_origin_folds_from_tags_only() -> None:
    # A group whose records all carry the same origin folds to that origin — no inference.
    assert fold_origin(["third-party-oss", "third-party-oss"]) == "third-party-oss"
    assert fold_origin(["first-party"]) == "first-party"


def test_modified_fold_rules() -> None:
    assert fold_modified([False, True]) is True
    assert fold_modified([False, "unknown"]) == "unknown"
    assert fold_modified([False, False]) is False
