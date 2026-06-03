from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.data import store
from repolens.exit_codes import InputError
from repolens.scan.inputs import load_discover_approved_repo_specs, repo_specs_from_records
from repolens.scan.runner import RepoSpec


def _repo(
    name: str,
    *,
    owner: str = "sentinel-owner",
    hard_excluded: bool = False,
    private: bool = False,
) -> dict[str, object]:
    return {
        "name": name,
        "name_with_owner": f"{owner}/{name}",
        "url": f"https://example.invalid/{owner}/{name}",
        "description": "",
        "topics": [],
        "archived": False,
        "private": private,
        "category": "runtime-bucket",
        "category_source": "default",
        "hard_excluded": hard_excluded,
        "exclusion_reason": "retired by fixture" if hard_excluded else None,
    }


def _write_discovered(work_root: Path, repositories: list[dict[str, object]]) -> None:
    store.write_discovered(
        work_root,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "owner": "sentinel-owner",
            "repository_count": len(repositories),
            "candidate_count": sum(1 for repo in repositories if not repo["hard_excluded"]),
            "hard_exclusion_count": sum(1 for repo in repositories if repo["hard_excluded"]),
            "repositories": repositories,
        },
    )


def _write_candidates(work_root: Path, rows: list[str]) -> None:
    (work_root / "repos.candidate.md").write_text(
        "\n".join(
            [
                "# Repository candidates",
                "",
                "## Candidates",
                "",
                *rows,
                "",
                "## Hard exclusions",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_checked_candidates_become_repo_specs_with_github_clone_urls(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha"), _repo("sentinel-beta")])
    _write_candidates(
        tmp_path,
        [
            "- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)",
            "- [x] `sentinel-owner/sentinel-beta` - category `runtime-bucket` (`default`)",
        ],
    )

    specs = load_discover_approved_repo_specs(tmp_path, RepoSpec)

    assert specs == [
        RepoSpec(
            repo_ref="sentinel-alpha",
            clone_url="https://github.com/sentinel-owner/sentinel-alpha.git",
        ),
        RepoSpec(
            repo_ref="sentinel-beta",
            clone_url="https://github.com/sentinel-owner/sentinel-beta.git",
        ),
    ]


def test_unticked_candidates_are_omitted(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha"), _repo("sentinel-beta")])
    _write_candidates(
        tmp_path,
        [
            "- [ ] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)",
            "- [x] `sentinel-owner/sentinel-beta` - category `runtime-bucket` (`default`)",
        ],
    )

    specs = load_discover_approved_repo_specs(tmp_path, RepoSpec)

    assert specs == [
        RepoSpec(
            repo_ref="sentinel-beta",
            clone_url="https://github.com/sentinel-owner/sentinel-beta.git",
        )
    ]


def test_private_discover_candidates_are_preserved_for_scan_progress(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-private", private=True)])
    _write_candidates(
        tmp_path,
        ["- [x] `sentinel-owner/sentinel-private` - category `runtime-bucket` (`default`)"],
    )

    specs = load_discover_approved_repo_specs(tmp_path, RepoSpec)

    assert specs == [
        RepoSpec(
            repo_ref="sentinel-private",
            clone_url="https://github.com/sentinel-owner/sentinel-private.git",
            private=True,
        )
    ]


def test_explicit_repo_specs_accept_optional_private_flag() -> None:
    specs = repo_specs_from_records(
        [
            {
                "repo_ref": "sentinel-private",
                "clone_url": "https://example.invalid/repo.git",
                "private": True,
            }
        ],
        RepoSpec,
    )

    assert specs == [
        RepoSpec(
            repo_ref="sentinel-private",
            clone_url="https://example.invalid/repo.git",
            private=True,
        )
    ]


def test_hard_excluded_checked_rows_are_not_emitted(tmp_path: Path) -> None:
    _write_discovered(
        tmp_path,
        [_repo("sentinel-alpha"), _repo("sentinel-retired", hard_excluded=True)],
    )
    _write_candidates(
        tmp_path,
        [
            "- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)",
            "- [x] `sentinel-owner/sentinel-retired` - category `runtime-bucket` (`default`)",
        ],
    )

    specs = load_discover_approved_repo_specs(tmp_path, RepoSpec)

    assert specs == [
        RepoSpec(
            repo_ref="sentinel-alpha",
            clone_url="https://github.com/sentinel-owner/sentinel-alpha.git",
        )
    ]


def test_missing_discovered_json_raises_input_error(tmp_path: Path) -> None:
    _write_candidates(
        tmp_path,
        ["- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)"],
    )

    with pytest.raises(InputError, match="discovered.json not found"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_empty_discovered_json_raises_input_error(tmp_path: Path) -> None:
    (tmp_path / "discovered.json").write_text("", encoding="utf-8")
    _write_candidates(
        tmp_path,
        ["- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)"],
    )

    with pytest.raises(InputError, match="discovered.json is not usable"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_discovered_json_without_repositories_raises_input_error(tmp_path: Path) -> None:
    (tmp_path / "discovered.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "owner": "sentinel-owner",
                "repository_count": 0,
                "candidate_count": 0,
                "hard_exclusion_count": 0,
                "repositories": [],
            }
        ),
        encoding="utf-8",
    )
    _write_candidates(tmp_path, [])

    with pytest.raises(InputError, match="at least one repository"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_zero_checked_candidates_uses_required_error_message(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha")])
    _write_candidates(
        tmp_path,
        ["- [ ] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)"],
    )

    with pytest.raises(InputError, match="^no repos checked in repos.candidate.md$"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_unknown_checked_candidate_raises_input_error(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha")])
    _write_candidates(
        tmp_path,
        ["- [x] `sentinel-owner/sentinel-missing` - category `runtime-bucket` (`default`)"],
    )

    with pytest.raises(InputError, match="checked repo not found"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_duplicate_checked_candidate_raises_input_error(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha")])
    row = "- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)"
    _write_candidates(tmp_path, [row, row])

    with pytest.raises(InputError, match="duplicate checked repo"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_malformed_checkbox_row_raises_input_error(tmp_path: Path) -> None:
    _write_discovered(tmp_path, [_repo("sentinel-alpha")])
    _write_candidates(tmp_path, ["- [x] sentinel-owner/sentinel-alpha"])

    with pytest.raises(InputError, match="malformed candidate checkbox row"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_invalid_discovered_repo_name_is_rejected_before_clone_url_derivation(
    tmp_path: Path,
) -> None:
    repository = _repo("sentinel-alpha")
    repository["name_with_owner"] = ""
    (tmp_path / "discovered.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "owner": "sentinel-owner",
                "repository_count": 1,
                "candidate_count": 1,
                "hard_exclusion_count": 0,
                "repositories": [repository],
            }
        ),
        encoding="utf-8",
    )
    _write_candidates(
        tmp_path,
        ["- [x] `sentinel-owner/sentinel-alpha` - category `runtime-bucket` (`default`)"],
    )

    with pytest.raises(InputError, match="discovered.json is not usable"):
        load_discover_approved_repo_specs(tmp_path, RepoSpec)


def test_repo_spec_validation_rejects_non_https_clone_url() -> None:
    with pytest.raises(InputError, match="needs an https 'clone_url'"):
        repo_specs_from_records(
            [{"repo_ref": "sentinel-alpha", "clone_url": "http://example.invalid/repo.git"}],
            RepoSpec,
        )


def test_repo_spec_validation_rejects_credentialed_clone_url() -> None:
    with pytest.raises(InputError, match="must not embed credentials"):
        repo_specs_from_records(
            [
                {
                    "repo_ref": "sentinel-alpha",
                    "clone_url": "https://user:secret@example.invalid/repo.git",
                }
            ],
            RepoSpec,
        )
