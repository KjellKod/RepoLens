from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from repolens.config import Config
from repolens.data.errors import ArtifactExistsError
from repolens.data.store import read_discovered
from repolens.discovery.gh import GhRunResult
from repolens.discovery.pipeline import run_discover


def test_discover_pipeline_writes_approval_artifacts_with_mocked_gh(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        commands.append(list(command))
        return GhRunResult(
            0,
            json.dumps(
                [
                    {
                        "name": "sentinel-explicit",
                        "nameWithOwner": "sentinel-owner/sentinel-explicit",
                        "description": "[bad](javascript:alert(1))",
                        "url": "https://example.invalid/sentinel-explicit",
                        "isArchived": False,
                        "isPrivate": False,
                        "repositoryTopics": [{"name": "runtime"}],
                    },
                    {
                        "name": "sentinel-archived",
                        "nameWithOwner": "sentinel-owner/sentinel-archived",
                        "description": "archived fixture",
                        "url": "https://example.invalid/sentinel-archived",
                        "isArchived": True,
                        "isPrivate": True,
                        "repositoryTopics": [],
                    },
                    {
                        "name": "sentinel-dead",
                        "nameWithOwner": "sentinel-owner/sentinel-dead",
                        "description": "ghp_" + "a" * 20,
                        "url": "https://example.invalid/sentinel-dead",
                        "isArchived": False,
                        "isPrivate": False,
                        "repositoryTopics": [],
                    },
                ]
            ),
            "",
        )

    config = Config(
        values={
            "discover": {
                "taxonomy": {
                    "default_category": "default-bucket",
                    "explicit": {"sentinel-owner/sentinel-explicit": "explicit-bucket"},
                    "topics": {"runtime": "topic-bucket"},
                    "dead": {"sentinel-dead": "retired by local approval"},
                }
            }
        },
        sources=(),
    )

    result = run_discover(
        owner="sentinel-owner",
        work_root=tmp_path,
        config=config,
        runner=runner,
        generated_at="2026-01-01T00:00:00Z",
    )

    assert commands[0][:4] == ["gh", "repo", "list", "sentinel-owner"]
    assert result.repository_count == 3
    assert result.candidate_count == 1
    assert result.hard_exclusion_count == 2

    discovered = read_discovered(tmp_path)
    assert discovered["repositories"][0]["category"] == "explicit-bucket"
    assert discovered["repositories"][1]["exclusion_reason"] == "archived by GitHub"
    assert discovered["repositories"][2]["exclusion_reason"] == "retired by local approval"

    approval = (tmp_path / "repos.candidate.md").read_text(encoding="utf-8")
    assert "sentinel-owner/sentinel-explicit" in approval
    assert "retired by local approval" in approval
    assert "javascript:" not in approval
    assert "ghp_" not in approval
    assert len(approval.encode("utf-8")) < 1_048_576

    # A rerun without explicit force must not clobber the human approval artifact.
    with pytest.raises(ArtifactExistsError, match="--force"):
        run_discover(
            owner="sentinel-owner",
            work_root=tmp_path,
            config=config,
            runner=runner,
            generated_at="2026-01-02T00:00:00Z",
        )
    assert read_discovered(tmp_path)["generated_at"] == "2026-01-01T00:00:00Z"

    # Concrete forced rerun smoke: the same command boundary can overwrite both artifacts.
    rerun = run_discover(
        owner="sentinel-owner",
        work_root=tmp_path,
        config=config,
        runner=runner,
        generated_at="2026-01-02T00:00:00Z",
        force_candidate=True,
    )
    assert rerun.discovered_path == result.discovered_path
    assert read_discovered(tmp_path)["generated_at"] == "2026-01-02T00:00:00Z"


def test_discover_pipeline_fetch_path_uses_only_named_repos(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        commands.append(list(command))
        name = command[3].split("/", 1)[1]
        return GhRunResult(
            0,
            json.dumps(
                {
                    "name": name,
                    "nameWithOwner": f"sentinel-owner/{name}",
                    "description": "fixture repo",
                    "url": f"https://example.invalid/{name}",
                    "isArchived": False,
                    "isPrivate": False,
                    "repositoryTopics": [{"name": "runtime"}],
                }
            ),
            "",
        )

    config = Config(values={}, sources=())

    result = run_discover(
        owner="sentinel-owner",
        work_root=tmp_path,
        config=config,
        repos=("sentinel-alpha", "sentinel-beta"),
        runner=runner,
        generated_at="2026-01-01T00:00:00Z",
    )

    # One `gh repo view` per name, input order preserved.
    assert [cmd[:4] for cmd in commands] == [
        ["gh", "repo", "view", "sentinel-owner/sentinel-alpha"],
        ["gh", "repo", "view", "sentinel-owner/sentinel-beta"],
    ]
    assert result.repository_count == 2

    discovered = read_discovered(tmp_path)
    names = {repo["name"] for repo in discovered["repositories"]}
    assert names == {"sentinel-alpha", "sentinel-beta"}

    approval = (tmp_path / "repos.candidate.md").read_text(encoding="utf-8")
    assert "sentinel-owner/sentinel-alpha" in approval
    assert "sentinel-owner/sentinel-beta" in approval
