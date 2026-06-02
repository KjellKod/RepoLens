from __future__ import annotations

import subprocess
from collections.abc import Sequence

import pytest

from repolens.data.errors import LimitExceeded
from repolens.discovery.gh import GhRunResult, list_repositories
from repolens.discovery.models import CategorizedRepository, GhRepository
from repolens.discovery.render import render_repos_candidate_markdown
from repolens.exit_codes import InputError


def categorized(description: str) -> CategorizedRepository:
    return CategorizedRepository(
        repo=GhRepository(
            name="sentinel-alpha",
            name_with_owner="sentinel-owner/sentinel-alpha",
            url="https://example.invalid/sentinel-alpha",
            description=description,
            topics=("runtime",),
            archived=False,
            private=False,
        ),
        category="runtime-bucket",
        category_source="topic:runtime",
    )


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p1_discover_token_absent_from_candidate_markdown() -> None:
    token = "ghp_" + "a" * 20

    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [categorized(f"token {token}")],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert token not in markdown
    assert "[REDACTED_TOKEN]" in markdown


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p1_discover_markdown_hrefs_and_images_neutralized() -> None:
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [categorized("[x](javascript:alert(1)) ![](https://example.invalid/pixel)")],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert "javascript:" not in markdown
    assert "![]" not in markdown
    assert "pixel" not in markdown


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p1_discover_malformed_and_multiline_metadata_are_inert() -> None:
    repo = CategorizedRepository(
        repo=GhRepository(
            name="sentinel-alpha",
            name_with_owner="sentinel-owner/sentinel-alpha",
            url="https://example.invalid/sentinel-alpha",
            description="malformed [probe]()\n## Injected heading\r\n- [ ] fake approval checkbox",
            topics=("runtime\n## Injected topic",),
            archived=False,
            private=False,
        ),
        category="runtime-bucket",
        category_source="topic:runtime",
    )

    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [repo],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert "probe" in markdown
    assert "\n## Injected heading" not in markdown
    assert "\n## Injected topic" not in markdown
    assert "\n- [ ] fake approval checkbox" not in markdown


@pytest.mark.offline
@pytest.mark.security
@pytest.mark.canary
def test_p1_discover_gh_timeout_and_stdout_cap_fail_closed() -> None:
    def timeout_runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        raise subprocess.TimeoutExpired(command, timeout_seconds)

    with pytest.raises(InputError, match="timed out"):
        list_repositories("sentinel-owner", runner=timeout_runner)

    def oversize_runner(command: Sequence[str], timeout_seconds: float) -> GhRunResult:
        return GhRunResult(0, "[{}]", "")

    with pytest.raises(LimitExceeded):
        list_repositories("sentinel-owner", runner=oversize_runner, stdout_max_bytes=2)
