from __future__ import annotations

from pathlib import Path

import pytest

from repolens.data.errors import ArtifactExistsError, LimitExceeded, SchemaValidationError
from repolens.data.store import read_discovered
from repolens.data.validation import validate_artifact
from repolens.discovery.artifacts import write_discovery_artifacts, write_repos_candidate_md
from repolens.discovery.models import CategorizedRepository, GhRepository
from repolens.discovery.render import build_discovered_payload, render_repos_candidate_markdown


def categorized(
    name: str,
    *,
    category: str = "runtime-bucket",
    description: str = "",
    topics: tuple[str, ...] = (),
    archived: bool = False,
    private: bool = False,
    reason: str | None = None,
) -> CategorizedRepository:
    return CategorizedRepository(
        repo=GhRepository(
            name=name,
            name_with_owner=f"sentinel-owner/{name}",
            url=f"https://example.invalid/{name}",
            description=description,
            topics=topics,
            archived=archived,
            private=private,
        ),
        category=category,
        category_source="default",
        hard_exclusion_reason=reason,
    )


def test_candidate_markdown_marks_private_repos_only() -> None:
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [
            categorized("sentinel-private", private=True),
            categorized("sentinel-public", private=False),
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    private_line = next(
        line for line in markdown.splitlines() if "sentinel-owner/sentinel-private" in line
    )
    public_line = next(
        line for line in markdown.splitlines() if "sentinel-owner/sentinel-public" in line
    )
    assert "private - needs auth to clone" in private_line
    assert "private - needs auth to clone" not in public_line


def test_private_marker_round_trips_through_candidate_parser(tmp_path: Path) -> None:
    from repolens.scan.inputs import _checked_candidate_names

    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [categorized("sentinel-private", private=True)],
        generated_at="2026-01-01T00:00:00Z",
    )
    candidate_path = tmp_path / "repos.candidate.md"
    candidate_path.write_text(markdown, encoding="utf-8")

    # The marker after the source fence must not break the strict checkbox regex.
    assert _checked_candidate_names(candidate_path) == ["sentinel-owner/sentinel-private"]


def test_discovered_payload_validates_counts() -> None:
    payload = build_discovered_payload(
        "sentinel-owner",
        [categorized("sentinel-alpha"), categorized("sentinel-archived", reason="archived")],
        generated_at="2026-01-01T00:00:00Z",
    )

    validate_artifact(payload, "discovered")
    assert payload["repository_count"] == 2
    assert payload["candidate_count"] == 1
    assert payload["hard_exclusion_count"] == 1


def test_discovered_payload_sorts_candidates_then_exclusions_by_category_and_name() -> None:
    payload = build_discovered_payload(
        "sentinel-owner",
        [
            categorized("sentinel-zulu", category="runtime-bucket"),
            categorized("sentinel-retired-zulu", category="legacy-bucket", reason="retired"),
            categorized("Sentinel-Beta", category="ALPHA-bucket"),
            categorized("sentinel-alpha", category="alpha-bucket"),
            categorized("sentinel-retired-alpha", category="legacy-bucket", reason="retired"),
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert [repo["name"] for repo in payload["repositories"]] == [
        "sentinel-alpha",
        "Sentinel-Beta",
        "sentinel-zulu",
        "sentinel-retired-alpha",
        "sentinel-retired-zulu",
    ]


def test_discovered_payload_count_mismatch_rejected() -> None:
    payload = build_discovered_payload(
        "sentinel-owner",
        [categorized("sentinel-alpha")],
        generated_at="2026-01-01T00:00:00Z",
    )
    payload["candidate_count"] = 99

    with pytest.raises(SchemaValidationError, match="candidate_count"):
        validate_artifact(payload, "discovered")


def test_candidate_markdown_defaults_candidates_checked_and_keeps_exclusions_plain() -> None:
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [
            categorized("sentinel-alpha"),
            categorized("sentinel-archived", reason="archived by GitHub"),
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert "Every checked repo below will be scanned" in markdown
    assert "UNTICK to exclude" in markdown
    assert "- [x] `sentinel-owner/sentinel-alpha`" in markdown
    assert "- [ ] `sentinel-owner/sentinel-alpha`" not in markdown
    assert "- `sentinel-owner/sentinel-archived`" in markdown
    assert "- [x] `sentinel-owner/sentinel-archived`" not in markdown
    assert "reason: `archived by GitHub`" in markdown


def test_candidate_markdown_sorts_each_section_by_category_and_name() -> None:
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [
            categorized("sentinel-zulu", category="runtime-bucket"),
            categorized("sentinel-retired-zulu", category="legacy-bucket", reason="retired"),
            categorized("Sentinel-Beta", category="ALPHA-bucket"),
            categorized("sentinel-alpha", category="alpha-bucket"),
            categorized("sentinel-retired-alpha", category="legacy-bucket", reason="retired"),
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert markdown.index("`sentinel-owner/sentinel-alpha`") < markdown.index(
        "`sentinel-owner/Sentinel-Beta`"
    )
    assert markdown.index("`sentinel-owner/Sentinel-Beta`") < markdown.index(
        "`sentinel-owner/sentinel-zulu`"
    )
    assert markdown.index("`sentinel-owner/sentinel-zulu`") < markdown.index("## Hard exclusions")
    assert markdown.index("`sentinel-owner/sentinel-retired-alpha`") < markdown.index(
        "`sentinel-owner/sentinel-retired-zulu`"
    )


def test_candidate_markdown_sanitizes_tokens_hrefs_images_and_descriptions() -> None:
    token = "ghp_" + "a" * 20
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [
            categorized(
                "sentinel-alpha",
                description=f"[x](javascript:alert(1)) ![](https://example.invalid/pixel) {token}",
                topics=("runtime",),
            )
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert token not in markdown
    assert "[REDACTED_TOKEN]" in markdown
    assert "javascript:" not in markdown
    assert "![]" not in markdown
    assert "sentinel-owner/sentinel-alpha" in markdown


def test_malformed_description_link_does_not_abort_approval_artifacts(tmp_path: Path) -> None:
    discovered_path, candidate_path = write_discovery_artifacts(
        tmp_path,
        owner="sentinel-owner",
        repositories=(
            categorized(
                "sentinel-alpha",
                description="malformed [probe]()",
            ),
        ),
        generated_at="2026-01-01T00:00:00Z",
    )

    assert discovered_path.exists()
    assert candidate_path.exists()
    markdown = candidate_path.read_text(encoding="utf-8")
    assert "malformed" in markdown
    assert "probe" in markdown


def test_candidate_markdown_neutralizes_multiline_description_and_topics() -> None:
    markdown = render_repos_candidate_markdown(
        "sentinel-owner",
        [
            categorized(
                "sentinel-alpha",
                description="legit\n## Injected heading\r\n- [ ] fake approval checkbox",
                topics=("runtime\n## Injected topic",),
            )
        ],
        generated_at="2026-01-01T00:00:00Z",
    )

    assert "\n## Injected heading" not in markdown
    assert "\n## Injected topic" not in markdown
    assert "\n- [ ] fake approval checkbox" not in markdown


def test_write_discovery_artifacts_round_trips_json_and_markdown(tmp_path: Path) -> None:
    discovered_path, candidate_path = write_discovery_artifacts(
        tmp_path,
        owner="sentinel-owner",
        repositories=(categorized("sentinel-alpha"),),
        generated_at="2026-01-01T00:00:00Z",
    )

    assert discovered_path == tmp_path / "discovered.json"
    assert candidate_path == tmp_path / "repos.candidate.md"
    assert read_discovered(tmp_path)["repositories"][0]["name"] == "sentinel-alpha"
    assert "Repository candidates" in candidate_path.read_text(encoding="utf-8")


def test_write_discovery_artifacts_refuses_to_overwrite_existing_candidate_md(
    tmp_path: Path,
) -> None:
    candidate_path = tmp_path / "repos.candidate.md"
    candidate_path.write_text("- [x] human selection\n", encoding="utf-8")

    with pytest.raises(ArtifactExistsError, match="--force"):
        write_discovery_artifacts(
            tmp_path,
            owner="sentinel-owner",
            repositories=(categorized("sentinel-alpha"),),
            generated_at="2026-01-01T00:00:00Z",
        )

    assert candidate_path.read_text(encoding="utf-8") == "- [x] human selection\n"
    assert not (tmp_path / "discovered.json").exists()


def test_write_discovery_artifacts_force_overwrites_existing_candidate_md(tmp_path: Path) -> None:
    candidate_path = tmp_path / "repos.candidate.md"
    candidate_path.write_text("- [x] human selection\n", encoding="utf-8")

    write_discovery_artifacts(
        tmp_path,
        owner="sentinel-owner",
        repositories=(categorized("sentinel-alpha"),),
        generated_at="2026-01-01T00:00:00Z",
        force_candidate=True,
    )

    assert "- [x] human selection" not in candidate_path.read_text(encoding="utf-8")
    assert read_discovered(tmp_path)["repositories"][0]["name"] == "sentinel-alpha"


def test_candidate_markdown_cap_rejects_oversize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("repolens.discovery.artifacts.max_bytes_for", lambda name: 32)

    with pytest.raises(LimitExceeded):
        write_repos_candidate_md(
            tmp_path,
            owner="sentinel-owner",
            repositories=(categorized("sentinel-alpha", description="x" * 128),),
            generated_at="2026-01-01T00:00:00Z",
        )
