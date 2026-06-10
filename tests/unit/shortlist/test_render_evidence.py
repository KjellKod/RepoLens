from __future__ import annotations

from repolens.shortlist.contexts import ShortlistMetadata, TriageMetadata
from repolens.shortlist.render import render_shortlist_markdown

_SECTION_HEADERS = (
    "DELIVERED / SHIPPED - ACTION REQUIRED",
    "INSTALLED BUT DELIVERY NOT CONFIRMED - REVIEW",
    "LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR",
    "DELIVERY ARTIFACT NOT SCANNED - UNKNOWN",
)

_PYPI_URL = "https://pypi.org/pypi/acme-lib/1.2.3/json"
_GITHUB_URL = "https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3"


def _metadata() -> ShortlistMetadata:
    return ShortlistMetadata(
        triage_by_ref={
            "acme-lib|UNKNOWN": TriageMetadata(
                spdx_id="UNKNOWN",
                tier="UNKNOWN",
                origin="third-party",
                scope="runtime",
                distribution="shipped",
                evidence_url=None,
                evidence_anchor=None,
                found_in=("sentinel-alpha",),
            )
        }
    )


def _item(research_evidence: dict[str, object]) -> dict[str, object]:
    return {
        "component_ref": "acme-lib|UNKNOWN",
        "reason": "UNKNOWN",
        "evidence": {"source_layer": "api", "url": _PYPI_URL, "anchor": "UNKNOWN"},
        "candidate_spdx": None,
        "status": "open",
        "decided_by": None,
        "decided_at": None,
        "note": None,
        "research_evidence": research_evidence,
    }


def test_render_researched_browser_evidence_as_markdown_links() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "pending_verifier_support",
                    "machine_verification": "pending_verifier_support",
                    "lookups_attempted": ["PyPI metadata"],
                    "likely_spdx": "MIT",
                    "browser_evidence": [
                        {"label": "PyPI metadata", "url": _PYPI_URL, "source_type": "pypi"}
                    ],
                }
            )
        ],
        metadata=_metadata(),
    )

    assert "[PyPI metadata](https://pypi.org/pypi/acme-lib/1.2.3/json)" in markdown
    assert "found in `sentinel-alpha`" in markdown
    assert "machine verification: `pending_verifier_support`" in markdown


def test_render_multiple_evidence_links_comma_separated() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "pending_verifier_support",
                    "machine_verification": "pending_verifier_support",
                    "lookups_attempted": ["PyPI metadata", "GitHub license API"],
                    "likely_spdx": "MIT",
                    "browser_evidence": [
                        {"label": "PyPI metadata", "url": _PYPI_URL, "source_type": "pypi"},
                        {
                            "label": "GitHub license API",
                            "url": _GITHUB_URL,
                            "source_type": "github_license_api",
                        },
                    ],
                }
            )
        ],
        metadata=_metadata(),
    )

    assert (
        "[PyPI metadata](https://pypi.org/pypi/acme-lib/1.2.3/json), "
        "[GitHub license API](https://api.github.com/repos/sentinel/acme-lib/license?ref=1.2.3)"
    ) in markdown


def test_render_no_public_evidence_lookup_trail() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "no_public_evidence",
                    "machine_verification": "no_public_evidence",
                    "lookups_attempted": ["PyPI metadata", "GitHub license API"],
                }
            )
        ],
        metadata=_metadata(),
    )

    assert "looked up: `PyPI metadata`, `GitHub license API`" in markdown
    assert "machine verification: `no_public_evidence`" in markdown


def test_render_external_candidate_as_human_review_correction() -> None:
    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": "1.2.3",
                    "ecosystem": "swiftpm",
                    "found_in": ["sentinel-alpha"],
                    "outcome": "pending_verifier_support",
                    "machine_verification": "pending_verifier_support",
                    "lookups_attempted": ["GitHub license API"],
                    "likely_spdx": "MIT",
                    "human_candidate_spdx": "MIT",
                    "browser_evidence": [
                        {
                            "label": "GitHub license API",
                            "url": _GITHUB_URL,
                            "source_type": "github_license_api",
                            "anchor": "MIT",
                        }
                    ],
                    "source_repo": {
                        "host": "github.com",
                        "owner": "sentinel",
                        "repo": "acme-lib",
                        "ref": "1.2.3",
                        "ref_kind": "version",
                        "provenance": "external_candidate",
                        "provenance_detail": "triage_evidence_url",
                        "bound_to_package": False,
                    },
                }
            )
        ],
        metadata=_metadata(),
    )

    assert "`acme-lib|UNKNOWN` -&gt; `MIT`" in markdown
    assert "external source candidate `sentinel/acme-lib`" in markdown
    assert "machine verification: `pending_verifier_support`" in markdown


_DEFAULT_BRANCH_BLOB = "https://github.com/sentinel/acme-lib/blob/HEAD/LICENSE"
_PINNED_BLOB = "https://github.com/sentinel/acme-lib/blob/1.2.3/LICENSE"


def test_render_verified_github_default_branch_shows_clickable_license_link() -> None:
    """#23a — the unpinned default-branch row gets a trusted bold prefix + emoji label."""

    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "verify:exact_anchor_default_branch",
                    "machine_verification": "verified",
                    "browser_evidence": [
                        {
                            "label": (
                                "🔎 GitHub license (MIT · default branch, not version-pinned)"
                            ),
                            "url": _DEFAULT_BRANCH_BLOB,
                            "source_type": "github_license_api_default_branch",
                            "anchor": "MIT",
                        }
                    ],
                }
            )
        ],
        metadata=_metadata(),
    )

    # The bold **review:** prefix is emitted by trusted render code OUTSIDE the link label,
    # so it is not escaped; it sits immediately before the markdown link.
    assert "**review:** [🔎 GitHub license " in markdown
    assert f"]({_DEFAULT_BRANCH_BLOB})" in markdown
    # The caveat rides in the (escaped) visible label as plain Unicode.
    assert "default branch, not version" in markdown
    assert "🔎" in markdown
    # The verifier cell is populated (not blank/None) and carries the distinct reason.
    assert "machine verification: `verified`" in markdown
    assert "outcome: `verify:exact_anchor_default_branch`" in markdown


def test_render_pinned_github_license_link_has_no_review_prefix() -> None:
    """#23b — a pinned row renders the clean label with NO prefix, NO emoji, NO caveat."""

    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "verify:exact_anchor",
                    "machine_verification": "verified",
                    "browser_evidence": [
                        {
                            "label": "GitHub license (MIT)",
                            "url": _PINNED_BLOB,
                            "source_type": "github_license_api",
                            "anchor": "MIT",
                        }
                    ],
                }
            )
        ],
        metadata=_metadata(),
    )

    assert "[GitHub license " in markdown
    assert f"]({_PINNED_BLOB})" in markdown
    assert "**review:**" not in markdown
    assert "🔎" not in markdown
    assert "default branch" not in markdown
    assert "outcome: `verify:exact_anchor`" in markdown


def test_render_borrowed_source_type_without_verified_outcome_has_no_review_prefix() -> None:
    """Forgery guard — an ingested-style row that borrows the trusted default-branch
    source_type but does NOT carry the integrity-protected verify outcome
    (``verify:exact_anchor_default_branch`` + ``machine_verification=="verified"``) must
    NOT receive the bold **review:** prefix. The verify:* outcomes are rejected by the
    evidence-ingestion allowlist, so an ingested artifact cannot forge them; the render
    gate mirrors that boundary. The link itself still renders (escaped, display-only).
    """

    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    # An ingestible outcome (in evidence._EVIDENCE_OUTCOMES) — NOT the
                    # trusted verify:* outcome that gates the prefix.
                    "outcome": "pending_verifier_support",
                    "machine_verification": "pending_verifier_support",
                    "browser_evidence": [
                        {
                            # Borrows the trusted source_type marker.
                            "label": (
                                "🔎 GitHub license (MIT · default branch, not version-pinned)"
                            ),
                            "url": _DEFAULT_BRANCH_BLOB,
                            "source_type": "github_license_api_default_branch",
                            "anchor": "MIT",
                        }
                    ],
                }
            )
        ],
        metadata=_metadata(),
    )

    # The link still renders (the URL/label are escaped & display-only)...
    assert f"]({_DEFAULT_BRANCH_BLOB})" in markdown
    assert "🔎" in markdown
    # ...but the trusted reviewer signpost is NOT emitted: the row lacks the
    # integrity-protected verify outcome, so the marker cannot be borrowed.
    assert "**review:**" not in markdown


def test_render_dropped_attacker_host_has_no_license_link() -> None:
    """#23c — a row whose lifted URL was dropped carries no browser_evidence link."""

    markdown = render_shortlist_markdown(
        [
            _item(
                {
                    "component_ref": "acme-lib|UNKNOWN",
                    "context_fingerprint": "abc123def456",
                    "package": "acme-lib",
                    "version": None,
                    "ecosystem": None,
                    "found_in": ["sentinel-alpha"],
                    "outcome": "verify:exact_anchor_default_branch",
                    "machine_verification": "verified",
                    "lookups_attempted": ["GitHub license API"],
                }
            )
        ],
        metadata=_metadata(),
    )

    assert "**review:**" not in markdown
    assert "GitHub license (" not in markdown
    assert "looked up: `GitHub license API`" in markdown


def test_render_presence_sections_are_exact_and_ordered() -> None:
    markdown = render_shortlist_markdown(
        [
            {
                **_item({}),
                "component_ref": "delivered-lib|GPL-3.0-only",
                "candidate_spdx": "GPL-3.0-only",
                "presence_section": _SECTION_HEADERS[0],
                "presence": {
                    "install_state": "installed",
                    "delivery_state": "delivered",
                    "relation": "direct",
                    "path": [],
                    "platform_match": "unknown",
                    "source": "syft",
                    "target": "unknown",
                    "reopen_on_delivery_change": True,
                },
            },
            {
                **_item({}),
                "component_ref": "monitor-lib|LGPL-3.0-only",
                "candidate_spdx": "LGPL-3.0-only",
                "presence_section": _SECTION_HEADERS[2],
                "presence": {
                    "install_state": "lockfile_only",
                    "delivery_state": "not_scanned",
                    "relation": "optional",
                    "path": [],
                    "platform_match": "unknown",
                    "source": "syft",
                    "target": "unknown",
                    "reopen_on_delivery_change": True,
                },
            },
        ],
        metadata=ShortlistMetadata(triage_by_ref={}),
    )

    positions = [markdown.index(f"## {header}") for header in _SECTION_HEADERS]
    assert positions == sorted(positions)
    assert [
        line.removeprefix("## ") for line in markdown.splitlines() if line.startswith("## ")
    ] == list(_SECTION_HEADERS)
    assert "delivery: delivered" in markdown
    assert "install: lockfile only" in markdown
