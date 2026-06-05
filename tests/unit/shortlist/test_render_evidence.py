from __future__ import annotations

from repolens.shortlist.contexts import ShortlistMetadata, TriageMetadata
from repolens.shortlist.render import render_shortlist_markdown

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
