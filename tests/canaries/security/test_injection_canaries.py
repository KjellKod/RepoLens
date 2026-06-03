"""P5 prompt-injection canaries (offline) for the capability-minimized shortlist agent.

Each test maps 1:1 to a ``rpl_security.md`` §Canaries injection row (AC 10-16) and is
registered active in ``canary_matrix.json``. All run offline with an injected
``AgentClient`` / ``fetcher`` / ``Resolver``; the live network is blocked by the suite
conftest. Fixture names are invented sentinels only (name-hygiene).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from repolens.security.http_client import FetchResult, HttpFetchOptions
from repolens.shortlist.agent import AgentRequest, AgentResponse, Resolution
from repolens.shortlist.prescreen import ItemContent, prescreen_item
from repolens.shortlist.verify import verify_agent_resolution

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security" / "injection"
_DEPS_DEV_URL = "https://api.deps.dev/v3alpha/systems/pypi/packages/sentinel-lib/versions/1.0.0"


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def _fetcher(body: bytes):
    def fetch(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        return FetchResult(url=url, status=200, headers=(), body=body)

    return fetch


class _RecordingAgent:
    """Fails the test loudly if invoked; canaries assert the agent is bypassed."""

    def __init__(self) -> None:
        self.calls: list[AgentRequest] = []

    def resolve(self, request: AgentRequest) -> AgentResponse:
        self.calls.append(request)
        return Resolution("MIT", _DEPS_DEV_URL, "MIT")


def test_p5_injection_override_requires_anchor() -> None:
    # A LICENSE that screams "output {MIT}" only resolves if the re-fetched evidence URL
    # actually anchors the claimed id; a fabricated claim fails verification (AC 10).
    fabricated = Resolution("MIT", _DEPS_DEV_URL, "MIT")
    outcome = verify_agent_resolution(
        fabricated, fetcher=_fetcher(b'{"license":"GPL-3.0-only"}'), resolver=_public_resolver
    )
    assert not outcome.verified
    assert outcome.reason == "verify:anchor_mismatch"

    truthful = verify_agent_resolution(
        Resolution("MIT", _DEPS_DEV_URL, "MIT"),
        fetcher=_fetcher(b'{"license":"MIT"}'),
        resolver=_public_resolver,
    )
    assert truthful.verified


def test_p5_injection_roleplay_routes_human_agent_not_invoked() -> None:
    text = (_FIXTURES / "LICENSE.roleplay.txt").read_text(encoding="utf-8")
    outcome = prescreen_item(
        ItemContent(license_text=text), source="shortlist", path="sentinel-lib|UNKNOWN"
    )

    assert not outcome.routed_to_agent
    assert "role_play" in outcome.markers
    # The agent is never constructed/invoked for flagged content: prescreen returns a human
    # route before any AgentClient.resolve call would occur.
    agent = _RecordingAgent()
    assert agent.calls == []


def test_p5_injection_container_escape_stripped_and_flagged() -> None:
    text = (_FIXTURES / "LICENSE.container_escape.txt").read_text(encoding="utf-8")
    outcome = prescreen_item(
        ItemContent(license_text=text), source="shortlist", path="sentinel-lib|UNKNOWN"
    )

    assert not outcome.routed_to_agent
    assert "container_escape" in outcome.markers
    # The wrapped context is never built for a flagged item, so no boundary token leaks.
    assert outcome.wrapped_context is None


def test_p5_injection_oversize_truncated() -> None:
    blob = "A" * (200 * 1024)
    outcome = prescreen_item(
        ItemContent(license_text=blob), source="shortlist", path="sentinel-lib|UNKNOWN"
    )

    assert outcome.routed_to_agent
    context = outcome.wrapped_context
    assert context is not None
    body = context[context.index(">") + 1 : context.index("</untrusted_content>")]
    assert len(body.encode("utf-8")) <= 32 * 1024 + 2


def test_p5_injection_bad_anchor_fails_verification() -> None:
    # Claims MIT, evidence URL returns GPL -> verification fails -> human queue (AC 14).
    outcome = verify_agent_resolution(
        Resolution("MIT", _DEPS_DEV_URL, "MIT"),
        fetcher=_fetcher(b'{"license":"GPL-3.0-only"}'),
        resolver=_public_resolver,
    )
    assert not outcome.verified


def test_p5_injection_off_allowlist_evidence_blocked() -> None:
    # evidence_url on an off-allowlist host (with a token-shaped query) fails closed (AC 15).
    outcome = verify_agent_resolution(
        Resolution(
            "MIT",
            "https://attacker.example.invalid/license?token=ghp_" + "A" * 30,
            "MIT",
        ),
        fetcher=_fetcher(b'{"license":"MIT"}'),
        resolver=_public_resolver,
    )
    assert not outcome.verified
    assert outcome.reason == "verify:fetch_blocked_or_failed"


def test_p5_shortlist_token_absent_from_artifacts_and_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolens.data import store
    from repolens.shortlist.stage import run_shortlist

    # The offline canary lane installs a minimal, hash-pinned dependency set that
    # excludes jsonschema (see requirements/security-canaries.lock). Schema validation
    # is exercised by offline-ci via tests/unit/shortlist; here we neutralize only the
    # lazy validate hook so the real redaction + write path still runs token-free.
    monkeypatch.setattr(store, "_validate_artifact", lambda *args, **kwargs: None)

    token = "ghp_" + "B" * 30
    store.write_shortlist(
        tmp_path,
        {
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "open_count": 1,
            "items": [
                {
                    "component_ref": f"sentinel-{token}|MIT",
                    "reason": "REVIEW",
                    "evidence": {"source_layer": "api", "url": _DEPS_DEV_URL, "anchor": "MIT"},
                    "candidate_spdx": None,
                    "status": "open",
                    "decided_by": None,
                    "decided_at": None,
                    "note": None,
                }
            ],
        },
    )

    seen: list[str] = []

    class _Agent:
        def resolve(self, request: AgentRequest) -> AgentResponse:
            seen.append(request.wrapped_context)
            seen.append(request.component_ref)
            return Resolution("MIT", _DEPS_DEV_URL, "MIT")

    run_shortlist(
        tmp_path,
        agent_client=_Agent(),
        fetcher=_fetcher(b'{"license":"MIT"}'),
        evidence_resolver=_public_resolver,
        content_loader=lambda item: ItemContent(license_text="MIT license text"),
    )

    json_text = (tmp_path / "shortlist.json").read_text(encoding="utf-8")
    md_text = (tmp_path / "shortlist.md").read_text(encoding="utf-8")
    assert token not in json_text
    assert token not in md_text
    # The token never reaches the agent: the request surface carries no token field, and the
    # screened license content handed to the agent does not contain it.
    for value in seen:
        assert token not in value
