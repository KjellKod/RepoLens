"""Shortlist stage orchestration: ingest human ticks, run the agent, verify, write back.

This is the one home for the P5 ``shortlist`` stage. Per run it:

1. Reads the schema-validated ``shortlist.json`` ``flag`` produced (``data.store``).
2. Ingests human checkbox decisions from the existing ``shortlist.md`` and records
   ``status`` / ``decided_by`` / ``decided_at`` on the matching ``open`` items (A2, AC 6).
3. For each still-``open`` item: pre-screens its content (cap/normalize/screen/wrap); a
   flagged item routes to the human queue and the agent is **never invoked** (AC 4). Clean
   content goes to the injected ``AgentClient`` (one isolated invocation per item, AC 3).
4. Verifies any agent proposal by re-fetching the cited evidence URL through the SSRF-guarded
   client and confirming the exact SPDX anchor (AC 2). A verified proposal sets
   ``candidate_spdx`` + ``evidence.source_layer="agent"`` but **stays ``open`` until a human
   ticks it** — the agent proposes, the human disposes (ratified decision A5).
5. Recomputes ``open_count`` and writes ``shortlist.json`` (token-redacted by the store) and
   ``shortlist.md`` (token-redacted before the byte write), then reports the open count so the
   CLI maps ``open_count > 0`` to ``FINDINGS_OPEN`` (AC 1).

Per-item content source (finding arb-it1-2): ``shortlist.json`` carries no clone path nor raw
license bytes, so per-item LICENSE/README/description text is supplied by an injectable
``content_loader``. The default loader degrades to the flag-supplied evidence anchor/URL
(no clone re-read in the offline stage); a production wiring may re-read the work-root clone
tree by ``component_ref``. When the loader yields no usable text the item routes to the human
queue ("no_content"). This gives the AC 5 cap behavior a defined input channel.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.data.limits import SCHEMA_VERSION
from repolens.security.http_client import Resolver, fetch_url
from repolens.security.limits import DEFAULT_LIMITS, SecurityLimits
from repolens.security.redaction import redact_tokens
from repolens.resolve.models import FetchFunction
from repolens.shortlist.agent import AgentClient, AgentRequest, Resolution
from repolens.shortlist.decisions import apply_decisions, parse_checkbox_decisions
from repolens.shortlist.prescreen import ItemContent, prescreen_item
from repolens.shortlist.render import render_shortlist_markdown
from repolens.shortlist.verify import verify_agent_resolution

#: Loads per-item untrusted content given the item mapping. Injectable for offline tests.
ContentLoader = Callable[[Mapping[str, Any]], ItemContent]


@dataclass(frozen=True)
class ShortlistResult:
    """Paths and summary for the settled shortlist artifacts."""

    shortlist_json_path: Path
    shortlist_md_path: Path
    open_count: int
    item_count: int
    agent_invocations: int


def _evidence_content_loader(item: Mapping[str, Any]) -> ItemContent:
    """Default loader: degrade to flag-supplied evidence (no clone re-read offline)."""

    evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
    return ItemContent(
        evidence_url=_optional_str(evidence.get("url")),
        evidence_anchor=_optional_str(evidence.get("anchor")),
    )


def run_shortlist(
    work_root: str | Path,
    *,
    agent_client: AgentClient,
    fetcher: FetchFunction = fetch_url,
    evidence_resolver: Resolver | None = None,
    content_loader: ContentLoader = _evidence_content_loader,
    identity: str | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
    now: str | None = None,
) -> ShortlistResult:
    """Settle the flagged items in ``work_root`` and write the artifacts back."""

    root = Path(work_root)
    document = store.read_shortlist(root)
    raw_items = document.get("items", [])
    items: Sequence[Mapping[str, Any]] = raw_items if isinstance(raw_items, list) else []
    timestamp = now or _utc_now()

    # 1. Ingest any human ticks from the existing shortlist.md before touching the agent.
    settled_items = _ingest_human_decisions(root, items, identity=identity, now=timestamp)

    # 2. Run the agent path for items still open.
    resolved_items: list[dict[str, Any]] = []
    agent_invocations = 0
    for item in settled_items:
        record = dict(item)
        if record.get("status") == "open":
            agent_invocations += _resolve_open_item(
                record,
                agent_client=agent_client,
                fetcher=fetcher,
                evidence_resolver=evidence_resolver,
                content_loader=content_loader,
                limits=limits,
            )
        resolved_items.append(record)

    open_count = sum(1 for item in resolved_items if item.get("status") == "open")
    out_document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": timestamp,
        "open_count": open_count,
        "items": resolved_items,
    }

    shortlist_json_path = store.write_shortlist(root, out_document)
    markdown = redact_tokens(render_shortlist_markdown(resolved_items))
    shortlist_md_path = root / "shortlist.md"
    store.atomic_write_bytes(shortlist_md_path, markdown.encode("utf-8"))

    return ShortlistResult(
        shortlist_json_path=shortlist_json_path,
        shortlist_md_path=shortlist_md_path,
        open_count=open_count,
        item_count=len(resolved_items),
        agent_invocations=agent_invocations,
    )


def _ingest_human_decisions(
    root: Path,
    items: Sequence[Mapping[str, Any]],
    *,
    identity: str | None,
    now: str,
) -> list[dict[str, Any]]:
    markdown_path = root / "shortlist.md"
    if not markdown_path.exists():
        return [dict(item) for item in items]
    markdown = markdown_path.read_text(encoding="utf-8", errors="replace")
    decisions = parse_checkbox_decisions(markdown)
    return apply_decisions(items, decisions, identity=identity, now=now)


def _resolve_open_item(
    record: dict[str, Any],
    *,
    agent_client: AgentClient,
    fetcher: FetchFunction,
    evidence_resolver: Resolver | None,
    content_loader: ContentLoader,
    limits: SecurityLimits,
) -> int:
    """Pre-screen, optionally invoke the agent, and verify. Returns the agent call count.

    Mutates ``record`` in place. A verified proposal sets ``candidate_spdx`` +
    ``evidence.source_layer="agent"`` but leaves ``status="open"`` (A5). A flagged item or a
    failed verification annotates ``note`` with the route reason and stays open. The agent is
    invoked at most once and never for flagged content.
    """

    component_ref = str(record.get("component_ref", ""))
    content = content_loader(record)
    outcome = prescreen_item(content, source="shortlist", path=component_ref, limits=limits)
    if not outcome.routed_to_agent:
        record["note"] = outcome.human_reason
        return 0

    assert outcome.wrapped_context is not None  # routed_to_agent guarantees this
    request = AgentRequest(component_ref=component_ref, wrapped_context=outcome.wrapped_context)
    response = agent_client.resolve(request)
    if not isinstance(response, Resolution):
        record["note"] = "agent:abstained"
        return 1

    verified = verify_agent_resolution(
        response, fetcher=fetcher, resolver=evidence_resolver
    )
    if not verified.verified:
        record["note"] = verified.reason
        return 1

    # Agent proposes, human disposes: record the verified candidate but stay open (A5).
    record["candidate_spdx"] = verified.spdx_id
    evidence = dict(record.get("evidence") or {})
    evidence["source_layer"] = "agent"
    if verified.evidence_url:
        evidence["url"] = verified.evidence_url
    if verified.evidence_anchor:
        evidence["anchor"] = verified.evidence_anchor
    record["evidence"] = evidence
    record["note"] = "agent:verified_awaiting_human"
    return 1


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = ["ContentLoader", "ShortlistResult", "run_shortlist"]
