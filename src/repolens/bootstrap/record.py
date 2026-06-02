"""Write the resolved tool versions to an on-disk artifact (``tool_versions.json``)."""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable, Mapping
from pathlib import Path

from .pins import Pins
from .syft import ResolvedTool

#: Self-describing schema marker so a future F3 store can identify the artifact.
VERSIONS_SCHEMA = "repolens.tool_versions/v1"


def build_versions_payload(
    pins: Pins,
    resolved: Iterable[ResolvedTool],
    *,
    now: _dt.datetime | None = None,
) -> dict:
    """Assemble the tool-versions mapping.

    Every pinned tool appears with ``{version, digest, source}``. Tools that were
    resolved (acquired + verified) carry their measured digest; tools that are
    pinned-only (e.g. ``git``/``gh`` provided by the environment) fall back to the
    manifest's pinned digest so the record is always complete.
    """
    resolved_by_name: Mapping[str, ResolvedTool] = {r.name: r for r in resolved}
    ts = (now or _dt.datetime.now(_dt.UTC)).isoformat()

    tools: dict[str, dict[str, str | None]] = {}
    for name, pin in pins.tools.items():
        res = resolved_by_name.get(name)
        if res is not None:
            digest: str | None = res.digest
            source = res.source
        else:
            # Use the first pinned platform digest as the recorded digest, if any.
            digest = next((pa.sha256 for pa in pin.platforms.values()), None)
            source = pin.source
        tools[name] = {
            "version": pin.version,
            "digest": digest,
            "source": source,
        }

    return {
        "schema": VERSIONS_SCHEMA,
        "generated_at": ts,
        "base_image": pins.base_image,
        "tools": tools,
    }


def write_tool_versions(
    pins: Pins,
    resolved: Iterable[ResolvedTool],
    out_path: Path | str,
    *,
    now: _dt.datetime | None = None,
) -> Path:
    """Write ``tool_versions.json`` and return its path."""
    payload = build_versions_payload(pins, resolved, now=now)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
