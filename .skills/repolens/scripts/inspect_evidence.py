#!/usr/bin/env python3
"""Inspect allowlisted evidence URLs through RepoLens parsing rules."""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from repolens.resolve.adapters import API_ALLOWED_HOSTS, target_license_candidates
from repolens.resolve.models import FetchFunction
from repolens.security.errors import FetchSecurityError
from repolens.security.http_client import HttpFetchOptions, fetch_url


def inspect_urls(
    urls: Sequence[str],
    *,
    fetcher: FetchFunction = fetch_url,
) -> list[dict[str, Any]]:
    options = HttpFetchOptions(allowed_hosts=API_ALLOWED_HOSTS, headers={})
    rows: list[dict[str, Any]] = []
    for url in urls:
        try:
            result = fetcher(url, options)
        except FetchSecurityError as exc:
            rows.append({"url": url, "ok": False, "error": str(exc), "candidates": []})
            continue
        candidates = target_license_candidates(result.body)
        rows.append(
            {
                "url": result.url,
                "ok": True,
                "status": result.status,
                "candidates": list(candidates),
                "raw_fields": _raw_license_fields(result.body),
            }
        )
    return rows


def _raw_license_fields(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    raw: dict[str, Any] = {}
    for key in ("license", "licenses"):
        if key in payload:
            raw[key] = payload[key]
    for parent in ("info", "version", "crate", "licensed"):
        child = payload.get(parent)
        if isinstance(child, dict):
            for key in ("license", "licenses", "declared"):
                if key in child:
                    raw[f"{parent}.{key}"] = child[key]
    return raw


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect evidence URLs using RepoLens allowlist and license extraction."
    )
    parser.add_argument("urls", nargs="+", help="Evidence URLs to fetch and inspect.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    print(json.dumps(inspect_urls(args.urls), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
