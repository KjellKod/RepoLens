"""F5 offline name-hygiene guard (AC 13).

Owner / repo / organization / company identifiers are *runtime inputs only* and
must never appear as literals in F5 source, tests, fixtures, or docs (quest hard
rule). This guard is deliberately **name-free**: it embeds no real identifiers,
because hard-coding the very names we forbid would itself violate the rule and is
exactly the failure mode this test exists to prevent.

It enforces the rule two ways, both offline and deterministic:

* **Structural leaks** — email addresses are flagged unconditionally; an email is
  never legitimate in F5's pure-policy surface.
* **Runtime identifiers** — any token supplied via the
  ``REPOLENS_FORBIDDEN_NAMES`` environment variable (comma-separated) is flagged.
  CI can populate this from uncommitted repository variables or secrets for target
  owner/repo/company names. Locally, with the variable unset, the structural
  checks still run.

X3 owns the standing repo-wide guard; this is F5's local compliance check over its
own added files.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Built from fragments so the guard file does not itself contain a literal that
# matches the email pattern when it scans itself.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+" + "@" + r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

# Every file F5 adds. The guard scans itself too — proof that it carries no
# forbidden literals.
F5_FILES = (
    "pyproject.toml",
    "src/repolens/policy/__init__.py",
    "src/repolens/policy/config.py",
    "src/repolens/policy/data/__init__.py",
    "src/repolens/policy/data/license-policy.default.json",
    "src/repolens/policy/engine.py",
    "src/repolens/policy/expression.py",
    "src/repolens/policy/spdx.py",
    "src/repolens/policy/tiers.py",
    "src/repolens/policy/types.py",
    "tests/policy/conftest.py",
    "tests/policy/test_canaries_policy.py",
    "tests/policy/test_engine.py",
    "tests/policy/test_expression.py",
    "tests/policy/test_name_hygiene.py",
    "tests/policy/test_spdx_normalize.py",
    "tests/policy/test_tiers.py",
    ".github/workflows/f5-policy.yml",
)


def _forbidden_tokens() -> list[str]:
    raw = os.environ.get("REPOLENS_FORBIDDEN_NAMES", "")
    return [token.strip() for token in raw.split(",") if token.strip()]


def test_f5_files_have_no_forbidden_owner_repo_or_company_names() -> None:
    root = Path(__file__).resolve().parents[2]
    tokens = _forbidden_tokens()
    token_patterns = [
        (
            f"runtime identifier #{index}",
            re.compile(
                rf"(?<![0-9A-Za-z]){re.escape(token)}(?![0-9A-Za-z])",
                re.IGNORECASE,
            ),
        )
        for index, token in enumerate(tokens, start=1)
    ]

    hits: list[str] = []
    for rel_path in F5_FILES:
        text = (root / rel_path).read_text(encoding="utf-8")
        for match in _EMAIL_RE.finditer(text):
            hits.append(f"{rel_path}: email-like token")
        for token_label, pattern in token_patterns:
            if pattern.search(text):
                hits.append(f"{rel_path}: forbidden {token_label}")

    assert not hits, f"Name-hygiene violations found: {hits}"
