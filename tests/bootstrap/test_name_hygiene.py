"""Tests for the name-hygiene guard (AC #7).

The denylist is supplied at test time (never committed). A planted forbidden
token proves the matcher fails closed; a clean acme-* tree passes.
"""

from __future__ import annotations

from pathlib import Path

from tools import name_hygiene

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_acme_tree_passes():
    findings = name_hygiene.scan_paths(
        [FIXTURES / "acme_clean_tree"], denylist=["forbiddenname", "secret-org"]
    )
    assert findings == []


def test_seeded_bad_token_fails():
    findings = name_hygiene.scan_paths(
        [FIXTURES / "seeded_bad_token.txt"], denylist=["FORBIDDENNAME"]
    )
    assert findings, "matcher must flag the planted forbidden literal"
    assert "seeded_bad_token.txt" in findings[0]


def test_matcher_is_case_insensitive():
    findings = name_hygiene.scan_text(
        "the Forbiddenname appears here",
        name_hygiene._compile_matchers(["FORBIDDENNAME"]),
        source="x",
    )
    assert findings


def test_scan_paths_empty_denylist_matches_nothing():
    # Library-level: an empty denylist matches nothing (no-op is main()'s concern).
    findings = name_hygiene.scan_paths([FIXTURES / "seeded_bad_token.txt"], denylist=[])
    assert findings == []


def _run_main_with_env(args, denylist_value):
    """Run name_hygiene.main with RPL_HYGIENE_DENYLIST set (or unset if None)."""
    import os

    old = os.environ.get("RPL_HYGIENE_DENYLIST")
    old_file = os.environ.get("RPL_HYGIENE_DENYLIST_FILE")
    # Ensure no file-based denylist leaks in from the ambient env.
    os.environ.pop("RPL_HYGIENE_DENYLIST_FILE", None)
    if denylist_value is None:
        os.environ.pop("RPL_HYGIENE_DENYLIST", None)
    else:
        os.environ["RPL_HYGIENE_DENYLIST"] = denylist_value
    try:
        return name_hygiene.main(args)
    finally:
        for key, val in (
            ("RPL_HYGIENE_DENYLIST", old),
            ("RPL_HYGIENE_DENYLIST_FILE", old_file),
        ):
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val


def test_main_fails_closed_when_denylist_unset():
    # Prove-it: with no denylist configured the gate must NOT pass vacuously.
    rc = _run_main_with_env([str(FIXTURES / "acme_clean_tree")], denylist_value=None)
    assert rc == 2, "unconfigured denylist must be a config error, not a vacuous pass"


def test_main_fails_closed_when_denylist_empty():
    rc = _run_main_with_env([str(FIXTURES / "acme_clean_tree")], denylist_value="")
    assert rc == 2, "empty denylist must be a config error, not a vacuous pass"


def test_main_passes_with_configured_denylist():
    # Sample denylist as the brief specifies; clean tree → exit 0.
    rc = _run_main_with_env(
        [str(FIXTURES / "acme_clean_tree")], denylist_value="acmecorp,realowner"
    )
    assert rc == 0


def test_extensionless_file_is_scanned(tmp_path):
    # A forbidden literal in an extension-less text file must be caught.
    f = tmp_path / "Dockerfile"
    f.write_text("FROM realowner/base:1.0\n")
    findings = name_hygiene.scan_paths([f], denylist=["realowner"])
    assert findings, "extension-less text file must be scanned"


def test_binary_content_is_skipped(tmp_path):
    # A NUL-containing file is sniffed as binary and skipped (no decode crash).
    f = tmp_path / "blob"
    f.write_bytes(b"realowner\x00\x01\x02binarydata")
    findings = name_hygiene.scan_paths([f], denylist=["realowner"])
    assert findings == [], "binary content must be skipped, not scanned"


def test_load_denylist_from_env():
    deny = name_hygiene.load_denylist(env={"RPL_HYGIENE_DENYLIST": "alpha, beta\ngamma"})
    assert deny == ["alpha", "beta", "gamma"]


def test_load_denylist_from_file(tmp_path):
    f = tmp_path / "deny.txt"
    f.write_text("# comment\nalpha\n\nbeta\n")
    deny = name_hygiene.load_denylist(env={"RPL_HYGIENE_DENYLIST_FILE": str(f)})
    assert deny == ["alpha", "beta"]


def test_main_passes_on_clean_subtree():
    # Run the CLI entry over the clean acme tree with a non-matching denylist.
    import os

    old = os.environ.get("RPL_HYGIENE_DENYLIST")
    os.environ["RPL_HYGIENE_DENYLIST"] = "forbiddenname"
    try:
        rc = name_hygiene.main([str(FIXTURES / "acme_clean_tree")])
    finally:
        if old is None:
            os.environ.pop("RPL_HYGIENE_DENYLIST", None)
        else:
            os.environ["RPL_HYGIENE_DENYLIST"] = old
    assert rc == 0


def test_main_fails_on_seeded_token():
    import os

    old = os.environ.get("RPL_HYGIENE_DENYLIST")
    os.environ["RPL_HYGIENE_DENYLIST"] = "FORBIDDENNAME"
    try:
        rc = name_hygiene.main([str(FIXTURES / "seeded_bad_token.txt")])
    finally:
        if old is None:
            os.environ.pop("RPL_HYGIENE_DENYLIST", None)
        else:
            os.environ["RPL_HYGIENE_DENYLIST"] = old
    assert rc == 1
