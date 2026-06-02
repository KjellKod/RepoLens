from __future__ import annotations

from repolens.security.redaction import redact_tokens, redact_tokens_from_structure


TOKENS = [
    "ghp_" + "a" * 20,
    "ghs_" + "b" * 20,
    "github_pat_" + "c" * 20,
]


def test_redacts_supported_token_families_from_text() -> None:
    text = " ".join(TOKENS)
    output = redact_tokens(text)
    for token in TOKENS:
        assert token not in output
    assert output.count("[REDACTED_TOKEN]") == len(TOKENS)


def test_redacts_nested_json_like_structures() -> None:
    payload = {
        "key-" + TOKENS[0]: ["safe", {"inner": TOKENS[1]}],
        "tuple": (TOKENS[2],),
    }
    output = redact_tokens_from_structure(payload)
    assert "ghp_" not in repr(output)
    assert "ghs_" not in repr(output)
    assert "github_pat_" not in repr(output)
