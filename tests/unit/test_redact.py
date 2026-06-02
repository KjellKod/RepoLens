from __future__ import annotations

from repolens.security.redaction import REDACTION, redact_tokens_from_structure


def test_redact_tokens_deep_walks() -> None:
    classic = "ghp_" + "1234567890abcdef"
    user_to_server = "ghu_" + "1234567890abcdef"
    refresh = "ghr_" + "1234567890abcdef"
    fine_grained = "github_pat_" + "1234567890abcdefghijklmnop"
    value = {
        "token": f"prefix {classic} suffix",
        "nested": [fine_grained, user_to_server, refresh],
        refresh: "key is token-shaped",
    }

    redacted = redact_tokens_from_structure(value)

    assert redacted["token"] == f"prefix {REDACTION} suffix"
    assert redacted["nested"] == [REDACTION, REDACTION, REDACTION]
    assert redacted[REDACTION] == "key is token-shaped"
