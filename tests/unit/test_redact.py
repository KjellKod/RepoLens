from __future__ import annotations

from repolens.data.redact import REDACTION, redact_tokens


def test_redact_tokens_deep_walks() -> None:
    classic = "ghp_" + "1234567890abcdef"
    fine_grained = "github_pat_" + "1234567890abcdefghijklmnop"
    value = {
        "token": f"prefix {classic} suffix",
        "nested": [fine_grained],
    }

    redacted = redact_tokens(value)

    assert redacted["token"] == f"prefix {REDACTION} suffix"
    assert redacted["nested"] == [REDACTION]
