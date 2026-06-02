import pytest

from repolens.security.secrets import redact_mapping, redact_text

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_token_redaction_scrubs() -> None:
    token = "ghp_" + "A" * 24
    oauth = "gho_" + "B" * 24
    user = "ghu_" + "C" * 24
    refresh = "ghr_" + "D" * 24
    text = f"token={token} oauth={oauth} user={user} refresh={refresh}"

    redacted_text = redact_text(text)
    assert token not in redacted_text
    assert oauth not in redacted_text
    assert user not in redacted_text
    assert refresh not in redacted_text
    assert redact_mapping(
        {
            "TOKEN": token,
            "nested": {"oauth": oauth},
            "tokens": [user, ("plain", refresh)],
        }
    ) == {
        "TOKEN": "[REDACTED]",
        "nested": {"oauth": "[REDACTED]"},
        "tokens": ["[REDACTED]", ("plain", "[REDACTED]")],
    }
