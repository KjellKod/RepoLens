import pytest

from repolens.security.secrets import redact_mapping, redact_text


pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_token_redaction_scrubs() -> None:
    token = "ghp_" + "A" * 24
    text = f"token={token}"

    assert token not in redact_text(text)
    assert redact_mapping({"TOKEN": token}) == {"TOKEN": "[REDACTED]"}
