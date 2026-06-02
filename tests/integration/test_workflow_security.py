from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_live_smoke_workflow_is_not_pr_triggered_and_has_no_dispatch_ref_checkout() -> None:
    workflow = (ROOT / ".github" / "workflows" / "live-smoke.yml").read_text(encoding="utf-8")

    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "target_ref" not in workflow
    assert "ref: ${{ inputs." not in workflow
    assert (
        "if: github.event_name != 'workflow_dispatch' "
        "|| github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        in workflow
    )
    assert "ref: ${{ github.event.repository.default_branch }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_offline_ci_workflow_contains_required_x3_steps() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    for expected in [
        "python -m pip install --require-hashes -r requirements-dev.txt",
        "python -m ruff format --check .",
        "python -m ruff check .",
        "python -m pytest tests/unit",
        "python -m pytest tests/integration",
        "python scripts/ci/run_security_canaries.py",
        "printf '%s%s%s' invented- forbidden- token",
        'python scripts/ci/name_hygiene.py --forbidden-name "$token" --require-denylist',
        "python scripts/ci/verify_tool_pins.py",
    ]:
        assert expected in workflow
    assert "RPL_FORBIDDEN_NAMES" not in workflow
    assert "-".join(["invented", "forbidden", "token"]) not in workflow
    assert "continue-on-error" not in workflow
