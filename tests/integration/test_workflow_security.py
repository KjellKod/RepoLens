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
        "|| github.ref == format('refs/heads/{0}', "
        "github.event.repository.default_branch || 'main')" in workflow
    )
    assert "ref: ${{ github.event.repository.default_branch || 'main' }}" in workflow
    assert (
        "RPL_LIVE_REPOSITORY: "
        "${{ inputs.target_repository || vars.RPL_LIVE_REPOSITORY "
        "|| github.event.repository.name || github.repository }}" in workflow
    )
    assert "persist-credentials: false" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_offline_ci_workflow_contains_required_x3_steps() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "  offline-ci:\n" in workflow
    # The security-canaries job lives only in security-canaries.yml; it must not be
    # duplicated in the offline gate.
    assert "  security-canaries:\n" not in workflow
    for expected in [
        "python -m pip install --require-hashes -r requirements-dev.txt",
        "python -m ruff format --check .",
        "python -m ruff check .",
        "python -m pytest tests/unit",
        "python -m pytest tests/integration tests/e2e tests/canaries",
        "python -m pytest tests/policy",
        "python -m pytest tests/bootstrap",
        "python scripts/security_canary_gate.py",
        "python -m repolens.security.name_hygiene --self-test",
        "printf '%s%s%s' invented- forbidden- token",
        'python -m repolens.security.name_hygiene --forbidden-name "$token" --require-denylist',
        "python -m repolens.security.name_hygiene --require-denylist",
        "python tools/pins_lint.py src/repolens/bootstrap/pins.toml",
        "python scripts/ci/verify_tool_pins.py",
        'python-version: "3.13"',
    ]:
        assert expected in workflow, expected
    # No references to deleted scripts may remain.
    for forbidden in [
        "run_security_canaries.py",
        "scripts/ci/name_hygiene.py",
        "scripts/check_name_hygiene.py",
        "name_hygiene_guard.py",
        "tools/name_hygiene.py",
    ]:
        assert forbidden not in workflow, forbidden
    assert "RPL_FORBIDDEN_NAMES" not in workflow
    assert "-".join(["invented", "forbidden", "token"]) not in workflow
    assert "continue-on-error" not in workflow
    assert 'python-version: "3.11"' not in workflow


def test_security_canaries_workflow_runs_gate_directly() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security-canaries.yml").read_text(
        encoding="utf-8"
    )

    assert "  security-canaries:\n" in workflow
    assert "python scripts/security_canary_gate.py" in workflow
    assert "run_security_canaries.py" not in workflow
    assert 'python-version: "3.13"' in workflow
    assert "# v6" in workflow
    assert "# v5" in workflow


def test_no_redundant_offline_workflows_remain() -> None:
    workflows_dir = ROOT / ".github" / "workflows"
    names = {path.name for path in workflows_dir.glob("*.yml")}

    assert "offline-ci.yml" not in names
    assert "offline-pr.yml" not in names
    assert "f5-policy.yml" not in names
    # The canonical set: one offline gate, the canary gate, advisory review, scheduled smoke.
    assert {"ci.yml", "security-canaries.yml", "codex-ci-review.yml", "live-smoke.yml"} <= names
