import zipfile
from pathlib import Path

import pytest

from repolens.config import Config
from repolens.flag import run_flag
from repolens.flag import stage as flag_stage
from repolens.report import main as report_main
from repolens.report import render_main_report
from repolens.security.redaction import REDACTION, redact_tokens, redact_tokens_from_structure

pytestmark = [pytest.mark.offline, pytest.mark.security, pytest.mark.canary]


def test_x2_token_redaction_scrubs() -> None:
    token = "ghp_" + "A" * 24
    oauth = "gho_" + "B" * 24
    user = "ghu_" + "C" * 24
    refresh = "ghr_" + "D" * 24
    text = f"token={token} oauth={oauth} user={user} refresh={refresh}"

    redacted_text = redact_tokens(text)
    assert token not in redacted_text
    assert oauth not in redacted_text
    assert user not in redacted_text
    assert refresh not in redacted_text
    assert redact_tokens_from_structure(
        {
            "TOKEN": token,
            "nested": {"oauth": oauth},
            "tokens": [user, ("plain", refresh)],
        }
    ) == {
        "TOKEN": REDACTION,
        "nested": {"oauth": REDACTION},
        "tokens": [REDACTION, ("plain", REDACTION)],
    }


def test_p6a_report_token_redacts_emitted_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classic = "gh" + "p_" + "A" * 24
    session = "gh" + "s_" + "B" * 24
    fine_grained = "github" + "_pat_" + "C" * 24
    record = {
        "schema_version": "1.0",
        "name": f"acme-token-{classic}",
        "version": f"1.2.3-{session}",
        "repo": "acme-alpha",
        "purl": f"pkg:pypi/acme-token@1.2.3-{session}",
        "declared_license_raw": "MIT",
        "spdx_id": "MIT",
        "evidence": {
            "source_layer": "syft",
            "url": f"https://example.invalid/licenses/{fine_grained}",
        },
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "modified": "unknown",
    }
    resolved_path = tmp_path / "work" / "acme-alpha" / "resolved.ndjson"
    resolved_path.parent.mkdir(parents=True)
    resolved_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(report_main.store, "iter_resolved", lambda path: iter([record]))

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())

    for path in (result.csv_path, result.markdown_path):
        data = path.read_bytes()
        assert classic.encode("utf-8") not in data
        assert session.encode("utf-8") not in data
        assert fine_grained.encode("utf-8") not in data
        assert REDACTION.encode("utf-8") in data


def test_p6b_report_docx_redacts_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    classic = "gh" + "p_" + "A" * 24
    session = "gh" + "s_" + "B" * 24
    record = {
        "schema_version": "1.0",
        "name": f"acme-token-{classic}",
        "version": f"1.2.3-{session}",
        "repo": "acme-alpha",
        "purl": f"pkg:pypi/acme-token@1.2.3-{session}",
        "declared_license_raw": "MIT",
        "spdx_id": "MIT",
        "evidence": {
            "source_layer": "syft",
            "url": "https://example.invalid/licenses/mit",
        },
        "tags": {
            "origin": "third-party-oss",
            "scope": "runtime",
            "distribution": "server",
        },
        "modified": "unknown",
    }
    resolved_path = tmp_path / "work" / "acme-alpha" / "resolved.ndjson"
    resolved_path.parent.mkdir(parents=True)
    resolved_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(report_main.store, "iter_resolved", lambda path: iter([record]))

    result = render_main_report(tmp_path, tmp_path / "out", _report_config())
    docx_bytes = result.docx_path.read_bytes()
    with zipfile.ZipFile(result.docx_path) as archive:
        xml = archive.read("word/document.xml")

    for data in (docx_bytes, xml):
        assert classic.encode("utf-8") not in data
        assert session.encode("utf-8") not in data
    assert REDACTION.encode("utf-8") in xml


def test_p4_flag_token_redacts_emitted_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classic = "gh" + "p_" + "A" * 24
    session = "gh" + "s_" + "B" * 24
    fine_grained = "github" + "_pat_" + "C" * 24
    # A flagged tier (BLOCK) so the component appears in all three artifacts, including the .md.
    record = {
        "schema_version": "1.0",
        "name": f"acme-token-{classic}",
        "version": f"1.2.3-{session}",
        "repo": "acme-alpha",
        "spdx_id": "AGPL-3.0-only",
        "evidence": {
            "source_layer": "syft",
            "url": f"https://example.invalid/licenses/{fine_grained}",
            "anchor": "AGPL-3.0-only",
        },
        "tags": {"origin": "third-party-oss", "scope": "runtime", "distribution": "server"},
        "modified": "unknown",
    }
    resolved_path = tmp_path / "work" / "acme-alpha" / "resolved.ndjson"
    resolved_path.parent.mkdir(parents=True)
    resolved_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(flag_stage.store, "iter_resolved", lambda path: iter([record]))
    _stub_flag_json_writers(tmp_path, monkeypatch)

    result = run_flag(tmp_path)

    for path in (result.inventory_path, result.shortlist_json_path, result.shortlist_md_path):
        data = path.read_bytes()
        assert classic.encode("utf-8") not in data
        assert session.encode("utf-8") not in data
        assert fine_grained.encode("utf-8") not in data
        assert REDACTION.encode("utf-8") in data


def _stub_flag_json_writers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def write_inventory(work_root: Path, value: dict[str, object]) -> Path:
        assert work_root == tmp_path
        path = work_root / "inventory.json"
        flag_stage.store.atomic_write_json(path, redact_tokens_from_structure(value))
        return path

    def write_shortlist(work_root: Path, value: dict[str, object]) -> Path:
        assert work_root == tmp_path
        path = work_root / "shortlist.json"
        flag_stage.store.atomic_write_json(path, redact_tokens_from_structure(value))
        return path

    monkeypatch.setattr(flag_stage.store, "write_inventory", write_inventory)
    monkeypatch.setattr(flag_stage.store, "write_shortlist", write_shortlist)
    monkeypatch.setattr(
        flag_stage,
        "_load_existing_metadata",
        lambda root: flag_stage.ShortlistMetadata(triage_by_ref={}),
    )


def _report_config() -> Config:
    return Config(
        values={
            "report": {
                "header": {
                    "org_name": "Example Org",
                    "legal_text": "Example legal notice.",
                }
            }
        },
        sources=(),
    )
