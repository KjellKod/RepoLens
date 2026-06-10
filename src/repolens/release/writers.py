"""Writers for release disclosure artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from repolens.data import store
from repolens.release.evaluate import ReleaseEntry, ReleaseEvaluation
from repolens.report.main import DEFAULT_LEGAL_TEXT
from repolens.security.redaction import redact_tokens
from repolens.security.sanitize import render_code_span, sanitize_markdown

_WITHHELD_OUTPUTS = ("release.licenses.json", "release.notices.md", "release.notices.txt")


def remove_withheld_outputs(out_dir: Path) -> None:
    for filename in _WITHHELD_OUTPUTS:
        path = out_dir / filename
        if path.exists():
            path.unlink()


def write_release_policy(out_dir: Path, evaluation: ReleaseEvaluation) -> Path:
    payload = {
        "schema_version": "1.0",
        "result": evaluation.result,
        "reasons": [
            {
                "code": blocker.code,
                "message": blocker.message,
                "name": blocker.name,
                "expression": blocker.expression,
                "context": blocker.context,
            }
            for blocker in evaluation.blockers
        ],
        "warnings": list(evaluation.warnings),
        "counts": {
            "delivered": len(evaluation.delivered),
            "monitored": len(evaluation.monitored),
            "not_scanned": len(evaluation.not_scanned),
            "notices_bundled": sum(
                1 for entry in evaluation.delivered if entry.actions.bundled_notice == "required"
            ),
            "notices_public": sum(
                1 for entry in evaluation.delivered if entry.actions.public_notice == "required"
            ),
        },
        "policy_version": evaluation.policy_version,
        "disclosure_policy_version": evaluation.disclosure_policy_version,
        "target": evaluation.target,
        "artifact": evaluation.artifact.to_dict() if evaluation.artifact is not None else None,
    }
    return store.write_release_policy(out_dir, payload)


def write_release_review(out_dir: Path, evaluation: ReleaseEvaluation) -> Path:
    lines = [
        "# RepoLens Release Review",
        "",
        DEFAULT_LEGAL_TEXT,
        "",
        f"Gate result: {_code(evaluation.result)}",
        "",
        "## Blockers",
    ]
    if evaluation.blockers:
        for blocker in evaluation.blockers:
            lines.append(
                "- "
                + " - ".join(
                    item
                    for item in (
                        blocker.code,
                        blocker.name,
                        blocker.expression,
                        blocker.context,
                        blocker.message,
                    )
                    if item
                )
            )
            if blocker.expression and blocker.context:
                lines.append(
                    "  Next step: add or update the disclosure policy entry for "
                    f"{render_code_span(blocker.expression)} in "
                    f"{render_code_span(blocker.context)}, or remove/replace the dependency."
                )
    else:
        lines.append("- None")
    lines.extend(["", "## Warnings"])
    lines.extend([f"- {warning}" for warning in evaluation.warnings] or ["- None"])
    lines.extend(["", "## Delivered Disclosures"])
    lines.extend([_review_entry_line(entry) for entry in evaluation.delivered] or ["- None"])
    lines.extend(["", "## Monitored Future Risks"])
    lines.extend(
        [
            f"- {_record_value(record, 'name')} "
            f"({_record_value(record, 'spdx_id')}): not currently delivered; monitor because "
            "a platform, feature, dependency, or deployment change could include it later."
            for record in evaluation.monitored
        ]
        or ["- None"]
    )
    lines.extend(["", "## Scan Coverage"])
    if evaluation.artifact is not None:
        artifact = evaluation.artifact.to_dict()
        lines.append(
            "- Scanned "
            f"{artifact.get('kind', 'artifact')} at {artifact.get('path', '')} "
            f"({artifact.get('hash', '')})"
        )
    else:
        lines.append("- No artifact scanned in this run.")
    if evaluation.not_scanned:
        lines.append(f"- {len(evaluation.not_scanned)} records remain not_scanned/unknown.")
    text = redact_tokens(sanitize_markdown("\n".join(lines).rstrip() + "\n"))
    path = out_dir / "release.review.md"
    store.atomic_write_bytes(path, text.encode("utf-8"))
    return path


def write_release_licenses(out_dir: Path, evaluation: ReleaseEvaluation) -> Path:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "policy_version": evaluation.policy_version,
        "disclosure_policy_version": evaluation.disclosure_policy_version,
        "entries": [
            _license_entry(entry) for entry in sorted(evaluation.delivered, key=_entry_key)
        ],
    }
    return store.write_release_licenses(out_dir, payload)


def write_release_notices(out_dir: Path, evaluation: ReleaseEvaluation) -> tuple[Path, Path]:
    notice_entries = [
        entry
        for entry in sorted(evaluation.delivered, key=_entry_key)
        if entry.actions.bundled_notice == "required"
    ]
    header = [
        "Generated by RepoLens.",
        DEFAULT_LEGAL_TEXT,
        "Full license texts are not included in this pilot output.",
        f"Policy: {evaluation.policy_version}; disclosure policy: "
        f"{evaluation.disclosure_policy_version}.",
    ]
    md_lines = ["# Third-Party Notices", "", *header, ""]
    txt_lines = ["Third-Party Notices", "", *header, ""]
    for entry in notice_entries:
        md_lines.extend(_notice_markdown(entry))
        txt_lines.extend(_notice_text(entry))
    md_path = out_dir / "release.notices.md"
    txt_path = out_dir / "release.notices.txt"
    store.atomic_write_bytes(
        md_path,
        redact_tokens(sanitize_markdown("\n".join(md_lines).rstrip() + "\n")).encode("utf-8"),
    )
    store.atomic_write_bytes(
        txt_path,
        redact_tokens("\n".join(txt_lines).rstrip() + "\n").encode("utf-8"),
    )
    return md_path, txt_path


def _license_entry(entry: ReleaseEntry) -> dict[str, Any]:
    artifact = _presence(entry).delivery_artifact
    delivery = {"state": _presence(entry).delivery_state}
    if artifact is not None:
        delivery["artifact"] = artifact.to_dict()
    return {
        "name": _record_value(entry.record, "name"),
        "versions": _split_values(entry.record.get("version")),
        "spdx_expression": _record_value(entry.record, "spdx_id"),
        "chosen_branch": entry.chosen_branch,
        "tier": entry.tier,
        "actions": {
            "public_notice": entry.actions.public_notice,
            "bundled_notice": entry.actions.bundled_notice,
            "internal_review": entry.actions.internal_review,
            "release_gate": entry.actions.release_gate,
        },
        "rationale": entry.actions.rationale,
        "source_urls": _source_urls(entry),
        "found_in": _split_values(entry.record.get("repo")),
        "delivery": delivery,
    }


def _notice_markdown(entry: ReleaseEntry) -> list[str]:
    name = _record_value(entry.record, "name")
    lines = [
        f"## {name}",
        "",
        f"- Version(s): {', '.join(_split_values(entry.record.get('version'))) or 'unknown'}",
        f"- SPDX expression: {render_code_span(_record_value(entry.record, 'spdx_id'))}",
        f"- Rationale: {entry.actions.rationale}",
    ]
    if entry.actions.public_notice == "required":
        lines.append(
            f"- Attribution: {name} is included under {_record_value(entry.record, 'spdx_id')}."
        )
    return lines + [""]


def _notice_text(entry: ReleaseEntry) -> list[str]:
    name = _record_value(entry.record, "name")
    lines = [
        name,
        f"Version(s): {', '.join(_split_values(entry.record.get('version'))) or 'unknown'}",
        f"SPDX expression: {_record_value(entry.record, 'spdx_id')}",
        f"Rationale: {entry.actions.rationale}",
    ]
    if entry.actions.public_notice == "required":
        lines.append(
            f"Attribution: {name} is included under {_record_value(entry.record, 'spdx_id')}."
        )
    return lines + [""]


def _review_entry_line(entry: ReleaseEntry) -> str:
    return (
        f"- {_record_value(entry.record, 'name')} ({_record_value(entry.record, 'spdx_id')}): "
        f"bundled={entry.actions.bundled_notice}, public={entry.actions.public_notice}, "
        f"gate={entry.actions.release_gate}"
    )


def _entry_key(entry: ReleaseEntry) -> tuple[str, str]:
    return (_record_value(entry.record, "name").casefold(), _record_value(entry.record, "spdx_id"))


def _source_urls(entry: ReleaseEntry) -> list[str]:
    evidence = entry.record.get("evidence")
    if isinstance(evidence, dict) and evidence.get("url"):
        return [str(evidence["url"])]
    return []


def _presence(entry: ReleaseEntry):
    from repolens.presence.models import Presence

    return Presence.from_dict(entry.record.get("presence")) or Presence()


def _record_value(record: Any, key: str) -> str:
    value = record.get(key) if isinstance(record, dict) else None
    return "" if value is None else str(value)


def _split_values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    return [str(value)]


def _code(value: str) -> str:
    return f"`{value}`"
