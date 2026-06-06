"""Human disclosure-review artifacts for complex report licenses."""

from __future__ import annotations

import getpass
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repolens.config import Config
from repolens.data import store
from repolens.data.errors import ArtifactError, LimitExceeded
from repolens.data.limits import MAX_JSON_DEPTH, SCHEMA_VERSION, max_bytes_for, scan_depth
from repolens.data.validation import validate_artifact
from repolens.exit_codes import InputError
from repolens.policy import classify_license_input
from repolens.policy.expression import ParseError, pure_or_leaf_options
from repolens.policy.tiers import risk_rank
from repolens.report.main import DisclosureRow, select_main_report_rows
from repolens.security.redaction import redact_tokens, redact_tokens_from_structure
from repolens.security.sanitize import markdown_link, render_code_span, sanitize_markdown
from repolens.shortlist.render import decode_component_ref, encode_component_ref

REVIEW_JSON_FILENAME = "report.review.json"
REVIEW_MD_FILENAME = "report.review.md"
KEEP_FULL_OPTION_ID = "keep-full"
LEGAL_FOLLOW_UP_OPTION_ID = "needs-legal-follow-up"

_COMPOUND_RE = re.compile(r"\b(AND|OR|WITH)\b|[()]", re.IGNORECASE)
_ITEM_MARKER_RE = re.compile(r"&lt;!-- rpl:license-review-item=([A-Za-z0-9_-]+) --&gt;")
_OPTION_MARKER_RE = re.compile(
    r"&lt;!-- rpl:license-review=([A-Za-z0-9_-]+) option=([A-Za-z0-9_-]+) --&gt;"
)
_SHORT_OPTION_MARKER_RE = re.compile(
    r"&lt;!-- rpl:license-review-option=([A-Za-z0-9_-]+) --&gt;"
)
_CHECKBOX_RE = re.compile(r"^\s*[-*]\s*\[(?P<mark>[^\]])\]")
_NOTE_HEADING = "Disclosure note:"
_MAX_REVIEW_NOTE_CHARS = 600


@dataclass(frozen=True, slots=True)
class ReviewOption:
    """One machine-keyed disclosure choice in ``report.review.md``."""

    option_id: str
    label: str
    spdx: str | None
    decision: str


@dataclass(frozen=True, slots=True)
class ReviewItem:
    """One complex-license disclosure review row."""

    review_id: str
    component_key: dict[str, object]
    found_in: tuple[str, ...]
    policy_tier: str
    raw_spdx: str
    options: tuple[ReviewOption, ...]
    row_review_ids: tuple[str, ...] = ()
    component_refs: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    source_urls: tuple[str, ...] = ()
    selected_spdx: str | None = None
    decision: str | None = None
    review_status: str = "open"
    review_note: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    """Approved disclosure decision consumed by presentation reports."""

    review_id: str
    selected_spdx: str
    review_note: str


@dataclass(frozen=True, slots=True)
class ReportReviewResult:
    """Paths and counts for a ``report review`` run."""

    markdown_path: Path
    json_path: Path
    item_count: int
    open_count: int


@dataclass(frozen=True, slots=True)
class _ParsedMarkdownDecision:
    option_ids: tuple[str, ...] = ()
    invalid_marks: tuple[str, ...] = ()
    note: str = ""


def run_report_review(
    work_root: Path,
    *,
    config: Config | None = None,
    identity: str | None = None,
    now: str | None = None,
) -> ReportReviewResult:
    """Ingest ``report.review.md`` decisions and regenerate review artifacts."""

    root = Path(work_root)
    timestamp = now or _utc_now()
    candidates = build_review_items(root, config=config)
    prior = _load_prior_items(root / REVIEW_JSON_FILENAME)
    parsed = _parse_existing_markdown(root / REVIEW_MD_FILENAME, candidates)
    items = _apply_prior_and_markdown(
        candidates,
        prior,
        parsed,
        identity=identity,
        now=timestamp,
        open_shortlist_refs=_open_shortlist_component_refs(root),
    )
    document = review_document(items, generated_at=timestamp)
    validate_artifact(document, "report_review")
    redacted = redact_tokens_from_structure(document)
    json_path = root / REVIEW_JSON_FILENAME
    md_path = root / REVIEW_MD_FILENAME
    store.atomic_write_bytes(json_path, _checked_review_json_bytes(json_path, redacted))
    store.atomic_write_bytes(md_path, redact_tokens(render_review_markdown(items)).encode("utf-8"))
    return ReportReviewResult(
        markdown_path=md_path,
        json_path=json_path,
        item_count=len(items),
        open_count=int(document["open_count"]),
    )


def build_review_items(work_root: Path, *, config: Config | None = None) -> tuple[ReviewItem, ...]:
    """Build review candidates from the same main-report rows as presentation output."""

    rows, _file_gaps = select_main_report_rows(Path(work_root), config)
    return _group_review_items(tuple(_review_item_for_row(row) for row in rows if _row_needs_review(row)))


def load_review_state(work_root: Path) -> dict[str, ReviewDecision]:
    """Load approved review decisions keyed by stable review id."""

    path = Path(work_root) / REVIEW_JSON_FILENAME
    if not path.exists():
        return {}
    raw = store.load_json_capped(path, max_bytes=max_bytes_for("report_review"))
    validate_artifact(raw, "report_review")
    if not isinstance(raw, Mapping):
        raise InputError("report.review.json must be an object")
    items = raw.get("items", [])
    if not isinstance(items, list):
        raise InputError("report.review.json items must be an array")
    decisions: dict[str, ReviewDecision] = {}
    for item in items:
        if not isinstance(item, Mapping) or item.get("review_status") != "approved":
            continue
        review_id = _non_empty(item.get("review_id"))
        selected_spdx = _non_empty(item.get("selected_spdx"))
        if review_id is None or selected_spdx is None:
            continue
        decision = ReviewDecision(
            review_id=review_id,
            selected_spdx=selected_spdx,
            review_note=_note_text(item.get("review_note")),
        )
        decisions[review_id] = decision
        row_review_ids = item.get("row_review_ids")
        if isinstance(row_review_ids, list):
            for alias in row_review_ids:
                if isinstance(alias, str) and alias.strip():
                    decisions[alias] = decision
    return decisions


def review_id_for_row(row: DisclosureRow) -> str:
    """Return the stable disclosure-review id for an aggregated report row."""

    return (
        "license-review:"
        f"{_review_key_part(row.name)}|"
        f"{_review_key_part(_version_key(row.versions))}|"
        f"{_review_key_part(row.spdx_id)}"
    )


def review_document(items: Sequence[ReviewItem], *, generated_at: str) -> dict[str, object]:
    """Serialize review items and enforce the open-count invariant."""

    raw_items = [_item_to_json(item) for item in items]
    open_count = sum(1 for item in raw_items if item["review_status"] == "open")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "open_count": open_count,
        "items": raw_items,
    }


def render_review_markdown(items: Sequence[ReviewItem]) -> str:
    """Render constrained, sanitized Markdown for human disclosure review."""

    lines = [
        "# RepoLens Disclosure License Review",
        "",
        "Choose exactly one disclosure license option per item, then rerun "
        "`repolens report review`. Review items blocked by an open shortlist row stay open "
        "until the shortlist item is approved or removed.",
        "",
    ]
    if not items:
        lines.append("No disclosure-license review items.")
    for item in items:
        marker = f"<!-- rpl:license-review-item={encode_component_ref(item.review_id)} -->"
        lines.extend(
            [
                f"## {render_code_span(item.raw_spdx)}",
                "",
                f"### {_review_item_heading(item)}",
                "",
                f"_review id: {render_code_span(item.review_id)}_ {marker}",
                "",
                f"- components: {_components_cell(item)}",
                "- versions: "
                f"{render_code_span('; '.join(_strings(item.component_key['versions'])))}",
                *_grouping_reason_lines(item),
                f"- found in: {render_code_span('; '.join(item.found_in))}",
                f"- source links: {_source_urls_cell(item)}",
                f"- current policy tier: {render_code_span(item.policy_tier)}",
                f"- detected SPDX: {render_code_span(item.raw_spdx)}",
            ]
        )
        suggested = _suggested_choice(item)
        if suggested is not None:
            suggested_option, suggested_reason = suggested
            lines.append(f"- suggested choice: {render_code_span(suggested_option.label)}")
            lines.append(f"- suggestion reason: {render_code_span(suggested_reason)}")
        if item.review_status == "approved" and item.selected_spdx:
            lines.append(f"- selected disclosure SPDX: {render_code_span(item.selected_spdx)}")
        for warning in item.warnings:
            lines.append(f"- warning: {render_code_span(warning)}")
        lines.extend(["", "Choose disclosure license:"])
        for option in item.options:
            checkbox = "[x]" if option.option_id == _checked_option_id(item) else "[ ]"
            option_marker = (
                f"<!-- rpl:license-review-option={encode_component_ref(option.option_id)} -->"
            )
            lines.append(f"- {checkbox} {render_code_span(option.label)} {option_marker}")
        lines.extend(["", _NOTE_HEADING])
        for note_line in (item.review_note or "").splitlines() or [""]:
            lines.append(f"> {note_line}")
        lines.append("")
    sanitized = sanitize_markdown("\n".join(lines).rstrip() + "\n")
    return (
        "\n".join(
            line.replace("&gt;", ">", 1) if line.startswith("&gt;") else line
            for line in sanitized.splitlines()
        )
        + "\n"
    )


def _checked_review_json_bytes(path: Path, value: object) -> bytes:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    max_bytes = max_bytes_for("report_review")
    if len(data) > max_bytes:
        raise LimitExceeded(f"{path} exceeds byte limit {max_bytes}")
    scan_depth(data, MAX_JSON_DEPTH)
    return data


def _review_item_for_row(row: DisclosureRow) -> ReviewItem:
    decision = classify_license_input(row.spdx_id)
    options = _options_for_spdx(row.spdx_id)
    return ReviewItem(
        review_id=review_id_for_row(row),
        component_key={
            "name": row.name,
            "versions": list(row.versions),
            "raw_spdx": row.spdx_id,
        },
        found_in=row.found_in,
        policy_tier=decision.effective_tier.value,
        raw_spdx=row.spdx_id,
        options=options,
        row_review_ids=(review_id_for_row(row),),
        component_refs=(f"{row.name}|{row.spdx_id}",),
        components=(row.name,),
        source_urls=row.source_urls,
    )


def _group_review_items(items: Sequence[ReviewItem]) -> tuple[ReviewItem, ...]:
    groups: dict[tuple[object, ...], list[ReviewItem]] = {}
    for item in items:
        key = (
            item.raw_spdx,
            tuple(_strings(item.component_key["versions"])),
            item.policy_tier,
            tuple((option.option_id, option.label, option.spdx, option.decision) for option in item.options),
        )
        groups.setdefault(key, []).append(item)
    return tuple(_merged_review_item(group) for group in groups.values())


def _merged_review_item(items: Sequence[ReviewItem]) -> ReviewItem:
    first = items[0]
    versions = tuple(_strings(first.component_key["versions"]))
    components = _sorted_unique(
        component for item in items for component in (item.components or (str(item.component_key["name"]),))
    )
    row_review_ids = _sorted_unique(
        review_id for item in items for review_id in (item.row_review_ids or (item.review_id,))
    )
    source_urls = _sorted_unique(url for item in items for url in item.source_urls)
    found_in = _sorted_unique(repo for item in items for repo in item.found_in)
    component_refs = _sorted_unique(
        ref for item in items for ref in (item.component_refs or (_component_ref(item),))
    )
    group_id = (
        "license-review-group:"
        f"{_review_key_part(first.raw_spdx)}|"
        f"{_review_key_part(_version_key(versions))}|"
        f"{_review_key_part(first.policy_tier)}"
    )
    return ReviewItem(
        review_id=group_id,
        component_key={
            "name": components[0] if len(components) == 1 else f"{len(components)} components",
            "versions": list(versions),
            "raw_spdx": first.raw_spdx,
        },
        found_in=found_in,
        policy_tier=first.policy_tier,
        raw_spdx=first.raw_spdx,
        options=first.options,
        row_review_ids=row_review_ids,
        component_refs=component_refs,
        components=components,
        source_urls=source_urls,
    )


def _row_needs_review(row: DisclosureRow) -> bool:
    raw_spdx = row.spdx_id
    decision = classify_license_input(raw_spdx)
    return (
        bool(_COMPOUND_RE.search(raw_spdx))
        or decision.chosen_branch is not None
        or decision.dual_license_detected
        or "parse_error" in decision.reasons
    )


def _options_for_spdx(raw_spdx: str) -> tuple[ReviewOption, ...]:
    options: list[ReviewOption] = []
    try:
        pure_or_options = pure_or_leaf_options(raw_spdx)
    except ParseError:
        pure_or_options = None
    if pure_or_options is not None:
        seen: set[str] = set()
        for spdx in pure_or_options:
            if spdx in seen:
                continue
            seen.add(spdx)
            options.append(
                ReviewOption(
                    option_id=f"branch:{len(options) + 1}",
                    label=spdx,
                    spdx=spdx,
                    decision="selected_branch",
                )
            )
    options.extend(
        (
            ReviewOption(
                option_id=KEEP_FULL_OPTION_ID,
                label=f"Keep full expression: {raw_spdx}",
                spdx=raw_spdx,
                decision="keep_full_expression",
            ),
            ReviewOption(
                option_id=LEGAL_FOLLOW_UP_OPTION_ID,
                label="Needs legal follow-up",
                spdx=None,
                decision="needs_legal_follow_up",
            ),
        )
    )
    return tuple(options)


def _load_prior_items(path: Path) -> dict[str, Mapping[str, Any]]:
    if not path.exists():
        return {}
    raw = store.load_json_capped(path, max_bytes=max_bytes_for("report_review"))
    validate_artifact(raw, "report_review")
    if not isinstance(raw, Mapping):
        return {}
    items = raw.get("items", [])
    if not isinstance(items, list):
        return {}
    return {
        str(item["review_id"]): item
        for item in items
        if isinstance(item, Mapping) and isinstance(item.get("review_id"), str)
    }


def _parse_existing_markdown(
    path: Path,
    current_items: Sequence[ReviewItem],
) -> dict[str, _ParsedMarkdownDecision]:
    if not path.exists():
        return {}
    current_options = {
        item.review_id: {option.option_id for option in item.options} for item in current_items
    }
    return _parse_review_markdown(path.read_text(encoding="utf-8"), current_options)


def _parse_review_markdown(
    markdown: str,
    current_options: Mapping[str, set[str]],
) -> dict[str, _ParsedMarkdownDecision]:
    checked: dict[str, list[str]] = {}
    invalid: dict[str, list[str]] = {}
    notes: dict[str, str] = {}
    current_review_id: str | None = None
    note_target: str | None = None
    note_lines: list[str] = []

    def flush_note() -> None:
        nonlocal note_target, note_lines
        if note_target is not None:
            notes[note_target] = _bounded_note("\n".join(note_lines))
        note_target = None
        note_lines = []

    for line in markdown.splitlines():
        item_marker = _ITEM_MARKER_RE.search(line)
        if item_marker is not None:
            flush_note()
            decoded = decode_component_ref(item_marker.group(1))
            current_review_id = decoded if decoded in current_options else None
            continue

        if line.strip() == _NOTE_HEADING:
            flush_note()
            note_target = current_review_id
            continue

        if note_target is not None:
            stripped = line.lstrip()
            if stripped.startswith("&gt;"):
                note_lines.append(stripped.removeprefix("&gt;").lstrip())
                continue
            if stripped.startswith(">"):
                note_lines.append(stripped.removeprefix(">").lstrip())
                continue
            if not stripped:
                continue
            flush_note()

        checkbox = _CHECKBOX_RE.match(line)
        if checkbox is None:
            continue
        marker = _OPTION_MARKER_RE.search(line)
        short_marker = _SHORT_OPTION_MARKER_RE.search(line) if marker is None else None
        if marker is not None:
            review_id = decode_component_ref(marker.group(1))
            option_id = decode_component_ref(marker.group(2))
        elif short_marker is not None:
            review_id = current_review_id
            option_id = decode_component_ref(short_marker.group(1))
        else:
            continue
        if (
            review_id is None
            or option_id is None
            or review_id not in current_options
            or option_id not in current_options[review_id]
        ):
            continue
        mark = checkbox.group("mark")
        if mark in {"x", "X"}:
            checked.setdefault(review_id, []).append(option_id)
        elif mark not in {" ", ""}:
            invalid.setdefault(review_id, []).append(mark)
    flush_note()

    review_ids = set(checked) | set(invalid) | set(notes)
    return {
        review_id: _ParsedMarkdownDecision(
            option_ids=tuple(checked.get(review_id, ())),
            invalid_marks=tuple(invalid.get(review_id, ())),
            note=notes.get(review_id, ""),
        )
        for review_id in review_ids
    }


def _apply_prior_and_markdown(
    candidates: Sequence[ReviewItem],
    prior: Mapping[str, Mapping[str, Any]],
    parsed: Mapping[str, _ParsedMarkdownDecision],
    *,
    identity: str | None,
    now: str,
    open_shortlist_refs: set[str],
) -> tuple[ReviewItem, ...]:
    reviewer = _reviewer_identity(identity)
    updated: list[ReviewItem] = []
    for item in candidates:
        current = _apply_prior(item, prior.get(item.review_id))
        parsed_decision = parsed.get(item.review_id)
        if parsed_decision is None:
            updated.append(_block_if_shortlist_open(current, open_shortlist_refs))
            continue
        warnings = list(current.warnings)
        if parsed_decision.invalid_marks:
            warnings.append("invalid checkbox mark ignored")
        if len(parsed_decision.option_ids) > 1:
            warnings.append("multiple checked options; choose exactly one")
            updated.append(
                _block_if_shortlist_open(
                    _replace_decision(
                        current,
                        selected_spdx=None,
                        decision=None,
                        review_status="open",
                        review_note=parsed_decision.note,
                        decided_by=None,
                        decided_at=None,
                        warnings=tuple(warnings),
                    ),
                    open_shortlist_refs,
                )
            )
            continue
        if len(parsed_decision.option_ids) == 0:
            updated.append(
                _block_if_shortlist_open(
                    _replace_decision(
                        current,
                        review_note=parsed_decision.note or current.review_note,
                        warnings=tuple(warnings),
                    ),
                    open_shortlist_refs,
                )
            )
            continue
        selected = _option_by_id(current, parsed_decision.option_ids[0])
        if selected is None:
            warnings.append("selected option is no longer available")
            updated.append(
                _block_if_shortlist_open(
                    _replace_decision(
                        current,
                        selected_spdx=None,
                        decision=None,
                        review_status="open",
                        review_note=parsed_decision.note,
                        decided_by=None,
                        decided_at=None,
                        warnings=tuple(warnings),
                    ),
                    open_shortlist_refs,
                )
            )
            continue
        if _component_ref(current) in open_shortlist_refs:
            updated.append(
                _replace_decision(
                    current,
                    selected_spdx=None,
                    decision="blocked_by_shortlist",
                    review_status="open",
                    review_note=parsed_decision.note,
                    decided_by=None,
                    decided_at=None,
                    warnings=tuple((*warnings, "matching shortlist item is still open")),
                )
            )
            continue
        if selected.option_id == LEGAL_FOLLOW_UP_OPTION_ID:
            updated.append(
                _replace_decision(
                    current,
                    selected_spdx=None,
                    decision=selected.decision,
                    review_status="open",
                    review_note=parsed_decision.note,
                    decided_by=reviewer,
                    decided_at=now,
                    warnings=tuple(warnings),
                )
            )
            continue
        updated.append(
            _replace_decision(
                current,
                selected_spdx=selected.spdx,
                decision=selected.decision,
                review_status="approved",
                review_note=parsed_decision.note,
                decided_by=reviewer,
                decided_at=now,
                warnings=tuple(warnings),
            )
        )
    return tuple(updated)


def _apply_prior(item: ReviewItem, prior: Mapping[str, Any] | None) -> ReviewItem:
    if prior is None:
        return item
    selected_spdx = _non_empty(prior.get("selected_spdx"))
    decision = _non_empty(prior.get("decision"))
    review_status = _non_empty(prior.get("review_status")) or "open"
    if review_status != "approved" or selected_spdx is None or decision is None:
        return _replace_decision(item, review_note=_note_text(prior.get("review_note")))
    option_ids = {option.option_id for option in item.options}
    if decision == "keep_full_expression":
        option_id = KEEP_FULL_OPTION_ID
    elif decision == "selected_branch":
        option_id = _branch_option_id_for_selected_spdx(item, selected_spdx)
        if option_id is None:
            return item
    else:
        return item
    if option_id not in option_ids:
        return item
    return _replace_decision(
        item,
        selected_spdx=selected_spdx,
        decision=decision,
        review_status="approved",
        review_note=_note_text(prior.get("review_note")),
        decided_by=_non_empty(prior.get("decided_by")),
        decided_at=_non_empty(prior.get("decided_at")),
    )


def _block_if_shortlist_open(item: ReviewItem, open_shortlist_refs: set[str]) -> ReviewItem:
    refs = item.component_refs or (_component_ref(item),)
    if not any(ref in open_shortlist_refs for ref in refs):
        return item
    warnings = tuple((*item.warnings, "matching shortlist item is still open"))
    return _replace_decision(
        item,
        selected_spdx=None,
        decision="blocked_by_shortlist",
        review_status="open",
        decided_by=None,
        decided_at=None,
        warnings=warnings,
    )


def _replace_decision(
    item: ReviewItem,
    *,
    selected_spdx: str | None | object = ...,
    decision: str | None | object = ...,
    review_status: str | object = ...,
    review_note: str | object = ...,
    decided_by: str | None | object = ...,
    decided_at: str | None | object = ...,
    warnings: tuple[str, ...] | object = ...,
) -> ReviewItem:
    return ReviewItem(
        review_id=item.review_id,
        component_key=item.component_key,
        found_in=item.found_in,
        policy_tier=item.policy_tier,
        raw_spdx=item.raw_spdx,
        options=item.options,
        row_review_ids=item.row_review_ids,
        component_refs=item.component_refs,
        components=item.components,
        source_urls=item.source_urls,
        selected_spdx=item.selected_spdx if selected_spdx is ... else selected_spdx,
        decision=item.decision if decision is ... else decision,
        review_status=item.review_status if review_status is ... else str(review_status),
        review_note=item.review_note if review_note is ... else _bounded_note(str(review_note)),
        decided_by=item.decided_by if decided_by is ... else decided_by,
        decided_at=item.decided_at if decided_at is ... else decided_at,
        warnings=item.warnings if warnings is ... else warnings,
    )


def _item_to_json(item: ReviewItem) -> dict[str, object]:
    return {
        "review_id": item.review_id,
        "component_key": item.component_key,
        "found_in": list(item.found_in),
        "policy_tier": item.policy_tier,
        "raw_spdx": item.raw_spdx,
        "row_review_ids": list(item.row_review_ids),
        "component_refs": list(item.component_refs),
        "components": list(item.components),
        "source_urls": list(item.source_urls),
        "options": [
            {
                "option_id": option.option_id,
                "label": option.label,
                "spdx": option.spdx,
                "decision": option.decision,
            }
            for option in item.options
        ],
        "selected_spdx": item.selected_spdx,
        "decision": item.decision,
        "review_status": item.review_status,
        "review_note": item.review_note,
        "decided_by": item.decided_by,
        "decided_at": item.decided_at,
        "warnings": list(item.warnings),
    }


def _open_shortlist_component_refs(work_root: Path) -> set[str]:
    path = Path(work_root) / "shortlist.json"
    if not path.exists():
        return set()
    try:
        document = store.read_shortlist(work_root)
    except ArtifactError as exc:
        raise InputError(f"invalid shortlist.json: {exc}") from exc
    items = document.get("items", [])
    if not isinstance(items, list):
        return set()
    return {
        str(item["component_ref"])
        for item in items
        if isinstance(item, Mapping)
        and item.get("status") == "open"
        and isinstance(item.get("component_ref"), str)
    }


def _option_by_id(item: ReviewItem, option_id: str) -> ReviewOption | None:
    for option in item.options:
        if option.option_id == option_id:
            return option
    return None


def _checked_option_id(item: ReviewItem) -> str | None:
    if item.review_status != "approved" or item.decision is None:
        return None
    if item.decision == "keep_full_expression":
        return KEEP_FULL_OPTION_ID
    if item.decision == "selected_branch" and item.selected_spdx is not None:
        return _branch_option_id_for_selected_spdx(item, item.selected_spdx)
    return None


def _suggested_choice(item: ReviewItem) -> tuple[ReviewOption, str] | None:
    keep_full = _option_by_id(item, KEEP_FULL_OPTION_ID)
    branch_options = tuple(
        option for option in item.options if option.decision == "selected_branch" and option.spdx
    )
    if branch_options:
        ranked = tuple(
            (option, classify_license_input(option.spdx or "").effective_tier)
            for option in branch_options
        )
        best_rank = min(risk_rank(tier) for _option, tier in ranked)
        best = tuple((option, tier) for option, tier in ranked if risk_rank(tier) == best_rank)
        has_higher_risk_branch = any(risk_rank(tier) > best_rank for _option, tier in ranked)
        if len(best) == 1 and has_higher_risk_branch:
            option, tier = best[0]
            return option, f"lowest policy-risk branch among the simple OR options ({tier.value})"
        if keep_full is not None:
            tier_values = _sorted_unique(tier.value for _option, tier in ranked)
            if len(tier_values) == 1:
                return (
                    keep_full,
                    f"all simple OR options have policy tier {tier_values[0]}; "
                    "keeping the full expression avoids an arbitrary branch choice",
                )
            return (
                keep_full,
                "multiple simple OR options share the lowest policy-risk tier; "
                "keeping the full expression avoids an arbitrary branch choice",
            )
    if keep_full is not None:
        return (
            keep_full,
            "not a simple OR branch choice; keep the full expression unless legal review chooses otherwise",
        )
    return None


def _branch_option_id_for_selected_spdx(item: ReviewItem, selected_spdx: str) -> str | None:
    for option in item.options:
        if option.decision == "selected_branch" and option.spdx == selected_spdx:
            return option.option_id
    return None


def _component_ref(item: ReviewItem) -> str:
    if item.component_refs:
        return item.component_refs[0]
    return f"{item.component_key['name']}|{item.raw_spdx}"


def _components_cell(item: ReviewItem) -> str:
    components = item.components or (str(item.component_key["name"]),)
    limit = 12
    rendered = ", ".join(render_code_span(component) for component in components[:limit])
    if len(components) > limit:
        rendered = f"{rendered}, ... ({len(components)} total)"
    return rendered or render_code_span("unknown")


def _review_item_heading(item: ReviewItem) -> str:
    components = item.components or (str(item.component_key["name"]),)
    versions = _strings(item.component_key["versions"])
    component_label = "package"
    if len(components) == 1:
        component_text = render_code_span(components[0])
    else:
        remaining = len(components) - 1
        package_word = "package" if remaining == 1 else "packages"
        component_text = (
            f"{render_code_span(components[0])} + {remaining} more {package_word} "
            f"({len(components)} total)"
        )
    version_label = "version" if len(versions) == 1 else "versions"
    version_text = render_code_span("; ".join(versions) or "unknown")
    return f"{component_label}: {component_text}, {version_label}: {version_text}"


def _grouping_reason_lines(item: ReviewItem) -> tuple[str, ...]:
    components = item.components or (str(item.component_key["name"]),)
    if len(components) <= 1:
        return ()
    return (
        "- grouping reason: "
        f"{render_code_span('same detected SPDX, same version set, and same policy tier')}",
    )


def _source_urls_cell(item: ReviewItem) -> str:
    if not item.source_urls:
        return render_code_span("none")
    limit = 8
    links = [markdown_link(_source_url_label(url, index), url) for index, url in enumerate(item.source_urls[:limit], 1)]
    if len(item.source_urls) > limit:
        links.append(f"... ({len(item.source_urls)} total)")
    return ", ".join(links)


def _source_url_label(url: str, index: int) -> str:
    text = url.strip()
    if text.startswith("pkg:"):
        return f"package {index}"
    return f"source{index}"


def _version_key(versions: Sequence[str]) -> str:
    return ",".join(versions) if versions else "*"


def _review_key_part(value: str) -> str:
    return redact_tokens(value.strip()) or "unknown"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}, key=lambda value: (value.casefold(), value)))


def _reviewer_identity(identity: str | None) -> str:
    explicit = _non_empty(identity)
    if explicit is not None:
        return explicit
    try:
        detected = _non_empty(getpass.getuser())
    except OSError:
        detected = None
    return detected or "unknown"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bounded_note(value: str) -> str:
    cleaned = "".join(char for char in value if char == "\n" or ord(char) >= 32)
    return cleaned.strip()[:_MAX_REVIEW_NOTE_CHARS]


def _note_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return _bounded_note(value)


def _non_empty(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value)
