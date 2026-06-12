"""CLI-facing release disclosure stage."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.config import Config
from repolens.presence.lockfile_scope import (
    LockfileScope,
    load_lockfile_licenses,
    load_lockfile_scopes,
)
from repolens.presence.models import DeliveryArtifact, Presence
from repolens.presence.scan_js_bundle import npm_package_name_from_purl, scan_js_bundle
from repolens.release.evaluate import (
    ReleaseEvaluation,
    evaluate_release,
    load_approved_decision_refs,
)
from repolens.release.writers import (
    remove_withheld_outputs,
    write_release_licenses,
    write_release_notices,
    write_release_policy,
    write_release_review,
)
from repolens.report.gate import ReportGateOpen, run_report_gate
from repolens.report.main import select_disclosure_record_selection

_SCANNABLE_TARGETS = frozenset({"cloudflare-worker", "js-bundle"})


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    evaluation: ReleaseEvaluation
    paths: tuple[Path, ...]


def run_release_stage(
    work_root: Path,
    *,
    artifact: Path | None = None,
    target: str | None = None,
    out_dir: Path | None = None,
    config: Config | None = None,
) -> ReleaseResult:
    del config
    root = Path(work_root)
    output_dir = Path(out_dir) if out_dir is not None else root / "release"
    gate = run_report_gate(root)
    if not gate.clear:
        raise ReportGateOpen(gate.message)
    selection = select_disclosure_record_selection(root)
    records = _apply_lockfile_delivery(selection.records, root, target=target)
    delivery_artifact: DeliveryArtifact | None = None
    if artifact is not None and target is not None and target in _SCANNABLE_TARGETS:
        records, delivery_artifact = _apply_bundle_scan(records, artifact=artifact, target=target)

    evaluation = evaluate_release(
        records,
        approved_decision_refs=load_approved_decision_refs(root),
        target=target,
        artifact=delivery_artifact,
        file_gaps=selection.file_gaps,
    )
    policy_path = write_release_policy(output_dir, evaluation)
    review_path = write_release_review(output_dir, evaluation)
    paths = [policy_path, review_path]
    if evaluation.result == "blocked":
        remove_withheld_outputs(output_dir)
    else:
        licenses_path = write_release_licenses(output_dir, evaluation)
        notices_md, notices_txt = write_release_notices(output_dir, evaluation)
        paths.extend([licenses_path, notices_md, notices_txt])
    return ReleaseResult(evaluation=evaluation, paths=tuple(paths))


def _apply_bundle_scan(
    records: list[dict[str, Any]],
    *,
    artifact: Path,
    target: str,
) -> tuple[list[dict[str, Any]], DeliveryArtifact]:
    package_names = {
        package_name
        for record in records
        if (package_name := npm_package_name_from_purl(record.get("purl"))) is not None
    }
    scan = scan_js_bundle(artifact, package_names, target=target)
    upgraded: list[dict[str, Any]] = []
    for record in records:
        package_name = npm_package_name_from_purl(record.get("purl"))
        if package_name is None or package_name not in scan.matched:
            upgraded.append(record)
            continue
        presence = Presence.from_dict(record.get("presence")) or Presence()
        updated_presence = Presence(
            install_state=presence.install_state,
            delivery_state="delivered",
            relation=presence.relation,
            path=presence.path,
            platform_match=presence.platform_match,
            source="artifact-scan",
            target=target,
            reopen_on_delivery_change=presence.reopen_on_delivery_change,
            delivery_artifact=scan.artifact,
        )
        updated = dict(record)
        updated["presence"] = updated_presence.to_dict()
        upgraded.append(updated)
    return upgraded, scan.artifact


_NPM_PURL_PREFIX = "pkg:npm/"
_NON_PROD_RELATIONS = frozenset({"unknown", "dev", "optional", "devOptional", "peer"})
_UNRESOLVED_EXPRESSIONS = frozenset({"", "unknown", "noassertion", "none"})


@dataclass(frozen=True, slots=True)
class _RepoLockfile:
    scopes: dict[str, LockfileScope]
    licenses: dict[str, str]


def _apply_lockfile_delivery(
    records: list[dict[str, Any]],
    work_root: Path,
    *,
    target: str | None,
) -> list[dict[str, Any]]:
    """Mark production npm dependencies ``delivered`` from the lockfile graph.

    Minified production bundles cannot be attributed by string markers, so the
    production dependency closure recorded in ``package-lock.json`` is the
    delivery signal: production packages ship (``delivered``, basis
    ``dependency-graph``), optional packages are per-platform binaries left to
    monitor, and dev-only packages never ship and are left unchanged. When a
    delivered package resolved to UNKNOWN but the lockfile declares its license,
    that declared license is used as an evidence-backed fallback.
    """

    cache: dict[str, _RepoLockfile] = {}
    updated_records: list[dict[str, Any]] = []
    for record in records:
        lockfile = _repo_lockfile(record, work_root, cache)
        name = record.get("name")
        scope = lockfile.scopes.get(name) if (lockfile and isinstance(name, str)) else None
        if scope != "prod":
            updated_records.append(record)
            continue
        updated = dict(record)
        _fill_declared_license(updated, lockfile.licenses.get(name) if lockfile else None)
        presence = Presence.from_dict(record.get("presence")) or Presence()
        if presence.delivery_state != "delivered":
            relation = "direct" if presence.relation in _NON_PROD_RELATIONS else presence.relation
            updated["presence"] = Presence(
                install_state="installed",
                delivery_state="delivered",
                relation=relation,
                path=presence.path,
                platform_match=presence.platform_match,
                source="dependency-graph",
                target=target,
                reopen_on_delivery_change=presence.reopen_on_delivery_change,
                delivery_artifact=presence.delivery_artifact,
            ).to_dict()
        updated_records.append(updated)
    return updated_records


def _fill_declared_license(record: dict[str, Any], lockfile_license: str | None) -> None:
    """Fall back to the lockfile-declared license when resolution was UNKNOWN."""

    if not lockfile_license:
        return
    spdx = record.get("spdx_id")
    if isinstance(spdx, str) and spdx.strip().casefold() not in _UNRESOLVED_EXPRESSIONS:
        return
    record["spdx_id"] = lockfile_license
    if not record.get("declared_license_raw"):
        record["declared_license_raw"] = lockfile_license


def _repo_lockfile(
    record: Mapping[str, Any],
    work_root: Path,
    cache: dict[str, _RepoLockfile],
) -> _RepoLockfile | None:
    purl = record.get("purl")
    if not (isinstance(purl, str) and purl.startswith(_NPM_PURL_PREFIX)):
        return None
    repo = record.get("repo")
    if not (isinstance(repo, str) and repo):
        return None
    if repo not in cache:
        snapshot = work_root / "work" / repo / "source.snapshot"
        cache[repo] = _RepoLockfile(
            scopes=load_lockfile_scopes(snapshot),
            licenses=load_lockfile_licenses(snapshot),
        )
    return cache[repo]
