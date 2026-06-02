"""Run the M1 synthetic fixture pipeline end to end.

This is an offline X1 harness: it drives the shipped stage functions in order
while injecting the external boundaries that cannot run offline (``gh``, clone,
Syft, and package metadata APIs). Artifacts are written to ``--work-root`` using
the same store/schema paths as the CLI pipeline.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from repolens.config import load_config
from repolens.data import store
from repolens.data.validation import validate_artifact
from repolens.discovery.gh import GhRunResult
from repolens.discovery.pipeline import run_discover
from repolens.report import render_main_report
from repolens.resolve.models import ApiCandidate, PackageFact
from repolens.resolve.stage import run_resolve
from repolens.scan.runner import RepoSpec, scan_repos
from repolens.security.clone import CloneOptions
from repolens.security.http_client import FetchResult, HttpFetchOptions

DEFAULT_FIXTURE_ROOT = Path("tests/fixtures/synthetic")
SHARED_COMPONENT = {
    "name": "acme-shared-core",
    "version": "9.9.9",
    "declared_license": "MIT",
    "scope": "runtime",
}


@dataclass(frozen=True)
class FixtureComponent:
    name: str
    version: str
    ecosystem: str
    license: str
    purl: str
    location: str


class FixtureAdapter:
    def __init__(self, components: dict[tuple[str, str], FixtureComponent]) -> None:
        self._components = components

    def resolve(self, package: PackageFact) -> ApiCandidate | None:
        key = (package.name, package.version)
        component = self._components.get(key)
        if component is None:
            return None
        return ApiCandidate(
            spdx_id=_normalized_fixture_license(component.license),
            evidence_url=_evidence_url(component),
            evidence_anchor=_normalized_fixture_license(component.license),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the offline M1 fixture e2e harness.")
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, default=DEFAULT_FIXTURE_ROOT)
    args = parser.parse_args()

    work_root = args.work_root
    fixture_root = args.fixture_root
    manifest = _load_manifest(fixture_root)
    owner = str(manifest["synthetic_owner"])
    fixtures = manifest["fixtures"]

    work_root.mkdir(parents=True, exist_ok=True)
    _run_discover(owner, fixtures, work_root)
    approved_repos = _approve_candidates(owner, fixtures, work_root)

    clone_targets: dict[Path, str] = {}
    components = _components_by_repo(fixtures)

    def clone(options: CloneOptions) -> Path:
        repo_id = Path(options.remote_url).stem
        source = fixture_root / repo_id
        if not source.is_dir():
            raise RuntimeError(f"unknown fixture repo: {repo_id}")
        shutil.copytree(source, options.destination)
        clone_targets[options.destination] = repo_id
        return options.destination

    def syft_runner(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        del timeout
        target = Path(argv[2].removeprefix("dir:"))
        repo_id = clone_targets[target]
        payload = _syft_payload(repo_id, components[repo_id])
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

    scan_repos(
        work_root,
        [RepoSpec(**record) for record in approved_repos["repos"]],
        syft_path=work_root / "tools" / "syft",
        clone=clone,
        command_runner=syft_runner,
    )

    all_components = {
        (component.name, component.version): component
        for repo_components in components.values()
        for component in repo_components
    }
    adapter = FixtureAdapter(all_components)
    fetcher = _fixture_fetcher_for(all_components.values())
    for repo in approved_repos["repos"]:
        run_resolve(
            work_root,
            repo["repo_ref"],
            adapters=[adapter],
            fetcher=fetcher,
            evidence_resolver=_public_resolver,
        )

    report = render_main_report(work_root, work_root / "reports")
    summary = _validate_and_summarize(work_root, report.csv_path)
    print(json.dumps(summary, sort_keys=True))
    return 0


def _load_manifest(fixture_root: Path) -> dict[str, object]:
    manifest = json.loads((fixture_root / "fixture_manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise RuntimeError("fixture manifest must be an object")
    return manifest


def _run_discover(owner: str, fixtures: list[dict[str, object]], work_root: Path) -> None:
    repos = [
        {
            "name": fixture["id"],
            "nameWithOwner": f"{owner}/{fixture['id']}",
            "description": f"Synthetic {fixture['ecosystem']} fixture",
            "url": f"https://example.invalid/{owner}/{fixture['id']}",
            "isArchived": False,
            "isPrivate": False,
            "repositoryTopics": [{"name": str(fixture["ecosystem"])}],
        }
        for fixture in fixtures
    ]

    def runner(command: list[str], timeout_seconds: float) -> GhRunResult:
        del command, timeout_seconds
        return GhRunResult(returncode=0, stdout=json.dumps(repos), stderr="")

    run_discover(
        owner=owner,
        work_root=work_root,
        config=load_config(Path.cwd(), None),
        runner=runner,
        generated_at="2026-01-01T00:00:00+00:00",
    )


def _approve_candidates(
    owner: str, fixtures: list[dict[str, object]], work_root: Path
) -> dict[str, list[dict[str, str]]]:
    candidate_path = work_root / "repos.candidate.md"
    candidate_text = candidate_path.read_text(encoding="utf-8")
    if "- [x]" not in candidate_text:
        raise RuntimeError("fixture approval expected discover candidates to default checked")

    approved = {
        "repos": [
            {
                "repo_ref": str(fixture["id"]),
                "clone_url": f"https://example.invalid/{owner}/{fixture['id']}.git",
            }
            for fixture in fixtures
        ]
    }
    store.atomic_write_json(work_root / "approved-repos.json", approved)
    return approved


def _components_by_repo(fixtures: list[dict[str, object]]) -> dict[str, list[FixtureComponent]]:
    by_repo: dict[str, list[FixtureComponent]] = {}
    for fixture in fixtures:
        repo_id = str(fixture["id"])
        ecosystem = str(fixture["ecosystem"])
        repo_components = [
            _component_from_manifest(repo_id, ecosystem, item)
            for item in fixture["expected_components"]
        ]
        if ecosystem in {"python", "node"}:
            repo_components.append(_component_from_manifest(repo_id, ecosystem, SHARED_COMPONENT))
        by_repo[repo_id] = repo_components
    return by_repo


def _component_from_manifest(
    repo_id: str, ecosystem: str, raw: dict[str, object]
) -> FixtureComponent:
    name = str(raw["name"])
    version = str(raw["version"])
    return FixtureComponent(
        name=name,
        version=version,
        ecosystem=ecosystem,
        license=str(raw["declared_license"]),
        purl=_purl(ecosystem, name, version),
        location=f"{repo_id}/{_manifest_name(ecosystem)}",
    )


def _purl(ecosystem: str, name: str, version: str) -> str:
    encoded_version = quote(version, safe="")
    if ecosystem == "python":
        return f"pkg:pypi/{quote(name, safe='')}@{encoded_version}"
    if ecosystem == "node":
        return f"pkg:npm/{quote(name, safe='')}@{encoded_version}"
    if ecosystem == "go":
        return f"pkg:golang/{quote(name, safe='/')}@v{encoded_version}"
    if ecosystem == "rust":
        return f"pkg:cargo/{quote(name, safe='')}@{encoded_version}"
    if ecosystem == "jvm":
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{encoded_version}"
    raise RuntimeError(f"unsupported fixture ecosystem: {ecosystem}")


def _manifest_name(ecosystem: str) -> str:
    return {
        "python": "pyproject.toml",
        "node": "package.json",
        "go": "go.mod",
        "rust": "Cargo.toml",
        "jvm": "pom.xml",
    }[ecosystem]


def _syft_payload(repo_id: str, components: list[FixtureComponent]) -> dict[str, object]:
    return {
        "descriptor": {"name": "syft", "version": "fixture-1.0"},
        "artifacts": [
            {
                "name": component.name,
                "version": component.version,
                "type": component.ecosystem,
                "purl": component.purl,
                "locations": [{"path": component.location}],
            }
            for component in components
        ],
        "source": {"target": {"userInput": repo_id}},
    }


def _normalized_fixture_license(value: str) -> str:
    if value == "MIT OR Apache-2.0":
        return "MIT"
    return value


def _evidence_url(component: FixtureComponent) -> str:
    name = quote(component.name, safe="")
    version = quote(component.version, safe="")
    return f"https://api.deps.dev/v3alpha/systems/fixture/packages/{name}/versions/{version}"


def _fixture_fetcher_for(components: object):
    license_by_url = {
        _evidence_url(component): _normalized_fixture_license(component.license)
        for component in components
    }

    def fetcher(url: str, options: HttpFetchOptions) -> FetchResult:
        del options
        license_value = license_by_url.get(url)
        if license_value is None:
            raise RuntimeError(f"unexpected fixture evidence URL: {url}")
        body = json.dumps({"license": license_value})
        return FetchResult(url=url, status=200, headers=(), body=body.encode("utf-8"))

    return fetcher


def _public_resolver(host: str, port: int) -> tuple[str, ...]:
    del host, port
    return ("8.8.8.8",)


def _validate_and_summarize(work_root: Path, csv_path: Path) -> dict[str, object]:
    discovered = store.read_discovered(work_root)
    validate_artifact(discovered, "discovered")

    repo_dirs = sorted((work_root / "work").iterdir())
    sbom_rows = 0
    resolved_rows = 0
    for repo_dir in repo_dirs:
        repo_ref = repo_dir.name
        sbom = store.read_sbom(work_root, repo_ref)
        validate_artifact(sbom, "sbom")
        sbom_rows += len(sbom["artifacts"])
        resolved = list(store.iter_resolved(repo_dir / "resolved.ndjson"))
        resolved_rows += len(resolved)

    with csv_path.open(encoding="utf-8", newline="") as handle:
        report_rows = list(csv.DictReader(handle))

    return {
        "approved_repos": discovered["candidate_count"],
        "discovered_schema_valid": True,
        "sbom_artifacts": sbom_rows,
        "resolved_rows": resolved_rows,
        "report_rows": len(report_rows),
        "report_rows_with_license": sum(1 for row in report_rows if row["spdx_id"] != "UNKNOWN"),
        "report_rows_with_source_url": sum(1 for row in report_rows if row["source_url"]),
        "deduped_shared_component_rows": sum(
            1 for row in report_rows if row["name"] == SHARED_COMPONENT["name"]
        ),
        "report_md_exists": (work_root / "reports" / "report.main.md").exists(),
        "report_csv_exists": csv_path.exists(),
    }


if __name__ == "__main__":
    raise SystemExit(main())
