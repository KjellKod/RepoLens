"""Input loaders for the scan stage."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from repolens.data.errors import ArtifactError
from repolens.data.limits import max_bytes_for
from repolens.data.store import read_discovered
from repolens.exit_codes import InputError

_CANDIDATE_ROW_RE = re.compile(
    r"^- \[(?P<mark>[xX ])\] "
    r"(?P<repo_fence>`+)(?P<name_with_owner>.*?)(?P=repo_fence) "
    r"- category (?P<category_fence>`+).*?(?P=category_fence) "
    r"\((?P<source_fence>`+).*?(?P=source_fence)\)"
    r"(?:\s.*)?$"
)


def load_explicit_repo_specs(path: Path, repo_spec_cls: type) -> list:
    """Load the legacy explicit ``scan --repos`` JSON file."""

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"Repo list not found: {path.name}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InputError(f"Repo list is not valid JSON: {path.name}") from exc

    records = raw.get("repos") if isinstance(raw, dict) else raw
    return repo_specs_from_records(records, repo_spec_cls)


def load_discover_approved_repo_refs(work_root: Path) -> tuple[str, ...]:
    """Load checked discover candidate repo refs from ``discovered.json`` and Markdown."""

    return tuple(
        _repo_ref_from_discovered(record) for record in _load_discover_approved_records(work_root)
    )


def load_discover_approved_repo_specs(work_root: Path, repo_spec_cls: type) -> list:
    """Load checked discover candidates from ``discovered.json`` and checklist Markdown."""

    records = []
    for discovered_record in _load_discover_approved_records(work_root):
        repo_ref = _repo_ref_from_discovered(discovered_record)
        name_with_owner = discovered_record["name_with_owner"]
        records.append(
            {
                "repo_ref": repo_ref,
                "clone_url": f"https://github.com/{name_with_owner}.git",
                # Carry the discovered privacy flag onto the record so the runner
                # resolves a credential for private repos. Dropping it here (as the
                # loader used to) silently clones private repos unauthenticated.
                "private": discovered_record.get("private") is True,
            }
        )

    return repo_specs_from_records(records, repo_spec_cls)


def _load_discover_approved_records(work_root: Path) -> list[dict]:
    """Return discovered records for checked, non-hard-excluded candidates."""

    root = Path(work_root)
    discovered = _read_discovered_input(root)
    raw_repositories = discovered.get("repositories")
    if not isinstance(raw_repositories, list) or not raw_repositories:
        raise InputError("discovered.json must contain at least one repository")

    by_name_with_owner: dict[str, dict] = {}
    for index, record in enumerate(raw_repositories):
        if not isinstance(record, dict):
            raise InputError(f"discovered.repositories[{index}] must be an object")
        name_with_owner = record.get("name_with_owner")
        if not isinstance(name_with_owner, str) or not name_with_owner:
            raise InputError(f"discovered.repositories[{index}].name_with_owner must be non-empty")
        if name_with_owner in by_name_with_owner:
            raise InputError(f"duplicate discovered repository: {name_with_owner}")
        by_name_with_owner[name_with_owner] = record

    checked_names = _checked_candidate_names(root / "repos.candidate.md")
    records: list[dict] = []
    for name_with_owner in checked_names:
        discovered_record = by_name_with_owner.get(name_with_owner)
        if discovered_record is None:
            raise InputError(f"checked repo not found in discovered.json: {name_with_owner}")
        if discovered_record.get("hard_excluded") is True:
            continue
        _repo_ref_from_discovered(discovered_record)
        records.append(discovered_record)

    if not records:
        raise InputError("no repos checked in repos.candidate.md")
    return records


def _repo_ref_from_discovered(record: dict) -> str:
    name_with_owner = record.get("name_with_owner")
    repo_ref = record.get("name")
    if not isinstance(repo_ref, str) or not repo_ref:
        if isinstance(name_with_owner, str) and name_with_owner:
            raise InputError(f"discovered repo {name_with_owner} is missing a non-empty name")
        raise InputError("discovered repo is missing a non-empty name")
    return repo_ref


def repo_specs_from_records(records: object, repo_spec_cls: type) -> list:
    """Validate scan repo records and materialize the runner's RepoSpec type."""

    if not isinstance(records, list) or not records:
        raise InputError("Repo list must contain a non-empty 'repos' array")

    specs = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise InputError(f"Repo list entry {index} must be an object")
        repo_ref = record.get("repo_ref")
        clone_url = record.get("clone_url")
        if not isinstance(repo_ref, str) or not repo_ref:
            raise InputError(f"Repo list entry {index} is missing a 'repo_ref'")
        _validate_clone_url(clone_url, index=index)
        specs.append(
            repo_spec_cls(
                repo_ref=repo_ref,
                clone_url=clone_url,
                private=record.get("private") is True,
            )
        )
    return specs


def _read_discovered_input(work_root: Path) -> dict:
    try:
        return read_discovered(work_root)
    except FileNotFoundError as exc:
        raise InputError("discovered.json not found") from exc
    except ArtifactError as exc:
        raise InputError(f"discovered.json is not usable: {exc}") from exc


def _checked_candidate_names(path: Path) -> list[str]:
    markdown = _read_candidate_markdown(path)
    in_candidates = False
    checked: list[str] = []
    seen: set[str] = set()

    for line_number, line in enumerate(markdown.splitlines(), start=1):
        if line == "## Candidates":
            in_candidates = True
            continue
        if in_candidates and line.startswith("## "):
            break
        if not in_candidates or not line.startswith("- ["):
            continue

        match = _CANDIDATE_ROW_RE.match(line)
        if match is None:
            raise InputError(f"repos.candidate.md:{line_number} malformed candidate checkbox row")
        if match.group("mark") == " ":
            continue

        name_with_owner = match.group("name_with_owner")
        if not name_with_owner:
            raise InputError(f"repos.candidate.md:{line_number} has an empty repo name")
        if name_with_owner in seen:
            raise InputError(f"duplicate checked repo in repos.candidate.md: {name_with_owner}")
        seen.add(name_with_owner)
        checked.append(name_with_owner)

    return checked


def _read_candidate_markdown(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes_for("repos_candidate_md") + 1)
    except FileNotFoundError as exc:
        raise InputError("repos.candidate.md not found") from exc
    if len(raw) > max_bytes_for("repos_candidate_md"):
        raise InputError("repos.candidate.md exceeds size limit") from None
    if not raw.strip():
        raise InputError("repos.candidate.md is empty")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("repos.candidate.md is not valid UTF-8") from exc


def _validate_clone_url(clone_url: object, *, index: int) -> None:
    if not isinstance(clone_url, str):
        raise InputError(f"Repo list entry {index} needs an https 'clone_url'")
    parsed_clone_url = urlparse(clone_url)
    if parsed_clone_url.scheme != "https" or not parsed_clone_url.hostname:
        raise InputError(f"Repo list entry {index} needs an https 'clone_url'")
    if parsed_clone_url.username or parsed_clone_url.password:
        raise InputError(f"Repo list entry {index} 'clone_url' must not embed credentials")
