"""Load and validate JSON-only local runtime config files."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repolens.data.validation import load_schema

from .exit_codes import InputError

LOCAL_CONFIG_FILENAME = ".repolens.local.json"
VISIBLE_LOCAL_CONFIG_FILENAME = "repolens.local.json"
DEFAULT_CATEGORY = "uncategorized"
DEFAULT_CLONE_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Config:
    values: dict[str, Any]
    sources: tuple[Path, ...]
    searched: tuple[Path, ...] = ()
    found: tuple[Path, ...] = ()
    active_path: Path | None = None
    explicit: bool = False


def load_config(
    base_dir: Path | str = ".",
    explicit_path: Path | str | None = None,
    *,
    work_root: Path | str | None = None,
) -> Config:
    """Load one JSON local config file using deterministic discovery.

    Discovery intentionally does not merge neighbors. An explicit ``--config``
    path wins; otherwise RepoLens checks ``<work-root>/.repolens.local.json``
    first when a command has ``--work-root``, then ``<cwd>/.repolens.local.json``.
    """

    if explicit_path is not None:
        source = Path(explicit_path)
        values = _read_config_file(source)
        return Config(
            values=values,
            sources=(source,),
            searched=(source,),
            found=(source,),
            active_path=source,
            explicit=True,
        )

    searched = _discovery_candidates(Path(base_dir), None if work_root is None else Path(work_root))
    found = tuple(path for path in searched if path.exists())
    active = found[0] if found else None
    values = _read_config_file(active) if active is not None else {}
    return Config(
        values=values,
        sources=(() if active is None else (active,)),
        searched=searched,
        found=found,
        active_path=active,
        explicit=False,
    )


def validate_config_values(values: dict[str, Any], *, path: Path | None = None) -> None:
    """Validate parsed local config against the canonical JSON Schema."""

    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(load_schema("local_config"))
    errors = sorted(validator.iter_errors(values), key=lambda error: list(error.absolute_path))
    if errors:
        raise InputError(_schema_error_message(errors[0], path))
    blank_path = _first_blank_string_path(values)
    if blank_path is not None:
        key_path = ".".join(blank_path) if blank_path else "root"
        location = f" {_display_path(path)}" if path is not None else ""
        raise InputError(
            f"Invalid config{location}: {key_path}: expected a non-empty string; "
            "got string. Fix: Use the type/value shown by `repolens config schema`."
        )


def local_config_json_schema() -> dict[str, Any]:
    """Return the canonical local-config JSON Schema."""

    return dict(load_schema("local_config"))


def human_schema_text() -> str:
    """Return a human-readable definition of supported local config keys."""

    return "\n".join(
        (
            "RepoLens local config schema",
            "",
            "Files",
            f"  Default discovered file: {LOCAL_CONFIG_FILENAME}",
            "  Explicit --config may point at any JSON file, including "
            f"{VISIBLE_LOCAL_CONFIG_FILENAME}.",
            "  TOML, YAML, and YML are not runtime-config formats.",
            "",
            "Supported keys",
            "  discover: object, optional, default={}",
            "    Operational impact: repository category labels and hard exclusions "
            "during discover.",
            f"  discover.taxonomy.default_category: string, optional, default={DEFAULT_CATEGORY}",
            "    Impact: category used when no explicit, pattern, or topic rule matches.",
            "  discover.taxonomy.explicit: object<string,string>, optional, default={}",
            "    Impact: exact repo or owner/repo category matches.",
            "  discover.taxonomy.patterns: array<object>, optional, default=[]",
            "    Impact: glob rules checked after explicit matches; each item requires "
            "glob and category.",
            "  discover.taxonomy.patterns[].glob: string, required when item is present",
            "  discover.taxonomy.patterns[].category: string, required when item is present",
            "  discover.taxonomy.topics: object<string,string>, optional, default={}",
            "    Impact: GitHub repository topic/tag category matches checked after patterns.",
            "  discover.taxonomy.dead: object<string,string>, optional, default={}",
            "    Impact: exact repos hard-excluded with a visible reason; use only for "
            "retired/dead repos.",
            "",
            "  scan: object, optional, default={}",
            "    Operational impact: SBOM filtering, clone timeout, and optional Syft "
            "cataloger restriction.",
            "  scan.exclude_paths: array<string>, optional, default=RepoLens built-in exclusions",
            "    Impact: repo-relative path prefixes filtered from SBOM artifacts.",
            "  scan.clone_timeout_seconds: number > 0, optional, "
            f"default={DEFAULT_CLONE_TIMEOUT_SECONDS}",
            "    Impact: positive hardened-clone timeout per repo.",
            "  scan.syft.catalogers: array<string>, optional, default=all Syft catalogers",
            "    Impact: restricts Syft catalogers; RepoLens still preserves mobile catalogers.",
            "",
            "  report: object, optional, default={}",
            "    Operational impact: main report category selection and optional docx cover text.",
            "  report.selection.include: array<string>, optional, "
            "default=all categories in main report",
            "    Impact: categories included in the main report; other categories route "
            "to appendices.",
            "  report.header.org_name: string, required only when report.header is present",
            "    Impact: optional docx cover organization text.",
            "  report.header.legal_text: string, required only when report.header is present",
            "    Impact: optional docx cover legal/disclaimer text.",
            "",
            "Unknown keys are rejected. Run `repolens config validate <path>` before using a file.",
        )
    )


def config_value_summary_lines(values: dict[str, Any]) -> list[str]:
    """Summarize validated local config values for humans."""

    taxonomy = _mapping(_mapping(values.get("discover")).get("taxonomy"))
    scan = _mapping(values.get("scan"))
    syft = _mapping(scan.get("syft"))
    report = _mapping(values.get("report"))
    selection = _mapping(report.get("selection"))
    header = _mapping(report.get("header")) if "header" in report else None

    default_category = taxonomy.get("default_category", DEFAULT_CATEGORY)
    explicit = _mapping(taxonomy.get("explicit"))
    patterns = _list(taxonomy.get("patterns"))
    topics = _mapping(taxonomy.get("topics"))
    dead = _mapping(taxonomy.get("dead"))

    exclude_paths = scan.get("exclude_paths")
    clone_timeout = scan.get("clone_timeout_seconds", DEFAULT_CLONE_TIMEOUT_SECONDS)
    catalogers = syft.get("catalogers")
    include = selection.get("include")

    return [
        (
            "discover.taxonomy: "
            f"default={default_category}, explicit={len(explicit)}, patterns={len(patterns)}, "
            f"topics={len(topics)}, dead={len(dead)}"
        ),
        (
            "scan: "
            f"exclude_paths={_count_or_default(exclude_paths)}, "
            f"clone_timeout_seconds={clone_timeout}, "
            f"syft.catalogers={_count_or_default(catalogers)}"
        ),
        (
            "report: "
            f"include={_count_or_default(include, default_label='all')}, "
            f"header={'present' if header is not None else 'absent'}"
        ),
    ]


def config_discovery_lines(config: Config) -> list[str]:
    """Return concise discovery and active-config lines for run/stage startup."""

    if config.active_path is None:
        active = "none (using defaults)"
    elif config.explicit:
        active = f"{_display_path(config.active_path)} (explicit)"
    else:
        active = _display_path(config.active_path)

    found = ", ".join(_display_path(path) for path in config.found) if config.found else "none"
    searched = (
        ", ".join(_display_path(path) for path in config.searched)
        if config.searched
        else "not searched"
    )
    return [
        f"active: {active}",
        f"found: {found}",
        f"searched: {searched}",
        *config_value_summary_lines(config.values),
    ]


def validate_config_file_message(path: Path | str) -> str:
    """Validate exactly one JSON local config file and return a readable summary."""

    config = load_config(explicit_path=Path(path))
    return "\n".join(
        (
            f"Config valid: {_display_path(config.active_path or Path(path))}",
            "Found:",
            *(f"  {line}" for line in config_value_summary_lines(config.values)),
        )
    )


def _discovery_candidates(base_dir: Path, work_root: Path | None) -> tuple[Path, ...]:
    candidates: list[Path] = []
    if work_root is not None:
        candidates.append(work_root / LOCAL_CONFIG_FILENAME)
    candidates.append(base_dir / LOCAL_CONFIG_FILENAME)

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path.expanduser().resolve(strict=False))
        if key in seen:
            continue
        deduped.append(path)
        seen.add(key)
    return tuple(deduped)


def _read_config_file(path: Path) -> dict[str, Any]:
    if path.is_dir():
        raise InputError(
            f"Config path is a directory, not a config file: {_display_path(path)}. "
            "Use --work-root <DIR> for output directories."
        )
    if not path.is_file():
        raise InputError(
            f"Config file not found: {_display_path(path)}. "
            "--config expects a JSON local config file; use --work-root <DIR> "
            "for output directories."
        )
    if path.suffix.lower() != ".json":
        raise InputError(
            f"Unsupported config extension for {_display_path(path)}: {path.suffix or '<none>'}. "
            "RepoLens local runtime config is JSON-only; use .repolens.local.json "
            "or pass a .json file."
        )

    try:
        loaded = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"Invalid JSON config: {_display_path(path)} at line {exc.lineno}, "
            f"column {exc.colno}. Fix: use a valid JSON object."
        ) from exc
    except ValueError as exc:
        raise InputError(
            f"Invalid JSON config: {_display_path(path)}. Fix: use strict JSON values."
        ) from exc
    except OSError as exc:
        raise InputError(f"Could not read config file: {_display_path(path)}") from exc

    if not isinstance(loaded, dict):
        raise InputError(
            f"Invalid config {_display_path(path)}: root: expected object; "
            f"got {_json_type_name(loaded)}. Fix: wrap settings in a JSON object."
        )
    if not all(isinstance(key, str) for key in loaded):
        raise InputError(
            f"Invalid config {_display_path(path)}: root: expected string keys. "
            "Fix: use JSON object property names."
        )

    validate_config_values(loaded, path=path)
    return loaded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _first_blank_string_path(value: object, path: tuple[str, ...] = ()) -> tuple[str, ...] | None:
    if isinstance(value, str):
        return path if not value.strip() else None
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if isinstance(key, str) and not key.strip():
                return (*path, key_text)
            found = _first_blank_string_path(child, (*path, key_text))
            if found is not None:
                return found
    if isinstance(value, list):
        for index, child in enumerate(value):
            found = _first_blank_string_path(child, (*path, str(index)))
            if found is not None:
                return found
    return None


def _schema_error_message(error: Any, path: Path | None) -> str:
    key_path = _error_key_path(error)
    expected = _expected_from_error(error)
    actual = _json_type_name(error.instance)
    fix = _fix_hint(error)
    location = f" {_display_path(path)}" if path is not None else ""
    return f"Invalid config{location}: {key_path}: expected {expected}; got {actual}. Fix: {fix}"


def _error_key_path(error: Any) -> str:
    parts = [str(part) for part in error.absolute_path]
    if error.validator == "additionalProperties":
        unexpected = _unexpected_property(error)
        if unexpected:
            parts.append(unexpected)
    return ".".join(parts) if parts else "root"


def _unexpected_property(error: Any) -> str | None:
    if isinstance(error.instance, dict):
        allowed = set(error.schema.get("properties", {}))
        unexpected = sorted(str(key) for key in error.instance if key not in allowed)
        if unexpected:
            return unexpected[0]
    match = re.search(r"'([^']+)' was unexpected", error.message)
    return match.group(1) if match else None


def _expected_from_error(error: Any) -> str:
    if error.validator == "additionalProperties":
        return "a supported config key"
    if error.validator == "type":
        return _schema_type_label(error.validator_value)
    if error.validator == "required":
        missing = _missing_required_property(error)
        return f"required key {missing}" if missing else "all required keys"
    if error.validator == "minLength":
        return "a non-empty string"
    if error.validator == "minItems":
        return "at least one item"
    if error.validator == "exclusiveMinimum":
        return f"a number greater than {error.validator_value}"
    return error.message


def _fix_hint(error: Any) -> str:
    if error.validator == "additionalProperties":
        return "Remove the unknown key or run `repolens config schema` for supported keys."
    if error.validator == "required":
        missing = _missing_required_property(error)
        return f"Add {missing} or remove the incomplete object."
    if error.validator in {"type", "minLength", "minItems", "exclusiveMinimum"}:
        return "Use the type/value shown by `repolens config schema`."
    return "Update the value to match `repolens config schema`."


def _missing_required_property(error: Any) -> str | None:
    match = re.search(r"'([^']+)' is a required property", error.message)
    return match.group(1) if match else None


def _schema_type_label(value: object) -> str:
    if isinstance(value, list):
        return " or ".join(str(item) for item in value)
    return str(value)


def _json_type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int | float):
        return "number"
    return type(value).__name__


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _count_or_default(value: object, *, default_label: str = "default") -> str:
    if isinstance(value, list):
        return str(len(value))
    return default_label


def _display_path(path: Path) -> str:
    return str(path)
