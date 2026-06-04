from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from repolens.config import (
    Config,
    config_discovery_lines,
    config_value_summary_lines,
    human_schema_text,
    load_config,
    validate_config_file_message,
)
from repolens.exit_codes import InputError


class ConfigTests(unittest.TestCase):
    def test_explicit_json_config_wins_without_neighbor_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_root = root / "work"
            work_root.mkdir()
            (root / ".repolens.local.json").write_text(
                json.dumps({"scan": {"exclude_paths": ["cwd-only/"]}}),
                encoding="utf-8",
            )
            (work_root / ".repolens.local.json").write_text(
                json.dumps({"scan": {"exclude_paths": ["work-only/"]}}),
                encoding="utf-8",
            )
            explicit = root / "repolens.local.json"
            explicit.write_text(
                json.dumps({"scan": {"exclude_paths": ["explicit-only/"]}}),
                encoding="utf-8",
            )

            config = load_config(root, explicit, work_root=work_root)

        self.assertEqual(config.values, {"scan": {"exclude_paths": ["explicit-only/"]}})
        self.assertEqual(config.sources, (explicit,))
        self.assertEqual(config.active_path, explicit)
        self.assertTrue(config.explicit)

    def test_work_root_hidden_config_precedes_cwd_hidden_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_root = root / "work"
            work_root.mkdir()
            cwd_config = root / ".repolens.local.json"
            work_config = work_root / ".repolens.local.json"
            cwd_config.write_text(
                json.dumps({"scan": {"exclude_paths": ["cwd-only/"]}}),
                encoding="utf-8",
            )
            work_config.write_text(
                json.dumps({"scan": {"exclude_paths": ["work-only/"]}}),
                encoding="utf-8",
            )

            config = load_config(root, work_root=work_root)

        self.assertEqual(config.values, {"scan": {"exclude_paths": ["work-only/"]}})
        self.assertEqual(config.sources, (work_config,))
        self.assertEqual(config.found, (work_config, cwd_config))
        self.assertEqual(config.active_path, work_config)
        self.assertFalse(config.explicit)

    def test_missing_discovered_config_uses_defaults_with_search_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_root = root / "work"

            config = load_config(root, work_root=work_root)

        self.assertEqual(config.values, {})
        self.assertEqual(config.sources, ())
        self.assertEqual(config.found, ())
        self.assertEqual(
            config.searched,
            (work_root / ".repolens.local.json", root / ".repolens.local.json"),
        )

    def test_explicit_toml_and_yaml_are_rejected_even_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("repolens.local.toml", "repolens.local.yaml", "repolens.local.yml"):
                path = root / name
                path.write_text("", encoding="utf-8")
                with self.subTest(name=name), self.assertRaisesRegex(InputError, "JSON-only"):
                    load_config(root, path)

    def test_explicit_config_directory_points_to_work_root_option(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "output"
            output_dir.mkdir()

            with self.assertRaisesRegex(
                InputError,
                "Config path is a directory.*--work-root <DIR>",
            ):
                load_config(root, output_dir)

    def test_missing_explicit_config_points_to_work_root_option(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            with self.assertRaisesRegex(
                InputError,
                "Config file not found.*Expected a JSON local config file",
            ):
                load_config(root, root / "missing.local.json")

    def test_explicit_config_and_validate_expand_tilde(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            path = home / ".repolens.local.json"
            path.write_text(json.dumps({"scan": {"exclude_paths": [".github/"]}}), encoding="utf-8")

            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                config = load_config(root, "~/.repolens.local.json")
                message = validate_config_file_message("~/.repolens.local.json")

        self.assertEqual(config.active_path, path)
        self.assertEqual(config.sources, (path,))
        self.assertIn(f"Config valid: {path}", message)

    def test_unknown_config_key_is_rejected_with_path_and_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".repolens.local.json"
            path.write_text(json.dumps({"discover": {"taxonmy": {}}}), encoding="utf-8")

            with self.assertRaisesRegex(InputError, "discover\\.taxonmy.*Remove the unknown key"):
                load_config(root, path)

    def test_non_strict_json_constants_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".repolens.local.json"
            path.write_text('{"scan": {"clone_timeout_seconds": NaN}}', encoding="utf-8")

            with self.assertRaisesRegex(InputError, "strict JSON values"):
                load_config(root, path)

    def test_json_null_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".repolens.local.json"
            path.write_text("null", encoding="utf-8")

            with self.assertRaisesRegex(InputError, "root: expected object; got null"):
                load_config(root, path)

    def test_blank_strings_are_rejected_by_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".repolens.local.json"
            path.write_text(
                json.dumps({"discover": {"taxonomy": {"explicit": {"sentinel": " "}}}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(InputError, "discover\\.taxonomy\\.explicit\\.sentinel"):
                load_config(root, path)

    def test_validate_message_summarizes_selected_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".repolens.local.json"
            path.write_text(
                json.dumps(
                    {
                        "discover": {
                            "taxonomy": {
                                "explicit": {"sentinel-owner/sentinel-alpha": "runtime"},
                                "patterns": [{"glob": "tool-*", "category": "tools"}],
                                "topics": {"mobile": "apps"},
                                "dead": {"sentinel-retired": "retired"},
                            }
                        },
                        "scan": {
                            "exclude_paths": ["fixtures/"],
                            "clone_timeout_seconds": 45,
                            "syft": {"catalogers": ["python-package-cataloger"]},
                        },
                        "report": {
                            "selection": {"include": ["runtime", "apps"]},
                            "header": {"org_name": "Sentinel", "legal_text": "Internal only"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            message = validate_config_file_message(path)

        self.assertIn("Config valid:", message)
        self.assertIn("explicit=1, patterns=1, topics=1, dead=1", message)
        self.assertIn("exclude_paths=1, clone_timeout_seconds=45, syft.catalogers=1", message)
        self.assertIn("include=2, header=present", message)

    def test_schema_text_and_discovery_summary_are_readable(self) -> None:
        schema = human_schema_text()
        self.assertIn("RepoLens local config schema", schema)
        self.assertIn("scan.clone_timeout_seconds", schema)
        self.assertIn("TOML, YAML, and YML are not runtime-config formats", schema)

        config = Config(values={}, sources=())
        self.assertIn("active: none (using defaults)", config_discovery_lines(config))
        self.assertIn(
            "discover.taxonomy: default=uncategorized, explicit=0, patterns=0, topics=0, dead=0",
            config_value_summary_lines({}),
        )


if __name__ == "__main__":
    unittest.main()
