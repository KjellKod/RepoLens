from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repolens.config import load_config
from repolens.exit_codes import InputError


class ConfigTests(unittest.TestCase):
    def test_load_config_merges_with_documented_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "base.local.json").write_text(
                '{"shared": {"kept": "json", "value": "json"}, "only_json": true}',
                encoding="utf-8",
            )
            (root / "base.local.yml").write_text(
                "shared:\n  value: yml\nonly_yml: true\n",
                encoding="utf-8",
            )
            (root / "base.local.yaml").write_text(
                "shared:\n  value: yaml\nonly_yaml: true\n",
                encoding="utf-8",
            )
            (root / "base.local.toml").write_text(
                "only_toml = true\n\n[shared]\nvalue = 'toml'\n",
                encoding="utf-8",
            )
            explicit = root / "override.local.json"
            explicit.write_text('{"shared": {"value": "explicit"}}', encoding="utf-8")

            config = load_config(root, explicit)

        self.assertEqual(config.values["shared"]["value"], "explicit")
        self.assertEqual(config.values["shared"]["kept"], "json")
        self.assertTrue(config.values["only_json"])
        self.assertTrue(config.values["only_yml"])
        self.assertTrue(config.values["only_yaml"])
        self.assertTrue(config.values["only_toml"])

    def test_yaml_unsafe_tag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.local.yaml").write_text(
                "payload: !!python/object/apply:os.system ['echo bad']\n",
                encoding="utf-8",
            )

            with self.assertRaises(InputError):
                load_config(root)

    def test_source_uses_safe_yaml_loader(self) -> None:
        source = Path("src/repolens/config.py").read_text(encoding="utf-8")
        self.assertIn("safe_load", source)
        self.assertNotIn("yaml.load(", source)
        self.assertNotIn("full_load", source)


if __name__ == "__main__":
    unittest.main()
