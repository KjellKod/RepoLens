from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from repolens import cli
from repolens.config import load_config
from repolens.exit_codes import InputError

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / ".github" / "scripts" / "name_hygiene_guard.py"


class F1OfflineCanaries(unittest.TestCase):
    def test_local_config_patterns_are_ignored(self) -> None:
        for name in (
            "tmp.local.toml",
            "tmp.local.yaml",
            "tmp.local.yml",
            "tmp.local.json",
        ):
            result = subprocess.run(
                ["git", "check-ignore", "-q", name],
                cwd=ROOT,
            )
            self.assertEqual(result.returncode, 0, name)

    def test_exit_code_contract_canary(self) -> None:
        self.assertEqual(cli.main(["discover"]), 0)
        self.assertEqual(cli.main(["discover", "--findings-open"]), 1)
        self.assertEqual(cli.main(["bad-command"]), 2)

    def test_yaml_unsafe_tag_canary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "unsafe.local.yml").write_text(
                "value: !!python/object/apply:os.system ['echo bad']\n",
                encoding="utf-8",
            )
            with self.assertRaises(InputError):
                load_config(root)

    def test_name_hygiene_seeded_bad_term_fails(self) -> None:
        term = "acme-" + "blocked-token"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture.txt"
            target.write_text(f"{term}\n", encoding="utf-8")
            env = {**os.environ, "REPOLENS_NAME_DENYLIST": term}
            result = subprocess.run(
                [sys.executable, str(GUARD), str(target)],
                env=env,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_name_hygiene_clean_tree_passes_with_denylist(self) -> None:
        term = "acme-" + "blocked-token"
        env = {**os.environ, "REPOLENS_NAME_DENYLIST": term}
        result = subprocess.run(
            [sys.executable, str(GUARD), "src", "docs", ".github/scripts"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
