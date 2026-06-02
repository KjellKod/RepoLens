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
GUARD_MODULE = "repolens.security.name_hygiene"


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
        self.assertEqual(cli.main(["shortlist"]), 0)
        self.assertEqual(cli.main(["shortlist", "--findings-open"]), 1)
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
            target = Path(tmp)
            (target / "fixture.txt").write_text(f"{term}\n", encoding="utf-8")
            env = {**os.environ, "REPOLENS_FORBIDDEN_NAMES": term}
            result = subprocess.run(
                [sys.executable, "-m", GUARD_MODULE, "--root", str(target), "--require-denylist"],
                env=env,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        # The forbidden literal must never be echoed; findings are reported by token id.
        self.assertNotIn(term, result.stdout)
        self.assertNotIn(term, result.stderr)
        self.assertIn("sha256:", result.stdout)

    def test_name_hygiene_clean_tree_passes_with_denylist(self) -> None:
        term = "acme-" + "blocked-token"
        env = {**os.environ, "REPOLENS_FORBIDDEN_NAMES": term}
        result = subprocess.run(
            [sys.executable, "-m", GUARD_MODULE, "--root", "src", "--require-denylist"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
