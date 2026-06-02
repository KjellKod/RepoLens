from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

from repolens import cli
from repolens.cli import CommandResult, CommandStatus


class CliTests(unittest.TestCase):
    def test_help_returns_success(self) -> None:
        self.assertEqual(cli.main(["--help"]), 0)

    def test_console_help_returns_success(self) -> None:
        result = subprocess.run(
            ["repolens", "--help"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("discover", result.stdout)

    def test_stage_command_routes_to_success(self) -> None:
        self.assertEqual(cli.main(["discover"]), 0)

    def test_stage_command_routes_findings_open_to_one(self) -> None:
        self.assertEqual(cli.main(["discover", "--findings-open"]), 1)

    def test_usage_error_returns_two(self) -> None:
        self.assertEqual(cli.main(["not-a-command"]), 2)

    def test_malformed_config_returns_two(self) -> None:
        self.assertEqual(cli.main(["--config", "missing.local.json", "discover"]), 2)

    def test_internal_error_returns_one_and_sanitizes_output(self) -> None:
        stderr = io.StringIO()
        with mock.patch(
            "repolens.cli.load_config",
            side_effect=RuntimeError("token ghp_abc123 path /tmp/acme/private"),
        ):
            with redirect_stderr(stderr):
                code = cli.main(["discover"])

        self.assertEqual(code, 1)
        output = stderr.getvalue()
        self.assertIn("[REDACTED_TOKEN]", output)
        self.assertIn("[REDACTED_PATH]", output)
        self.assertNotIn("ghp_abc123", output)
        self.assertNotIn("/tmp/acme/private", output)


if __name__ == "__main__":
    unittest.main()
