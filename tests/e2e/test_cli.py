from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from repolens import cli


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
        self.assertEqual(cli.main(["scan"]), 0)

    def test_stage_command_routes_findings_open_to_one(self) -> None:
        self.assertEqual(cli.main(["scan", "--findings-open"]), 1)

    def test_discover_requires_owner(self) -> None:
        self.assertEqual(cli.main(["discover"]), 2)

    def test_discover_routes_to_real_handler(self) -> None:
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.cli.run_discover") as run_discover,
        ):
            run_discover.return_value = mock.Mock(
                repository_count=1,
                candidate_count=1,
                hard_exclusion_count=0,
                discovered_path="work/discovered.json",
                candidate_path="work/repos.candidate.md",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main(["discover", "--owner", "sentinel-owner", "--work-root", "work"])

        self.assertEqual(code, 0)
        run_discover.assert_called_once()
        self.assertEqual(run_discover.call_args.kwargs["owner"], "sentinel-owner")
        self.assertEqual(run_discover.call_args.kwargs["config"], config)
        self.assertFalse(run_discover.call_args.kwargs["force_candidate"])
        output = stdout.getvalue()
        self.assertIn("Discovered 1 repositories", output)
        self.assertIn("work/discovered.json", output)
        self.assertIn("work/repos.candidate.md", output)
        self.assertIn("Next: review", output)

    def test_discover_force_routes_to_real_handler(self) -> None:
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.cli.run_discover") as run_discover,
        ):
            run_discover.return_value = mock.Mock(
                repository_count=1,
                candidate_count=1,
                hard_exclusion_count=0,
                discovered_path="work/discovered.json",
                candidate_path="work/repos.candidate.md",
            )

            code = cli.main(
                [
                    "discover",
                    "--owner",
                    "sentinel-owner",
                    "--work-root",
                    "work",
                    "--force",
                ]
            )

        self.assertEqual(code, 0)
        self.assertTrue(run_discover.call_args.kwargs["force_candidate"])

    def test_usage_error_returns_two(self) -> None:
        self.assertEqual(cli.main(["not-a-command"]), 2)

    def test_malformed_config_returns_two(self) -> None:
        self.assertEqual(
            cli.main(["--config", "missing.local.json", "discover", "--owner", "sentinel-owner"]),
            2,
        )

    def test_internal_error_returns_one_and_sanitizes_output(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch(
                "repolens.cli.load_config",
                side_effect=RuntimeError("token ghp_abc123 path /tmp/acme/private"),
            ),
            redirect_stderr(stderr),
        ):
            code = cli.main(["scan"])

        self.assertEqual(code, 1)
        output = stderr.getvalue()
        self.assertIn("[REDACTED_TOKEN]", output)
        self.assertIn("[REDACTED_PATH]", output)
        self.assertNotIn("ghp_abc123", output)
        self.assertNotIn("/tmp/acme/private", output)


if __name__ == "__main__":
    unittest.main()
