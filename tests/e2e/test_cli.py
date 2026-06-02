from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from repolens import cli
from repolens.data import store


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
        self.assertEqual(cli.main(["flag"]), 0)

    def test_stage_command_routes_findings_open_to_one(self) -> None:
        self.assertEqual(cli.main(["flag", "--findings-open"]), 1)

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
            code = cli.main(["flag"])

        self.assertEqual(code, 1)
        output = stderr.getvalue()
        self.assertIn("[REDACTED_TOKEN]", output)
        self.assertIn("[REDACTED_PATH]", output)
        self.assertNotIn("ghp_abc123", output)
        self.assertNotIn("/tmp/acme/private", output)

    def test_report_command_writes_main_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            work_root = Path(tmp)
            out_dir = work_root / "out"
            store.write_resolved(
                work_root,
                "acme-alpha",
                [
                    {
                        "schema_version": "1.0",
                        "name": "acme-lib",
                        "version": "1.2.3",
                        "repo": "acme-alpha",
                        "purl": "pkg:pypi/acme-lib@1.2.3",
                        "declared_license_raw": "MIT",
                        "spdx_id": "MIT",
                        "evidence": {
                            "source_layer": "syft",
                            "url": "https://example.invalid/licenses/mit",
                        },
                        "tags": {
                            "origin": "third-party-oss",
                            "scope": "runtime",
                            "distribution": "server",
                        },
                        "modified": "unknown",
                    }
                ],
            )

            code = cli.main(["report", "--work-root", str(work_root), "--out-dir", str(out_dir)])

            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "report.main.md").exists())
            self.assertTrue((out_dir / "report.main.csv").exists())

    def test_report_missing_work_root_returns_two(self) -> None:
        with TemporaryDirectory() as tmp:
            work_root = Path(tmp)

            code = cli.main(
                ["report", "--work-root", str(work_root), "--out-dir", str(work_root / "out")]
            )

            self.assertEqual(code, 2)


def _fake_clone(options):
    destination = Path(options.destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "README.md").write_text("acme\n", encoding="utf-8")
    return destination


def _syft_document() -> dict:
    return {
        "descriptor": {"name": "syft", "version": "1.18.1"},
        "artifacts": [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": [{"value": "MIT"}],
                "locations": [{"path": "requirements.txt"}],
            }
        ],
    }


class ScanCliTests(unittest.TestCase):
    def _scaffold(self, work_root: Path, repos: list[dict]) -> Path:
        (work_root / "tools").mkdir(parents=True, exist_ok=True)
        (work_root / "tools" / "syft").write_text("#!/bin/sh\n", encoding="utf-8")
        repos_path = work_root / "repos.json"
        repos_path.write_text(json.dumps({"repos": repos}), encoding="utf-8")
        return repos_path

    def test_scan_arg_parse_and_routing_missing_args(self) -> None:
        # `scan` now requires --work-root / --repos; argparse errors map to exit 2.
        self.assertEqual(cli.main(["scan"]), 2)

    def test_scan_happy_path_persists_sbom_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            with (
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            self.assertTrue(store.is_repo_scanned(work_root, "acme-alpha"))

    def test_scan_mixed_run_persists_successes_and_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [
                    {"repo_ref": "acme-ok", "clone_url": "https://example.invalid/acme-ok"},
                    {"repo_ref": "acme-bad", "clone_url": "https://example.invalid/acme-bad"},
                ],
            )

            def fake_runner(argv, *, timeout):
                if "acme-bad" in argv[2]:
                    return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="boom")
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = io.StringIO()
            with (
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 1)
            self.assertTrue(store.is_repo_scanned(work_root, "acme-ok"))
            self.assertFalse(store.is_repo_scanned(work_root, "acme-bad"))

    def test_scan_missing_syft_binary_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            work_root.mkdir(parents=True)
            repos_path = work_root / "repos.json"
            repos_path.write_text(
                json.dumps(
                    {
                        "repos": [
                            {"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/x"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])
            self.assertEqual(code, 2)

    def test_scan_bad_repo_list_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._scaffold(
                work_root, [{"repo_ref": "acme-alpha", "clone_url": "ftp://example.invalid/x"}]
            )
            repos_path = work_root / "repos.json"
            code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])
            self.assertEqual(code, 2)

    def test_scan_malformed_https_clone_url_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root, [{"repo_ref": "acme-alpha", "clone_url": "https:///acme-alpha"}]
            )
            code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])
            self.assertEqual(code, 2)

    def test_scan_credentialed_clone_url_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [
                    {
                        "repo_ref": "acme-alpha",
                        "clone_url": "https://user:secret@example.invalid/acme-alpha",
                    }
                ],
            )
            code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])
            self.assertEqual(code, 2)

    def test_scan_non_finite_timeout_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            code = cli.main(
                [
                    "scan",
                    "--work-root",
                    str(work_root),
                    "--repos",
                    str(repos_path),
                    "--timeout",
                    "nan",
                ]
            )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
