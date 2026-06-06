from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from repolens import cli
from repolens.data import store
from repolens.scan.runner import ScanProgressEvent


class _TtyStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


class CliTests(unittest.TestCase):
    def test_help_returns_success(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(["--help"])

        self.assertEqual(code, 0)
        help_text = stdout.getvalue()
        self.assertIn("global options:", help_text)
        self.assertIn(
            "`repolens --config ./.repolens.local.json discover --owner <OWNER>`",
            help_text,
        )
        self.assertIn("owner is still supplied at runtime with --owner", help_text)
        self.assertIn("Use stage options such as --work-root", help_text)
        self.assertIn("Common local config commands:", help_text)
        self.assertIn("`repolens config init --work-root work`", help_text)
        self.assertIn("`repolens config schema`", help_text)
        self.assertIn("`repolens config validate ./.repolens.local.json`", help_text)
        self.assertIn("repolens resolve --work-root work", help_text)

    def test_config_without_action_prints_help(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(["config"])

        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        help_text = stdout.getvalue()
        self.assertIn("usage: repolens config", help_text)
        self.assertIn("repolens config init", help_text)
        self.assertIn("repolens config schema", help_text)
        self.assertIn("repolens config validate", help_text)

    def test_config_help_after_missing_path_returns_root_help(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(["--config", "--help"])

        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        help_text = stdout.getvalue()
        self.assertIn("usage: repolens", help_text)
        self.assertIn("--config PATH", help_text)

    def test_config_without_path_still_errors(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cli.main(["--config"])

        self.assertEqual(code, 2)
        self.assertIn("argument --config: expected one argument", stderr.getvalue())

    def test_each_stage_help_is_actionable(self) -> None:
        expected_stages = {
            "discover": "Stage 1/6",
            "scan": "Stage 2/6",
            "resolve": "Stage 3/6",
            "flag": "Stage 4/6",
            "shortlist": "Stage 5/6",
            "report": "Stage 6/6",
        }

        for stage, marker in expected_stages.items():
            with self.subTest(stage=stage):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = cli.main([stage, "--help"])

                help_text = stdout.getvalue()
                self.assertEqual(code, 0)
                self.assertIn(marker, help_text)
                self.assertIn("Before:", help_text)
                self.assertIn("Example:", help_text)
                self.assertIn("Output:", help_text)
                self.assertIn("Next:", help_text)

    def test_resolve_help_explains_default_repo_selection(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(["resolve", "--help"])

        self.assertEqual(code, 0)
        help_text = stdout.getvalue()
        self.assertIn("Syft SBOMs from scan at <WORK>/work/*/sbom.syft.json", help_text)
        self.assertIn("omit to resolve checked", help_text)
        self.assertIn("scan output", help_text)
        self.assertIn("repolens resolve --work-root <WORK>", help_text)

    def test_resolve_without_repo_ref_resolves_all_scanned_repos(self) -> None:
        with TemporaryDirectory() as temp_dir:
            work_root = Path(temp_dir)
            store.write_sbom(work_root, "sentinel-alpha", _repo_sbom("sentinel-alpha"))
            store.write_sbom(work_root, "sentinel-beta", _repo_sbom("sentinel-beta"))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main(["resolve", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            output = stdout.getvalue()
            self.assertIn("resolved 2 repos: sentinel-alpha, sentinel-beta", output)
            self.assertIn(f"Next CLI stage: repolens flag --work-root {work_root}", output)
            self.assertTrue((work_root / "work" / "sentinel-alpha" / "resolved.ndjson").exists())
            self.assertTrue((work_root / "work" / "sentinel-beta" / "resolved.ndjson").exists())

    def test_console_help_returns_success(self) -> None:
        result = subprocess.run(
            ["repolens", "--help"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("discover", result.stdout)

    def test_shortlist_requires_work_root(self) -> None:
        self.assertEqual(cli.main(["shortlist"]), 2)

    def test_shortlist_command_clean_exit_zero(self) -> None:
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.shortlist.run_shortlist") as run_shortlist,
        ):
            run_shortlist.return_value = mock.Mock(
                open_count=0,
                item_count=2,
                shortlist_json_path=Path("work/shortlist.json"),
                shortlist_md_path=Path("work/shortlist.md"),
            )
            code = cli.main(["shortlist", "--work-root", "work"])

        self.assertEqual(code, 0)

    def test_shortlist_command_findings_open_exit(self) -> None:
        # ExitCode.FINDINGS_OPEN == 1 (not 2); mirrors flag's _exit_code_for_result.
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.shortlist.run_shortlist") as run_shortlist,
        ):
            run_shortlist.return_value = mock.Mock(
                open_count=1,
                item_count=2,
                shortlist_json_path=Path("work/shortlist.json"),
                shortlist_md_path=Path("work/shortlist.md"),
            )
            code = cli.main(["shortlist", "--work-root", "work", "--identity", "reviewer-sentinel"])

        self.assertEqual(code, 1)
        self.assertEqual(run_shortlist.call_args.kwargs["identity"], "reviewer-sentinel")

    def test_shortlist_accepts_emit_contexts_and_proposals_flags(self) -> None:
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.shortlist.run_shortlist") as run_shortlist,
        ):
            run_shortlist.return_value = mock.Mock(
                open_count=1,
                item_count=2,
                shortlist_json_path=Path("work/shortlist.json"),
                shortlist_md_path=Path("work/shortlist.md"),
                contexts_path=Path("work/shortlist.contexts.json"),
            )
            code = cli.main(
                [
                    "shortlist",
                    "--work-root",
                    "work",
                    "--emit-contexts",
                    "work/shortlist.contexts.json",
                    "--proposals",
                    "work/shortlist.proposals.json",
                ]
            )

        self.assertEqual(code, 1)
        self.assertEqual(
            run_shortlist.call_args.kwargs["emit_contexts_path"],
            Path("work/shortlist.contexts.json"),
        )
        self.assertEqual(
            run_shortlist.call_args.kwargs["proposals_path"],
            Path("work/shortlist.proposals.json"),
        )

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
        self.assertIn(
            "Manual step: open work/repos.candidate.md, untick any repos you want to exclude",
            output,
        )
        self.assertIn("Next: prepare work-root tools: repolens bootstrap --work-root work", output)
        self.assertIn("Next CLI stage: repolens scan --work-root work", output)

    def test_discover_repos_routes_to_fetch_path(self) -> None:
        config = cli.load_config(".", None)
        with (
            mock.patch("repolens.cli.load_config", return_value=config),
            mock.patch("repolens.cli.run_discover") as run_discover,
        ):
            run_discover.return_value = mock.Mock(
                repository_count=2,
                candidate_count=2,
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
                    "--repos",
                    "sentinel-alpha, sentinel-beta",
                ]
            )

        self.assertEqual(code, 0)
        # --repos parses to a validated, ordered tuple and reaches the fetch path.
        self.assertEqual(
            run_discover.call_args.kwargs["repos"],
            ("sentinel-alpha", "sentinel-beta"),
        )

    def test_discover_without_repos_uses_list_path(self) -> None:
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

            code = cli.main(["discover", "--owner", "sentinel-owner", "--work-root", "work"])

        self.assertEqual(code, 0)
        # Omitting --repos yields repos=None (the enumerate path).
        self.assertIsNone(run_discover.call_args.kwargs["repos"])

    def test_discover_empty_repos_value_is_usage_error(self) -> None:
        with mock.patch("repolens.cli.run_discover") as run_discover:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = cli.main(["discover", "--owner", "sentinel-owner", "--repos", ""])

        self.assertEqual(code, 2)
        run_discover.assert_not_called()
        self.assertIn("at least one repo name", stderr.getvalue())

    def test_discover_next_step_remembers_work_root(self) -> None:
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
                code = cli.main(
                    ["discover", "--owner", "sentinel-owner", "--work-root", "/tmp/repo1"]
                )

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("repolens bootstrap --work-root /tmp/repo1", output)
        self.assertIn("repolens scan --work-root /tmp/repo1", output)

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

            stderr = io.StringIO()
            with redirect_stderr(stderr):
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
        self.assertIn(
            "discards prior checkbox/tick edits",
            stderr.getvalue(),
        )

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
            code = cli.main(["shortlist", "--work-root", "work"])

        self.assertEqual(code, 1)
        output = stderr.getvalue()
        self.assertIn("[REDACTED_TOKEN]", output)
        self.assertIn("[REDACTED_PATH]", output)
        self.assertNotIn("ghp_abc123", output)
        self.assertNotIn("/tmp/acme/private", output)

    def test_usage_error_keeps_operator_paths_but_redacts_tokens(self) -> None:
        token = "ghp_" + "Z" * 12
        stderr = io.StringIO()
        with (
            mock.patch(
                "repolens.cli.load_config",
                side_effect=cli.InputError(f"missing /tools/syft with {token}"),
            ),
            redirect_stderr(stderr),
        ):
            code = cli.main(["shortlist", "--work-root", "work"])

        self.assertEqual(code, 2)
        output = stderr.getvalue()
        self.assertIn("/tools/syft", output)
        self.assertIn("[REDACTED_TOKEN]", output)
        self.assertNotIn(token, output)

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

            config_path = _report_config_path(work_root)
            code = cli.main(
                [
                    "--config",
                    str(config_path),
                    "report",
                    "--work-root",
                    str(work_root),
                    "--out-dir",
                    str(out_dir),
                ]
            )

            self.assertEqual(code, 0)
            self.assertTrue((out_dir / "report.main.md").exists())
            self.assertTrue((out_dir / "report.main.csv").exists())
            self.assertTrue((out_dir / "report.main.html").exists())
            self.assertTrue((out_dir / "report.main.docx").exists())
            self.assertTrue((out_dir / "report.presentation.md").exists())
            self.assertTrue((out_dir / "report.presentation.csv").exists())
            self.assertTrue((out_dir / "report.presentation.html").exists())
            self.assertTrue((out_dir / "report.presentation.docx").exists())

    def test_report_missing_work_root_returns_two(self) -> None:
        with TemporaryDirectory() as tmp:
            work_root = Path(tmp)
            config_path = _report_config_path(work_root)

            code = cli.main(
                [
                    "--config",
                    str(config_path),
                    "report",
                    "--work-root",
                    str(work_root),
                    "--out-dir",
                    str(work_root / "out"),
                ]
            )

            self.assertEqual(code, 2)

    def test_report_cli_exit_findings_open_when_shortlist_open(self) -> None:
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
                        "evidence": {"source_layer": "syft"},
                        "tags": {
                            "origin": "third-party-oss",
                            "scope": "runtime",
                            "distribution": "server",
                        },
                        "modified": "unknown",
                    }
                ],
            )
            store.atomic_write_json(
                work_root / "shortlist.json",
                {
                    "schema_version": "1.0",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "open_count": 1,
                    "items": [{"status": "open"}],
                },
            )

            code = cli.main(["report", "--work-root", str(work_root), "--out-dir", str(out_dir)])

            self.assertEqual(code, 1)
            self.assertFalse((out_dir / "report.main.csv").exists())
            self.assertFalse((out_dir / "report.presentation.csv").exists())

    def test_report_cli_skips_docx_when_header_missing_non_interactive(self) -> None:
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
                        "evidence": {"source_layer": "syft"},
                        "tags": {
                            "origin": "third-party-oss",
                            "scope": "runtime",
                            "distribution": "server",
                        },
                        "modified": "unknown",
                    }
                ],
            )

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = cli.main(
                    ["report", "--work-root", str(work_root), "--out-dir", str(out_dir)]
                )

            self.assertEqual(code, 0)
            self.assertIn("docx files skipped (no report.header)", stderr.getvalue())
            self.assertTrue((out_dir / "report.main.md").exists())
            self.assertTrue((out_dir / "report.main.csv").exists())
            self.assertTrue((out_dir / "report.main.html").exists())
            self.assertTrue((out_dir / "report.presentation.md").exists())
            self.assertTrue((out_dir / "report.presentation.csv").exists())
            self.assertTrue((out_dir / "report.presentation.html").exists())
            self.assertFalse((out_dir / "report.main.docx").exists())
            self.assertFalse((out_dir / "report.presentation.docx").exists())

    def test_report_review_cli_accepts_work_root_after_review_action(self) -> None:
        with TemporaryDirectory() as tmp:
            work_root = Path(tmp)
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
                        "declared_license_raw": "MIT OR Apache-2.0",
                        "spdx_id": "MIT OR Apache-2.0",
                        "evidence": {
                            "source_layer": "syft",
                            "url": "https://example.invalid/licenses/acme-lib",
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

            code = cli.main(
                [
                    "report",
                    "review",
                    "--work-root",
                    str(work_root),
                    "--identity",
                    "reviewer-sentinel",
                ]
            )

            self.assertEqual(code, 0)
            self.assertTrue((work_root / "report.review.md").exists())
            payload = json.loads((work_root / "report.review.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["open_count"], 1)

    def test_report_review_decision_flows_to_report_presentation(self) -> None:
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
                        "declared_license_raw": "MIT OR Apache-2.0",
                        "spdx_id": "MIT OR Apache-2.0",
                        "evidence": {
                            "source_layer": "syft",
                            "url": "https://example.invalid/licenses/acme-lib",
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
            self.assertEqual(cli.main(["report", "review", "--work-root", str(work_root)]), 0)
            review_md = work_root / "report.review.md"
            review_md.write_text(
                review_md.read_text(encoding="utf-8").replace("- [ ] `MIT`", "- [x] `MIT`", 1),
                encoding="utf-8",
            )
            self.assertEqual(
                cli.main(
                    [
                        "report",
                        "review",
                        "--work-root",
                        str(work_root),
                        "--identity",
                        "reviewer-sentinel",
                    ]
                ),
                0,
            )

            self.assertEqual(
                cli.main(["report", "--work-root", str(work_root), "--out-dir", str(out_dir)]),
                0,
            )

            presentation = (out_dir / "report.presentation.csv").read_text(encoding="utf-8")
            self.assertIn(
                '"disclosure license (spdx)","detected license (spdx)"',
                presentation,
            )
            self.assertIn('"MIT","MIT OR Apache-2.0"', presentation)


def _fake_clone(options):
    destination = Path(options.destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "README.md").write_text("acme\n", encoding="utf-8")
    return destination


def _report_config_path(work_root: Path) -> Path:
    path = work_root / "report.local.json"
    path.write_text(
        json.dumps(
            {
                "report": {
                    "header": {
                        "org_name": "Example Org",
                        "legal_text": "Example legal notice.",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


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


def _repo_sbom(repo_ref: str) -> dict:
    return {
        "schema_version": "1.0",
        "repo": repo_ref,
        "generated_at": "2026-01-01T00:00:00Z",
        "tool": {"name": "syft", "version": "1.18.1"},
        "source": f"https://example.invalid/{repo_ref}",
        "artifacts": [
            {
                "name": "acme-lib",
                "version": "1.2.3",
                "type": "python",
                "purl": "pkg:pypi/acme-lib@1.2.3",
                "licenses": ["MIT"],
                "locations": ["requirements.txt"],
            }
        ],
    }


def _assert_scan_next_step(testcase: unittest.TestCase, output: str, work_root: Path) -> None:
    testcase.assertEqual(
        output,
        f"Next CLI stage: repolens resolve --work-root {work_root}\n",
    )


class ScanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._ensure_patch = mock.patch(
            "repolens.cli._ensure_syft_for_scan",
            lambda args: Path(args.work_root) / "tools" / "syft",
        )
        self._ensure_patch.start()

    def tearDown(self) -> None:
        if self._ensure_patch is not None:
            self._ensure_patch.stop()

    def _use_real_syft_ensure(self) -> None:
        if self._ensure_patch is not None:
            self._ensure_patch.stop()
            self._ensure_patch = None

    def _scaffold(self, work_root: Path, repos: list[dict]) -> Path:
        (work_root / "tools").mkdir(parents=True, exist_ok=True)
        (work_root / "tools" / "syft").write_text("#!/bin/sh\n", encoding="utf-8")
        repos_path = work_root / "repos.json"
        repos_path.write_text(json.dumps({"repos": repos}), encoding="utf-8")
        return repos_path

    def _discover_bridge_scaffold(
        self,
        work_root: Path,
        *,
        checked: bool = True,
        repo_names: tuple[str, ...] = ("sentinel-alpha",),
    ) -> None:
        (work_root / "tools").mkdir(parents=True, exist_ok=True)
        (work_root / "tools" / "syft").write_text("#!/bin/sh\n", encoding="utf-8")
        store.write_discovered(
            work_root,
            {
                "schema_version": "1.0",
                "generated_at": "2026-01-01T00:00:00Z",
                "owner": "sentinel-owner",
                "repository_count": len(repo_names),
                "candidate_count": len(repo_names),
                "hard_exclusion_count": 0,
                "repositories": [
                    {
                        "name": repo_name,
                        "name_with_owner": f"sentinel-owner/{repo_name}",
                        "url": f"https://example.invalid/{repo_name}",
                        "description": "",
                        "topics": [],
                        "archived": False,
                        "private": False,
                        "category": "runtime-bucket",
                        "category_source": "default",
                        "hard_excluded": False,
                        "exclusion_reason": None,
                    }
                    for repo_name in repo_names
                ],
            },
        )
        checkbox = "x" if checked else " "
        (work_root / "repos.candidate.md").write_text(
            "\n".join(
                [
                    "# Repository candidates",
                    "",
                    "## Candidates",
                    "",
                    *(
                        f"- [{checkbox}] `sentinel-owner/{repo_name}` "
                        "- category `runtime-bucket` (`default`)"
                        for repo_name in repo_names
                    ),
                    "",
                    "## Hard exclusions",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def test_scan_arg_parse_and_routing_missing_args(self) -> None:
        # `scan` requires --work-root; argparse errors map to exit 2.
        self.assertEqual(cli.main(["scan"]), 2)

    def test_resolve_uses_checked_discover_repos_not_stale_work_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(work_root)
            store.write_sbom(work_root, "sentinel-alpha", _repo_sbom("sentinel-alpha"))
            store.write_sbom(work_root, "sentinel-stale", _repo_sbom("sentinel-stale"))

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main(["resolve", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            output = stdout.getvalue()
            self.assertIn("wrote resolved.ndjson", output)
            self.assertIn(f"Next CLI stage: repolens flag --work-root {work_root}", output)
            self.assertTrue((work_root / "work" / "sentinel-alpha" / "resolved.ndjson").exists())
            self.assertFalse((work_root / "work" / "sentinel-stale" / "resolved.ndjson").exists())

    def test_resolve_skips_checked_repos_missing_sboms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(
                work_root,
                repo_names=("sentinel-alpha", "sentinel-missing"),
            )
            store.write_sbom(work_root, "sentinel-alpha", _repo_sbom("sentinel-alpha"))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(["resolve", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            self.assertIn("wrote resolved.ndjson", stdout.getvalue())
            self.assertIn(
                "Warning: resolve skipped checked repos without SBOMs: sentinel-missing",
                stderr.getvalue(),
            )
            self.assertTrue((work_root / "work" / "sentinel-alpha" / "resolved.ndjson").exists())
            self.assertFalse((work_root / "work" / "sentinel-missing" / "resolved.ndjson").exists())

    def test_resolve_falls_back_to_available_sboms_when_checked_artifacts_are_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(work_root, repo_names=("sentinel-missing",))
            store.write_sbom(work_root, "sentinel-available", _repo_sbom("sentinel-available"))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(["resolve", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            self.assertIn("wrote resolved.ndjson", stdout.getvalue())
            self.assertIn(
                "Warning: resolve skipped checked repos without SBOMs: sentinel-missing",
                stderr.getvalue(),
            )
            self.assertTrue(
                (work_root / "work" / "sentinel-available" / "resolved.ndjson").exists()
            )
            self.assertFalse((work_root / "work" / "sentinel-missing" / "resolved.ndjson").exists())

    def test_resolve_falls_back_to_available_sboms_when_approvals_are_mismatched(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(work_root, repo_names=("sentinel-alpha",))
            (work_root / "repos.candidate.md").write_text(
                "\n".join(
                    [
                        "# Repository candidates",
                        "",
                        "## Candidates",
                        "",
                        "- [x] `sentinel-owner/sentinel-missing` "
                        "- category `runtime-bucket` (`default`)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            store.write_sbom(work_root, "sentinel-available", _repo_sbom("sentinel-available"))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli.main(["resolve", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            self.assertIn("wrote resolved.ndjson", stdout.getvalue())
            self.assertIn(
                "Warning: resolve could not use checked discover approvals",
                stderr.getvalue(),
            )
            self.assertTrue(
                (work_root / "work" / "sentinel-available" / "resolved.ndjson").exists()
            )

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
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            _assert_scan_next_step(self, stdout.getvalue(), work_root)
            self.assertTrue(store.is_repo_scanned(work_root, "acme-alpha"))
            progress = stderr.getvalue()
            self.assertIn("[1/1] acme-alpha — cloning…", progress)
            self.assertRegex(progress, r"\[1/1\] acme-alpha ✓ 1 deps \([0-9.]+s\)")
            self.assertRegex(
                progress,
                r"Done: 1 repos — 1 scanned, 0 skipped, 0 failed in [0-9.]+s\.",
            )

    def test_scan_work_root_defaults_to_checked_discover_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(work_root)
            clone_urls = []

            def clone_spy(options):
                clone_urls.append(options.remote_url)
                return _fake_clone(options)

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            with (
                mock.patch("repolens.scan.runner.hardened_clone", clone_spy),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
            ):
                code = cli.main(["scan", "--work-root", str(work_root)])

            self.assertEqual(code, 0)
            self.assertTrue(store.is_repo_scanned(work_root, "sentinel-alpha"))
            self.assertEqual(
                clone_urls,
                ["https://github.com/sentinel-owner/sentinel-alpha.git"],
            )

    def test_scan_repos_override_wins_without_discover_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [
                    {
                        "repo_ref": "sentinel-override",
                        "clone_url": "https://example.invalid/sentinel-override",
                    }
                ],
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
            self.assertTrue(store.is_repo_scanned(work_root, "sentinel-override"))

    def test_scan_work_root_zero_approved_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            self._discover_bridge_scaffold(work_root, checked=False)

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = cli.main(["scan", "--work-root", str(work_root)])

            self.assertEqual(code, 2)
            self.assertIn("no repos checked in repos.candidate.md", stderr.getvalue())

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
                    return subprocess.CompletedProcess(
                        list(argv), 1, stdout="", stderr="boom at /tmp/acme/private"
                    )
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = io.StringIO()
            with (
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertTrue(store.is_repo_scanned(work_root, "acme-ok"))
            self.assertFalse(store.is_repo_scanned(work_root, "acme-bad"))
            progress = stderr.getvalue()
            self.assertIn("[1/2] acme-ok ✓ 1 deps", progress)
            self.assertIn("[2/2] acme-bad ✗ failed: boom at [REDACTED_PATH]", progress)
            self.assertNotIn("/tmp/acme/private", progress)
            self.assertRegex(
                progress,
                r"Done: 2 repos — 1 scanned, 0 skipped, 1 failed in [0-9.]+s\.",
            )
            self.assertNotIn("Internal error", progress)

    def test_scan_quiet_suppresses_progress_output(self) -> None:
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
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                code = cli.main(
                    [
                        "scan",
                        "--work-root",
                        str(work_root),
                        "--repos",
                        str(repos_path),
                        "--quiet",
                    ]
                )

            self.assertEqual(code, 0)
            _assert_scan_next_step(self, stdout.getvalue(), work_root)
            self.assertEqual(stderr.getvalue(), "")

    def test_scan_private_repo_reports_auth_failure_without_clone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [
                    {
                        "repo_ref": "acme-private",
                        "clone_url": "https://example.invalid/acme-private",
                        "private": True,
                    }
                ],
            )
            clone_calls = []

            def clone_spy(options):
                clone_calls.append(options)
                return _fake_clone(options)

            stderr = io.StringIO()
            with (
                mock.patch("repolens.githost.resolve_clone_credential_result", return_value=None),
                mock.patch("repolens.scan.runner.hardened_clone", clone_spy),
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(clone_calls, [])
            progress = stderr.getvalue()
            self.assertIn(
                "[1/1] acme-private ✗ failed: private repo acme-private needs auth",
                progress,
            )
            self.assertRegex(
                progress,
                r"Done: 1 repos — 0 scanned, 0 skipped, 1 failed in [0-9.]+s\.",
            )
            self.assertIn("1 repos - 0 scanned, 0 skipped, 1 failed", progress)
            self.assertNotIn("Internal error", progress)

    def test_scan_cached_repo_reports_cached_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            store.write_sbom(
                work_root,
                "acme-alpha",
                {
                    "schema_version": "1.0",
                    "repo": "acme-alpha",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "tool": {"name": "syft", "version": "1.18.1"},
                    "source": "https://example.invalid/acme-alpha",
                    "artifacts": [],
                },
            )

            stderr = io.StringIO()
            with (
                mock.patch("repolens.scan.runner.hardened_clone") as clone,
                redirect_stdout(io.StringIO()) as stdout,
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            _assert_scan_next_step(self, stdout.getvalue(), work_root)
            clone.assert_not_called()
            self.assertIn("[1/1] acme-alpha ↻ skipped (cached)", stderr.getvalue())

    def test_scan_tty_rewrites_in_progress_line(self) -> None:
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

            stderr = _TtyStringIO()
            with (
                mock.patch("sys.stderr", stderr),
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stdout(io.StringIO()) as stdout,
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            _assert_scan_next_step(self, stdout.getvalue(), work_root)
            output = stderr.getvalue()
            self.assertIn("\r[1/1] acme-alpha — cloning…", output)
            self.assertIn("\r[1/1] acme-alpha ✓ 1 deps", output)

    def test_scan_progress_heartbeats_when_clone_is_slow(self) -> None:
        stderr = io.StringIO()
        heartbeats = []

        class FakeHeartbeat:
            def __init__(self, interval_seconds, write):
                self.interval_seconds = interval_seconds
                self.write = write
                self.started = False
                self.stopped = False

            def start(self):
                self.started = True

            def stop(self):
                self.stopped = True

        def make_heartbeat(interval_seconds, write):
            heartbeat = FakeHeartbeat(interval_seconds, write)
            heartbeats.append(heartbeat)
            return heartbeat

        printer = cli._ScanProgressPrinter(
            quiet=False,
            stream=stderr,
            heartbeat_interval=30.0,
            heartbeat_factory=make_heartbeat,
        )

        printer(ScanProgressEvent("start", 1, 1, "acme-alpha"))
        heartbeats[0].write(31.0)
        printer(
            ScanProgressEvent(
                "outcome",
                1,
                1,
                "acme-alpha",
                status="scanned",
                deps_count=1,
                elapsed_seconds=0.1,
            )
        )

        output = stderr.getvalue()
        self.assertTrue(heartbeats[0].started)
        self.assertTrue(heartbeats[0].stopped)
        self.assertIn("[1/1] acme-alpha — cloning…", output)
        self.assertIn("still cloning acme-alpha (31s)…", output)
        self.assertIn("[1/1] acme-alpha ✓ 1 deps", output)

    def test_scan_cache_miss_fetches_before_scan(self) -> None:
        self._use_real_syft_ensure()
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
            pin = cli.load_syft_pin()
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch(
                    "repolens.cli.ensure_syft_cached",
                    return_value=SimpleNamespace(path=syft_path, pin=pin, acquired=True),
                ) as ensure,
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            ensure.assert_called_once()
            self.assertEqual(stderr.getvalue().count("First run:"), 1)
            self.assertIn(f"✓ Syft {pin.version} ready", stderr.getvalue())
            self.assertNotIn("Download and install", stderr.getvalue())

    def test_scan_interactive_cache_miss_fetches_without_prompt(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            pin = cli.load_syft_pin()
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = _TtyStringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch(
                    "repolens.cli.ensure_syft_cached",
                    return_value=SimpleNamespace(path=syft_path, pin=pin, acquired=True),
                ) as ensure,
                mock.patch("sys.stdin", _TtyStringIO("")),
                mock.patch("sys.stderr", stderr),
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            ensure.assert_called_once()
            prompt = stderr.getvalue()
            self.assertIn(f"Syft {pin.version}", prompt)
            self.assertNotIn("Download and install", prompt)
            self.assertEqual(prompt.count("First run:"), 1)
            self.assertIn(f"✓ Syft {pin.version} ready", prompt)

    def test_scan_noninteractive_cache_miss_fetches(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            pin = cli.load_syft_pin()
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch(
                    "repolens.cli.ensure_syft_cached",
                    return_value=SimpleNamespace(path=syft_path, pin=pin, acquired=True),
                ) as ensure,
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            ensure.assert_called_once()
            self.assertEqual(stderr.getvalue().count("First run:"), 1)
            self.assertIn(f"✓ Syft {pin.version} ready", stderr.getvalue())
            self.assertNotIn("Download and install", stderr.getvalue())

    def test_scan_noninteractive_cache_miss_prints_acquire_phases_in_order(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            pin = cli.load_syft_pin()
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            def fake_ensure(*, progress):
                for phase in (
                    "download_syft",
                    "download_cosign",
                    "verify_signature",
                    "cache",
                    "ready",
                ):
                    progress(phase, pin)
                return SimpleNamespace(path=syft_path, pin=pin, acquired=True)

            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch("repolens.cli.ensure_syft_cached", side_effect=fake_ensure),
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            output = stderr.getvalue()
            expected = [
                "First run: fetching RepoLens's pinned Syft",
                f"• downloading syft {pin.version}…",
                "• downloading cosign…",
                "• verifying signature…",
                "• caching…",
                f"✓ Syft {pin.version} ready",
                "[1/1] acme-alpha — cloning…",
            ]
            positions = [output.index(text) for text in expected]
            self.assertEqual(positions, sorted(positions))

    def test_scan_quiet_suppresses_acquire_progress(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            pin = cli.load_syft_pin()
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            def fake_ensure(*, progress):
                for phase in (
                    "download_syft",
                    "download_cosign",
                    "verify_signature",
                    "cache",
                    "ready",
                ):
                    progress(phase, pin)
                return SimpleNamespace(path=syft_path, pin=pin, acquired=True)

            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch("repolens.cli.ensure_syft_cached", side_effect=fake_ensure),
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
                redirect_stderr(stderr),
            ):
                code = cli.main(
                    [
                        "scan",
                        "--work-root",
                        str(work_root),
                        "--repos",
                        str(repos_path),
                        "--quiet",
                    ]
                )

            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")

    def test_scan_verify_timeout_surfaces_clear_error(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch(
                    "repolens.cli.ensure_syft_cached",
                    side_effect=cli.IntegrityError(
                        "verifying Syft signature timed out — check network and retry"
                    ),
                ),
                redirect_stderr(stderr),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 1)
            self.assertIn(
                "verifying Syft signature timed out — check network and retry",
                stderr.getvalue(),
            )

    def test_scan_offline_empty_cache_exits_without_fetch(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            stderr = io.StringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=None),
                mock.patch(
                    "repolens.cli.ensure_syft_cached",
                    side_effect=cli.UsageError("cache required /tools/syft"),
                ) as ensure,
                redirect_stderr(stderr),
            ):
                code = cli.main(
                    ["scan", "--work-root", str(work_root), "--repos", str(repos_path), "--offline"]
                )

            self.assertEqual(code, 2)
            ensure.assert_called_once()
            self.assertIn("/tools/syft", stderr.getvalue())

    def test_scan_cache_hit_does_not_prompt_or_fetch(self) -> None:
        self._use_real_syft_ensure()
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "work-root"
            repos_path = self._scaffold(
                work_root,
                [{"repo_ref": "acme-alpha", "clone_url": "https://example.invalid/acme-alpha"}],
            )
            syft_path = work_root / "tools" / "syft"

            def fake_runner(argv, *, timeout):
                return subprocess.CompletedProcess(
                    list(argv), 0, stdout=json.dumps(_syft_document()), stderr=""
                )

            stderr = _TtyStringIO()
            with (
                mock.patch("repolens.cli.cached_syft_path", return_value=syft_path),
                mock.patch("repolens.cli.ensure_syft_cached") as ensure,
                mock.patch("sys.stdin", _TtyStringIO("")),
                mock.patch("sys.stderr", stderr),
                mock.patch("repolens.scan.runner.hardened_clone", _fake_clone),
                mock.patch("repolens.scan.runner._default_command_runner", fake_runner),
            ):
                code = cli.main(["scan", "--work-root", str(work_root), "--repos", str(repos_path)])

            self.assertEqual(code, 0)
            ensure.assert_not_called()
            self.assertNotIn("Download and install", stderr.getvalue())

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
