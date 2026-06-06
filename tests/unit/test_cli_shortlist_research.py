from __future__ import annotations

import argparse
from pathlib import Path

from repolens import cli


def test_shortlist_parent_accepts_evidence_with_proposals() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "shortlist",
            "--work-root",
            "work",
            "--proposals",
            "work/shortlist.proposals.json",
            "--evidence",
            "work/shortlist.evidence.json",
        ]
    )

    assert args.handler == cli._shortlist_stage
    assert args.proposals == Path("work/shortlist.proposals.json")
    assert args.evidence == Path("work/shortlist.evidence.json")


def test_shortlist_research_subcommand_parses_after_action() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "shortlist",
            "research",
            "--work-root",
            "work",
            "--contexts",
            "work/shortlist.contexts.json",
            "--proposals",
            "work/shortlist.proposals.json",
            "--evidence",
            "work/shortlist.evidence.json",
            "--review",
            "work/shortlist.review.md",
        ]
    )

    assert args.handler == cli._shortlist_research_stage
    assert args.work_root == Path("work")


def test_shortlist_research_subcommand_defaults_to_work_root_paths(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    captured: dict[str, Path] = {}

    def fake_run_research(
        *,
        contexts_path,
        proposals_path,
        evidence_path,
        review_path,
        progress=None,
    ):
        captured["contexts"] = contexts_path
        captured["proposals"] = proposals_path
        captured["evidence"] = evidence_path
        captured["review"] = review_path
        if progress is not None:
            progress("sentinel research progress")
        return argparse.Namespace(
            proposals_path=proposals_path,
            evidence_path=evidence_path,
            review_path=review_path,
            row_count=0,
            proposal_count=0,
        )

    monkeypatch.setattr("repolens.shortlist.research.run_research", fake_run_research)
    result = cli._shortlist_research_stage(
        argparse.Namespace(
            work_root=tmp_path,
            contexts=None,
            proposals=None,
            evidence=None,
            review=None,
        )
    )

    assert result.status == cli.CommandStatus.SUCCESS
    assert "sentinel research progress" in capsys.readouterr().err
    assert captured == {
        "contexts": tmp_path / "shortlist.contexts.json",
        "proposals": tmp_path / "shortlist.proposals.json",
        "evidence": tmp_path / "shortlist.evidence.json",
        "review": tmp_path / "shortlist.review.md",
    }
