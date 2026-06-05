from __future__ import annotations

import re
from pathlib import Path


def test_repolens_skill_wrappers_resolve_to_source_of_truth(repo_root: Path) -> None:
    source = repo_root / ".skills" / "repolens" / "SKILL.md"
    assert source.is_file()

    for wrapper in (
        repo_root / ".agents" / "skills" / "repolens" / "SKILL.md",
        repo_root / ".claude" / "skills" / "repolens" / "SKILL.md",
    ):
        assert wrapper.is_file()
        target = (wrapper.parent / "../../../.skills/repolens/SKILL.md").resolve()
        assert target == source.resolve()
        assert "source of\ntruth" in wrapper.read_text(encoding="utf-8")


def test_repolens_skill_referenced_files_exist(repo_root: Path) -> None:
    skill = repo_root / ".skills" / "repolens" / "SKILL.md"
    text = skill.read_text(encoding="utf-8")
    references = {
        match.group(1) for match in re.finditer(r"`((?:\.skills|src)/repolens/[^`]+)`", text)
    }

    assert ".skills/repolens/reference/proposal-schema.md" in references
    assert ".skills/repolens/reference/evidence-lookup.md" in references
    assert ".skills/repolens/reference/triage-cheatsheet.md" in references
    assert ".skills/repolens/scripts/generate_shortlist_proposals.py" in references
    assert ".skills/repolens/scripts/inspect_evidence.py" in references
    assert "src/repolens/data/schemas/shortlist_proposals.schema.json" in references
    for reference in references:
        assert (repo_root / reference).is_file(), reference
