"""P5 shortlist stage — capability-minimized resolution agent + human approval.

This package is the single home for the ``shortlist`` pipeline stage. It reads the
``shortlist.json`` that ``flag`` (P4) produced, routes each ``open`` item through a
pre-screen gate, can emit those model-free contexts for an external proposal pass,
re-verifies proposal citations against freshly re-fetched evidence, ingests human checkbox
decisions from ``shortlist.md``, and writes both artifacts back.
"""

from repolens.shortlist.research import ResearchResult, run_research
from repolens.shortlist.stage import ShortlistResult, run_shortlist

__all__ = ["ResearchResult", "ShortlistResult", "run_research", "run_shortlist"]
