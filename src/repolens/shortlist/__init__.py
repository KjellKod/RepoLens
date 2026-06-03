"""P5 shortlist stage — capability-minimized resolution agent + human approval.

This package is the single home for the ``shortlist`` pipeline stage. It reads the
``shortlist.json`` that ``flag`` (P4) produced, routes each ``open`` item through a
pre-screen gate, optionally invokes a capability-minimized resolution agent, re-verifies
any agent claim against freshly re-fetched evidence, ingests human checkbox decisions
from ``shortlist.md``, and writes both artifacts back.
"""

from repolens.shortlist.stage import ShortlistResult, run_shortlist

__all__ = ["ShortlistResult", "run_shortlist"]
