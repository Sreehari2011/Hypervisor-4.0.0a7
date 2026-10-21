"""hypervisor.tui — the operator TUI (UX-01).

A Codex/Claude-Code-style interactive front end for the hypervisor:
header config card, streaming transcript, slash-command palette with
Tab completion, and an elevated input block — pure stdlib (termios +
ANSI), zero new dependencies, zero engine changes.

Entry: `hypervisor` with no arguments on an interactive terminal
(wired in cli.py), or `python -m hypervisor.tui`.

Layout: term.py (geometry/raw mode) · editor.py (keys/input) ·
render.py (visual language) · commands.py (slash verbs) ·
engage.py (engine bridge) · app.py (composition).
"""
from __future__ import annotations

from .app import TuiApp, run_tui

__all__ = ["TuiApp", "run_tui"]
