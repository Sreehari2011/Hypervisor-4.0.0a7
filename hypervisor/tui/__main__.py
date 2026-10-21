"""python -m hypervisor.tui — direct TUI entry (UX-01)."""
from __future__ import annotations

import sys

if __name__ == "__main__":
    from .app import run_tui
    raise SystemExit(run_tui(sys.argv[1:]))
