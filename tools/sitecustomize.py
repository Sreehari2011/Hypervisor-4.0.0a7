"""Opt-in auto-install for the AEGIS Debug Kit (4.0 port).

Same activation pattern as the 3.x kit: put this directory on
PYTHONPATH and set AEGIS_DEBUG=1 — sitecustomize runs before any
application import, so even imports that fire LLM traffic at module
load are captured.

    PYTHONPATH=/path/to/hypervisor-4.0/tools AEGIS_DEBUG=1 \
        AEGIS_DEBUG_DIR=./logs/debug python -m your entry

Inert unless AEGIS_DEBUG is set (the kit itself re-checks).
"""
import os

if os.environ.get("AEGIS_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
    try:
        import hypervisor.debug as _aegis_debug
        _aegis_debug.install()
    except Exception:
        # The kit must never take the agent down — including at import.
        pass
