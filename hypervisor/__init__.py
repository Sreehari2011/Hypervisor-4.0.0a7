"""AEGIS Hypervisor 4.0 — single-loop VAPT agent platform.

Clean-room rebuild. Zero imports from any 3.x tree; carried-forward
subsystems arrive as reviewed ports (see docs/port-cards/) with acceptance
tests derived from the frozen 3.7.3 oracle (see oracle/).

Phase status:
  P0  audit & strip ...... DONE (scaffold, oracle freeze, debug kit + journal)
  P1  core loop .......... DONE (query loop, tools+dispatcher, scope gate,
                           guard, adapter, sessions, CLI; 125 tests green
                           incl. E2E vs a real socket endpoint)
  P2  context engine ..... context/*, memory/*
  P3  subagents + VAPT ... agents/*, tools/vapt/*
  P4  hardening/cutover ..
"""
__version__ = "4.0.0a5"

# 3.x parity alias (AEGIS_VERSION was the 3.x runtime marker).
AEGIS_VERSION = __version__
