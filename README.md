# AEGIS Hypervisor 4.0

Clean-room rebuild of the Hypervisor VAPT agent platform. One asyncio query
loop is the sole control plane; tools, experts and subagents are its children.
Architecture is function-for-function modeled on the Claude Code reference
(single event loop, tool_use as the only exit signal, 7-step context
pre-flight, subagents as nested async generators, append-only 0o600 JSONL
persistence).

**Zero imports from 3.x.** Everything carried forward arrives as a reviewed
port with a port card (`docs/port-cards/`) and acceptance tests derived from
the frozen 3.7.3 oracle (`oracle/`).

## Status — Phase 0 (Audit & Strip)

| Delivered in P0 | Where |
|---|---|
| Repo scaffold (Layout 9-1, ~13.5K-line target) | `hypervisor/` |
| 3.7.3 frozen as oracle (manifest + verifier) | `oracle/` |
| **Debug kit port** — wire tap, timeline, log tap, loop monitor, journal tap, reaper | `hypervisor/debug/` |
| **Journal port** — J1–J4 contracts, sidecars, resume continuation, integrity replay | `hypervisor/persist/journal.py` |
| Port cards: 11 PORT / 6 REFACTOR / 5 DELETE / 2 UX families | `docs/port-cards/` |
| Golden-trajectory capture harness (executes in P3 A/B) | `oracle/golden/` |

P1 (core loop + tools + permissions), P2 (context engine + EKD), P3
(subagents + VAPT experts as agent files), P4 (hardening + cutover) land on
top. Module docstrings carry their phase and port-card reference.

## Layout

```
hypervisor/
  query.py          # THE loop (P1)
  tools/base.py     # Tool protocol + dispatcher (P1)   tools/vapt/ (P3)
  permissions.py    # scope engine: deny-by-default (P1)
  agents/           # Task tool + run_agent (P3); defs/*.md experts
  context/          # budget, compact ladder, byte-stable assembly (P2)
  memory/           # EKD store, Tier-A extractors, brief renderer (P2)
  persist/journal.py# engagement journal — PORTED (P0)
  persist/sessions.py# 0o600 JSONL sessions, parentUuid chains (P1)
  guard.py          # llm_guard port: bounds, breaker, sanitizer (P1)
  debug/            # aegis_debug port — PORTED (P0)
  cli.py            # thin entry chain + the UX-01 TUI hook (bare tty)
  tui/              # operator TUI: term/editor/render/commands/engage/app (UX-01)
  adapters/openai.py# cisai-ultra client (P1)
```

## Quick start (P0 surface)

```bash
pip -e .[dev]
pytest                        # acceptance tests for the P0 ports

# Operator TUI (UX-01) — bare command on any interactive terminal:
# header card, streaming transcript, slash commands, Tab completion.
hypervisor                     # /doctor /test /scope /engage /journal ...

# Debug kit (env-activated, zero source intrusion — same discipline as 3.x):
AEGIS_DEBUG=1 AEGIS_DEBUG_DIR=./logs/debug python -c \
  "import hypervisor.debug as d; d.install(); d.timeline.emit('meta','hello')"
# -> ./logs/debug/run_*/timeline.jsonl
```

## Design invariants (from the ratified blueprint)

1. The loop is the only control plane; tools are pure data.
2. Scope is the authority model — ON by default, deny by default; every
   allow writes a journal audit record (`permission_decision` events).
3. Observability before behavior: the debug kit and journal ported in P0,
   before any loop exists.
4. Duration-bounded I/O everywhere (the 24-minute-hang lesson): llm_guard
   bounds, turn watchdog, dead-stream reaper — all journaled.
5. Journal contracts J1–J4: write-ahead, revision carriage, never
   compacted, never a gate.

See `docs/port-cards/README.md` for the component-by-component plan.
