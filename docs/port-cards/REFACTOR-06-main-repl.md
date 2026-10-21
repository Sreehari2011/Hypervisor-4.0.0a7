# REFACTOR-06 — main.py REPL → thin CLI

**Status: ✅ DONE (P1) · Target: `hypervisor/cli.py` (250 lines)**
· Source: `src/main.py` (1,368 lines — REPL, slash commands, mesh
  bootstrap)

The 1,368-line bootstrap thins to an entry chain: arg/env parse →
debug kit install FIRST (observability before behavior) → journal boot
event → scope load → loop. Slash commands keep their 3.x names where
they map (/scope /compact /reset /health /report /resume — operator
muscle memory) and gain /agents (list/load expert defs, P3) and
/watchdog (turn bound config). The mesh bootstrap, graph build,
registry init, handoff wiring — all DELETE-01 territory, none of it
ports. Acceptance: boot sequence emits kit_start → boot journal event
in order; every slash command journaled (operator_input); zero lines
of grid initialization remain.

## Landing results (P1)

- Entry chain landed exactly as specified: args/env → kit install
  (skippable via --no-debug) → journal boot event (engagement_id,
  scope_ref, mode, rule counts, workspace) → ScopeFile load with
  unsigned-scope warning → registry.freeze() → SessionStore →
  production_deps → query_loop with a line renderer (text streamed,
  tool results one-line, transitions on stderr) + exit codes
  (0 completed / 2 prompt_too_long / 3 watchdog / 4 model_error /
  5 scope error).
- `--check-scope FILE` operator pre-flight: validates signature,
  prints fingerprint + full scope status.
- The interactive REPL with slash commands is later polish on this
  same chain (P2/P4); the headless one-shot runner IS the P1 scope —
  it is the same entry the SDK-style engine and subagents share.
- Boot order verified in the kit-live E2E run: kit_start → taps →
  journal boot → loop transitions, all captured in one timeline
  (wire/* + journal/* + loop/turn_activity + persist/session_append).
- Zero lines of grid initialization remain (nothing imports LangGraph
  or any 3.x module — enforced by the clean-room import rule and the
  stdlib-only scaffold test).
