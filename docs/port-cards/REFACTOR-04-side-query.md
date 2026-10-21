# REFACTOR-04 — Side query → loop pre-assembly step

**Status: ✅ DONE (P3)** · Target: pre-assembly step in
`hypervisor/query.py` + `hypervisor/memory/sidequery.py` · Source:
`src/core/side_query.py` (429 lines)

The L3 pre-expansion selector (revision_bump / new_entities triggers,
planner-model selection over EKD candidates, capped Zone T expansions,
already-surfaced anti-re-pick set, skip/failed health flags) ports as a
loop-owned pre-assembly step — an explicit, journaled, guard-bounded
LLM side call instead of a hidden mesh path. Journal surface unchanged
(side_query events, carried in the P0 port). Acceptance: trigger
parity on fixture revisions; expansions sha-pinned; skip paths
journaled; selector failures never gate assembly (J4 discipline).

## Landing results (P3)

- memory/sidequery.py: the selector prompts ported VERBATIM (the
  no-tools preamble LEADS, the consequence-explicit trailer closes —
  the measured 2.79% lesson); brief_section_index (entity/finding/
  hypothesis ids, capped), detect_new_entities (deterministic id/key/
  title mention resolution), selector_gate (spec 3.5: skip when
  revision unchanged AND no new entities; skip when no unsurfaced
  candidates), parse_selector_output (the post-filter: valid-only,
  surfaced-dropped, dupe-dropped, hard cap 5), expand_entities
  (hard-capped AT INJECTION, sha of the capped text journaled),
  write_expansions (tail_attachments + the never-re-pick surfaced set).
- SideQueryEngine: one evaluation per turn assembly — the side call
  routes through the guard (purpose='sidequery', no tools, 256 max
  tokens, SIDEQUERY_TIMEOUT_S-bounded with named failure classes —
  the 2026-10-06 "selector failed ()" hardening), skip/run/failure all
  journaled, the outer net swallows even a broken ctx (oracle L378-400
  parity). Never gates assembly (J4 in-engine).
- Loop integration: the deps-slot pattern — LoopDeps.side_query
  (no-op default) + ProductionDeps wiring + ONE awaited call between
  the blocking gate and zone assembly. The loop body otherwise
  untouched.
- CLI: AEGIS_SIDEQUERY=0 disables; surfaced-set + counters ride
  ctx.extra.
- Acceptance: test_sidequery.py (11 tests — gate parity, detection,
  post-filter contract, prompt shape, injection cap + sha, Zone T
  landing, revision-bump run + journaled skip on steady state, failure
  -> [] + journaled with the class named, broken-ctx outer net,
  current-turn extraction skipping machinery, the deps slot) + the P3
  E2E (the selector fires on the child-extraction revision bump, the
  expansion rides the next main prompt as <aegis-drilldown>, the skip
  path journaled on turn 1).
