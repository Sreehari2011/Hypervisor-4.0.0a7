# REFACTOR-01 — Memory_Manager → pre-flight compaction step

Phase: P2 · Target: `hypervisor/context/compact.py` (with PORT-02)

**Status: ☑ done (P2)**
· Source: `src/core/graph.py` Memory_Manager node + `src/core/memory_budget.py` (189 lines)

The graph node and its budget-trigger plumbing dissolve into the
loop's 7-step pre-flight pipeline: budget check → tier ladder → fold,
executed before every model call (CC's applyToolResultBudget → snip →
microcompact → collapse → autocompact ordering; Skeleton 9-1/9-5).
Node-visit semantics (once per turn boundary) become turn-boundary
steps; the budget triggers (window-relative thresholds) port from
memory_budget.py re-tuned to cisai-ultra's window. Acceptance: no
separate "manager" exists — budget events + ladder events fire in
pre-flight order, observable in the timeline; oracle trigger thresholds
documented as the tuning baseline.

## Landing notes (P2 closeout)

- No "manager" exists: the budget half is `context/budget.py`
  (BudgetManager — window-derived reserve/trigger/target/chunk/
  per-message cap + the CC cascade: microcompact below the fold
  trigger, blocking above it) and the ladder half is
  `context/compact.py`'s CompactEngine, both attached to the loop's
  pre-flight slots. Budget + ladder events fire in pre-flight order,
  observable in the timeline (E2E-verified).
- The window authority: env pin (AEGIS_CONTEXT_WINDOW_TOKENS) >
  registry (longest-key match) > conservative 32k with the loud B3
  warning naming the override.
- Oracle trigger thresholds documented as the tuning baseline
  (`test_budget_manager_thresholds`); the Memory_Manager node and its
  graph plumbing did not port (DELETE-01 with the grid).
