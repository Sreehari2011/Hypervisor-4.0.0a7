# DELETE — families with no successor

Ratified in Blueprint Table 10-1. Within the 4.0 program these are
one-way doors: re-introduction requires a new port card + blueprint
amendment. The frozen oracle retains them for reference and A/B
comparison only.

## DELETE-01 — The grid

`src/core/graph.py` (StateGraph, 15-node topology, Selection_Agent
entry, safety-valve router L582-643, handoff_count≥30 kill switch
L637, node factory), `src/agents/registry_v2.py` (15 expert nodes +
`create_handoff_tool`/`__HANDOFF__` Command-goto L161-199, zero-tool
Mission Commander L223-278), `src/core/state.py` (11-channel state),
`src/core/engagement_dag.py`'s graph plumbing (the store ports,
PORT-03; the ToolNode wrapper does not). Replaced by: query.py loop +
agents/defs/*.md. The LangGraph dependency itself leaves the runtime.

## DELETE-02 — skill_engine/

Eight modules, zero skills shipped, zero skills consumable by the grid.
Deferred to a 4.1 card if the operator wants CC-style skills; the 4.0
expert system is agents/defs/ files.

## DELETE-03 — Handoff protocol

`__HANDOFF__::agent` tool family, Command(goto) routing, A-B-A-B cycle
detection, the termination switch. Delegation in 4.0 is the Task tool
(REFACTOR-03) — a call that returns, not a jump that transfers control.

## DELETE-04 — memory_tiered.py + semantic_store (store side)

`src/core/memory_tiered.py` (381 lines, episodic keep-first+6 LLM
compression — superseded by the fold ladder), semantic_store's tiered
blob store (the render path ports as PORT-11; the store dies to the
EKD, PORT-03). The LLM-compression tool-pair corruption risk dies with
it.

## DELETE-05 — Dead code + shims (Blueprint Table 3-4)

The eleven-item inventory: DAGEngine (never driven), state.findings
(never written), turn_count (commented out), WorkingMemory (never
instantiated), record_handoff (never called), INTERNAL_TARGET_RANGES
(unused), MODEL_EXECUTOR empty-default planner path, otool-on-Linux
iOS path, unpinned deps, compat shims, httpx2-era workarounds that
4.0's guarded imports replace. None survive; the rebuild's mere
existence removes them.
