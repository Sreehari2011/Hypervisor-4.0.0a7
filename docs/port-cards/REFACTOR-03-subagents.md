# REFACTOR-03 — Contract subagents → Task tool + run_agent

**Status: ✅ DONE (P3)** · Target: `hypervisor/agents/` (task tool,
run_agent, defs/) · Source: `src/core/subagents.py` (692 lines —
`run_contract_subagent` L507-666 is the latent 4.0 seed: 8-round
bounded loop, scoped toolset, single-result contract) +
`src/core/subagent_prompts.py` + `src/agents/registry_v2.py`

The contract subagent generalizes into the full Task tool: same loop
at depth+1 (nested async generator, not a graph node), agent-file
system prompt (contract_hash journaled — write-ahead preserved),
brief-slice context mode, scoped tools, turn ceiling with done-so-far
partial reports, spawn/report journal linkage (subagent_spawn +
subagent_report + message source='subagent:<phase>' — all already in
the P0 journal port). The two context modes (brief-slice vs
fresh+pointer) port as-is. Acceptance: spawn/report chain replays;
ceiling produces partial=True; scopes inherited ⊆ parent scope
(permission engine, PORT-09).

## Landing results (P3)

- agents/prompts.py: the six Task-tool contract texts ported
  BYTE-IDENTICAL from the frozen oracle (scripts/
  port_agent_prompts.py generates + asserts 6/6 constants; the test
  suite sha-pins DEFAULT_AGENT_PROMPT independently).
- agents/defs.py: 22 agent definitions as data — the six Table 11
  phase contracts (verbatim completion bars + report emphases) + the
  fifteen registry_v2 experts re-authored (planner..replay-attack,
  legacy names resolve: Selection_Agent→planner) + the CC
  general-purpose fallback. Each def carries tool allowlist, ceiling,
  brief-section scope, memory query scopes.
- agents/task.py: TaskTool (name "task", aliases subagent/
  spawn_agent; schema + agent resolution + depth cap 2) and run_agent
  — THE query_loop at depth+1 with: write-ahead subagent_spawn
  (contract_hash, brief_rev, brief_slice_hash, scopes, ceiling);
  SessionStore sidechain transcript (own file + 0600 meta sidecar);
  child ToolContext (scoped registry: the def's allowlist resolved
  against the parent registry, ScopedMemoryQueryTool substituting the
  parent's, Task tool structurally absent); the done-so-forced final
  (one bounded no-tools call through the guard) on ceiling-hit and
  empty-final; subagent_report + the linked channel message event
  (source='subagent:<agent>', full-text sha verified by replay).
- Channel discipline for replay (PORT-06 interlock): the child's
  journal events ride a ChildJournal proxy — message sources prefixed
  subagent:<agent>:, fold surgery stamped channel=subagent:<agent> —
  so the Zone W simulation reconstructs each channel independently
  while the EKD revision chain stays global.
- build_child_registry refuses defs allowlisting unknown tools;
  brief_slice_for_agent renders under the Table 8 budgets then keeps
  the phase sections + header + floor-guaranteed drilldown pointer.
- Acceptance: test_agents.py (12 tests — verbatim bars, 22 defs,
  legacy resolution, slice floor, child-registry subset + task-free,
  scoped-query result filtering, spawn/report linkage + sidechain,
  ceiling partial, depth gate, allowlist registry, child-scope
  inheritance denies out-of-scope identically) + the P3 E2E.
