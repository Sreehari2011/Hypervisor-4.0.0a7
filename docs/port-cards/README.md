# Port Cards — 3.7.3 → 4.0 component dispositions

Master inventory ratified in Blueprint Chapter 10 (Table 10-1). Each
card pins: source anchors in the frozen oracle (`oracle/MANIFEST.json`),
the 4.0 target, the contracts that must survive the port, the 4.0
deltas, and acceptance tests. **A component is not "ported" until its
card's acceptance tests pass against the frozen oracle's recorded
behavior.**

Status legend: ☐ pending · ◐ in progress · ✅/☑ done

*Re-scoped at P2 closeout: PORT-06 (replay) and REFACTOR-04 (L3
side-query) move to P3 — PORT-06's acceptance requires the golden
trajectories the phase plan defers to P3 kickoff (capture harness
armed since P0), and Table 12-6 lists the side-query as deferrable
("optimization layer, never gates"). The Zone-T expansion seam
(tail_attachments + tier-0 hygiene) is in place for it. Both landed
in P3 — see the cards.*

## PORT — semantics preserved, rewritten into the new package

| Card | Component (3.7.3) | 4.0 home | Phase | Status |
|---|---|---|---|---|
| [PORT-01](PORT-01-compact-prompts.md) | compact_prompts.py verbatim family | context/compact_prompts.py | P2 | ✅ |
| [PORT-02](PORT-02-compaction.md) | compaction.py tier ladder + breaker + auditor | context/compact.py | P2 | ✅ |
| [PORT-03](PORT-03-ekd.md) | engagement_dag.py EKD store | memory/ekd.py | P2 | ✅ |
| [PORT-04](PORT-04-extractors.md) | dag_extractors.py Tier-A parsers | memory/extractors.py | P2 | ✅ |
| [PORT-05](PORT-05-journal.md) | journal.py engagement journal | persist/journal.py | **P0** | ☑ |
| [PORT-06](PORT-06-replay.md) | replay.py integrity passes | persist/replay.py | P3 | ✅ |
| [PORT-07](PORT-07-llm-guard.md) | llm_guard.py bounds + breaker + sanitizer | guard.py | P1 | ✅ |
| [PORT-08](PORT-08-aegis-debug.md) | aegis_debug/* debug kit | debug/ | **P0** | ☑ |
| [PORT-09](PORT-09-scope-manager.md) | engagement_context.py scope manager | permissions.py | P1 | ✅ |
| [PORT-10](PORT-10-fingerprint.md) | fingerprint.py zone fingerprinting | context/fingerprint.py | P2 | ✅ |
| [PORT-11](PORT-11-brief-renderer.md) | semantic_store.py brief render path | memory/brief.py | P2 | ✅ |

## REFACTOR — ported with a changed attachment point

| Card | Component (3.7.3) | 4.0 home | Phase |
|---|---|---|---|
| [REFACTOR-01](REFACTOR-01-memory-manager.md) | Memory_Manager node + memory_budget triggers | context/compact.py pre-flight | P2 |
| [REFACTOR-02](REFACTOR-02-context-assembler.md) | context_assembler.py zones S/W/T | context/assemble.py | P2 |
| [REFACTOR-03](REFACTOR-03-subagents.md) | subagents.py contract spawn | agents/ Task tool + run_agent | P3 | ✅ |
| [REFACTOR-04](REFACTOR-04-side-query.md) | side_query.py L3 selector | loop pre-assembly step | P3 | ✅ |
| [REFACTOR-05](REFACTOR-05-safe-execution.md) | tools/safe_execution.py + toolset | tools/vapt/* + permissions.py | P1/P3 | ✅ P1 / ✅ P3 |
| [REFACTOR-06](REFACTOR-06-main-repl.md) | main.py REPL + slash commands | cli.py | P1 | ✅ |

## DELETE — no successor

[DELETE-families.md](DELETE-families.md) covers all five: the grid
(graph.py, registry_v2.py, state.py, handoff tools), skill_engine,
memory_tiered/semantic_store (superseded by EKD), the dead-code
inventory (Table 3-4), and every shim that only existed to serve the
grid.

## UX — 4.0-native additions

New surfaces with no 3.x source to port; same card discipline and
acceptance-test bar as the PORT/REFACTOR families, anchored to the
4.0 contracts they must preserve instead of an oracle.

| Card | Component | 4.0 home | Phase | Status |
|---|---|---|---|---|
| [UX-01](UX-01-operator-tui.md) | Operator TUI (Codex/CC-shaped, slash commands) | hypervisor/tui/ | P4/UX | ✅ |
| [UX-02](UX-02-prompt-derating.md) | Prompt de-upstreaming + engagement orientation | agents/prompts.py, context/compact_prompts.py | UX/a7 | ✅ |

## Rules

1. **No card, no port.** Any behavior moving from 3.7.3 into 4.0 must
   have a card with acceptance tests first.
2. **Oracle-anchored.** Acceptance tests cite oracle file:line anchors;
   behavioral expectations cite golden trajectories once captured (P3).
3. **One-way door discipline.** A DELETE is permanent within the 4.0
   program; re-introducing a deleted component requires a new card and
   a blueprint amendment.
4. **Update on landing.** When a port lands, its card gains the
   acceptance-test results and moves to ☑.
