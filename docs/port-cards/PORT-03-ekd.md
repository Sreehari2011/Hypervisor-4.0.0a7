# PORT-03 — Engagement knowledge DAG (EKD) store

**Status: ☑ done** · Target: `hypervisor/memory/ekd.py`
· Source: `src/core/engagement_dag.py` (1,487 lines)

## What ports

The crown jewel of the 3.x lineage: the revision-disciplined
engagement DAG — nodes (hosts, services, findings, evidence,creds,
paths), typed edges, EkdBatch write-ahead through the journal, bounded
snapshot retention, `render_brief`.

## Contracts preserved

- Revision discipline: every mutation commits rev N+1 through
  `record_ekd_mutation` BEFORE the store write (J1); snapshots make
  every committed revision byte-reconstructible.
- EkdBatch semantics: bounded deltas (refs over blobs), crash between
  journal and store detectable by replay.
- `/reset` discontinuity journaled (`ekd_reset`, rev → 0).
- Snapshot pruning: `ekd_snapshot_prune` journaled before deletion;
  replay treats references as pruned, not missing.
- `render_brief(rev, budget, now)` — the pinned-clock render that
  makes J2 true.

## 4.0 deltas

- Attachment point: **tool post-hook** (Tier-A extractors feed it after
  each tool result) instead of a ToolNode wrapper — simpler, loop-owned.
- The debug kit's EKD tap is ALREADY armed for this module's import
  (hypervisor/debug/patcher.py `install_ekd_tap`) — it will be born
  observed.
- Node/edge schema unchanged; new node kinds arrive only via card
  amendment.

## Acceptance tests (write on landing)

1. Mutation sequence: N mutations → journal has N ekd_mutation events,
   revs strictly increasing, final `to_json` sha matches the last
   snapshot.
2. Crash injection: kill between journal append and store write →
   replay detects (journal rev N, store rev N-1) and repairs.
3. render_brief: same (rev, budget, now) → byte-identical brief
   (frozen sha fixture).
4. Prune: retention bound enforced; pruned refs replay as pruned.
5. Oracle-parity: fixture batches from golden trajectories produce
   identical graphs (node/edge shas).

## Landing notes (P2 closeout)

- `memory/ekd.py` — EngagementDAG (canonical dedup, backward-edge drop,
  Zep supersession, merge_entities, M2 incremental indexes, H7b
  re-projection) + EkdBatch write-ahead + bounded snapshot retention
  with journaled prunes + workspace state (`ekd.json`, atomic, 0600) +
  `recover()` (J1 crash repair from the referenced snapshot).
- Mutation sequence: `test_mutation_sequence_journals_every_commit` —
  N commits -> N `ekd_mutation` events, revs strictly increasing,
  no-op batches journal nothing.
- Crash injection: `test_crash_between_journal_and_state_detected_and_repaired`
  — journal ahead of state -> rebuilt from the snapshot, state repaired.
- render_brief determinism: see PORT-11 (the render paths moved to
  memory/brief.py; the store keeps only the graph).
- Prune: `test_snapshot_retention_prunes_and_journals` — retention
  bound enforced, pruned refs journaled before unlink.
- Born observed: the P0-armed debug-kit import hook fired on first
  import; `ekd_mutation` events carry bounded deltas (refs over blobs).
- 4.0 delta landed: the semantic-store projection (project()) is
  DELETE-04 — memory_query queries the graph directly.
