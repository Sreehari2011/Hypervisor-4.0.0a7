# PORT-06 — Replay and integrity passes

**Status: ✅ DONE (P3)** · Target: `hypervisor/persist/replay.py`
· Source: `src/replay.py` (815 lines)

## What ports

The journal replay machinery: strict +1 seq integrity, rev-chain
verification, window reconstruction from message events (byte-verify
per-render window hashes), sidecar chain pass (sidecar sha vs the
event's claim), brief re-render byte-identity, crash-boundary repair
(journal rev N with no store rev N).

## Contracts preserved

- Every pass accepts v1 (oracle) and v2 (4.0) journals — replaying the
  frozen oracle's journals is a hard requirement (P3/P4 A/B reads it).
- Torn-tail tolerance identical to `Journal.events` (skip unparseable,
  report the boundary).
- Repair is explicit and reported, never silent.

## 4.0 deltas

- v2 event handling: loop_transition / permission_decision /
  turn_watchdog surfaces in the replay report (counts + spans).
- Session-store cross-check (P1's sessions.py) joins the pass family:
  journal ↔ session sidechain linkage audit.

## Acceptance tests (write on landing)

1. Oracle journals replay clean: capture 2–3 golden trajectories, run
   the pass, zero false positives.
2. Mutation testing: each corruption class (seq gap, lying sidecar sha,
   broken rev chain, missing window message) is detected and named.
3. Crash-boundary: journal-ahead-of-store case repairs to a consistent
   state.

## Landing results (P3)

- persist/replay.py (1,024 ln): the oracle's three passes ported —
  integrity (strict +1 seq, schema fields, v1/v2 acceptance),
  revision chain (contiguous write-ahead, snapshot existence + sha +
  embedded rev, residual/objective/message sidecars, side_query
  expansion shas, subagent spawn mode sanction + report linkage with
  the channel message sha), render reconstruction (Zone W sim + J2
  byte re-render through the 4.0 stack: EngagementDAG.from_json +
  deterministic ensure_objective with the pinned clock +
  render_brief_l2 under the boot render_params).
- 4.0 deltas all landed: v2 surfaces in the report (loop_transition /
  permission_decision allow+deny counts / turn_watchdog events +
  spans); the session-store cross-check (subagent_spawn ↔ sidechain
  meta sidecar ↔ parent chain integrity; explicit skip when the store
  is absent); crash_boundary + repair (journal-ahead-of-store —
  including the missing-state-file case — detected, repaired from the
  newest VERIFIABLE snapshot, every action named, refuses without
  one).
- The Zone W sim surgery rules for 4.0: identity drops, in-place stub
  replaces (replaces=), and the fold's continuation INSERT at the
  recorded first-drop position (reconstructing [head, continuation,
  tail] exactly as the fold built it); unmatched drops are NAMED
  issues, never silent skips; per-channel discipline — subagent
  sidechain messages/surgery never pollute the main window.
- Window reconstruction wired through the journal: the loop journals
  channel message events (objective/assistant/tool-result carriers
  through the frozen-sig _MsgView), the fold journals its
  continuation, tier-2 stubs journal their replaces.
- Golden trajectories: scripts/capture_golden.py runs scripted
  engagements against the fake endpoint and stores the artifacts —
  tests/golden/golden-fold (tiny window: two folds, stubs,
  continuations) + golden-quiet (healthy window). Both replay CLEAN:
  golden-fold 4/4 brief re-renders byte-identical, 3/3 window hashes
  verified (the empty first window skips explicitly); golden-quiet
  2/2 + 1/1.
- CLI: python -m hypervisor.persist.replay <dir> [--json] [--repair].
- Acceptance green: test_replay.py (16 tests) — both goldens clean,
  v1 oracle-shape journal accepted, all five mutation classes detected
  AND named (seq gap, lying sidecar sha, chain discontinuity, missing
  window message, lying expansion sha + unsanctioned spawn mode),
  crash-boundary repair round-trip + refusal without a verifiable
  snapshot, session linkage (missing sidechain, headless skip, real
  sidechain linked), CLI exit codes, torn-tail tolerance.
