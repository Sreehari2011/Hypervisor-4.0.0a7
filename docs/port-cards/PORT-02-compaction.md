# PORT-02 — Compaction tier ladder, breaker, auditor

**Status: ☑ done** · Target: `hypervisor/context/compact.py`
· Source: `src/core/compaction.py` (470 lines)

## What ports

The episodic fold machinery: tier-3 LLM fold with direction planning,
the fold verifier family, the 3-failure breaker, and the audit trail.

## Contracts preserved

- Tier semantics: tier 0 attachment hygiene / tier 1 window trim /
  tier 2 microcompact (in-place stubs, `replaces` pairing) / tier 3
  fold — recorded via `compaction_trim` + `compaction` journal events.
- 3-failure breaker: counted → open (auto-compaction disabled,
  deterministic tiers carry the load) → reset on success; manual
  override journaled (`compaction_breaker` actions).
- Fold verifier: id preservation (tool_call pairing), summary-hash
  pinning, residual sidecar via the journal's writer.
- `dropped_sig_shas` + `drop_position` window surgery records that
  replay applies.

## 4.0 deltas

- Attachment point: pre-flight pipeline step in the loop (REFACTOR-01
  dissolves Memory_Manager into this), not a graph node.
- The CC cascade ordering wraps the ladder: budget → microcompact →
  collapse → autocompact (Skeleton 9-5 keeps the 3.x verifier family
  inside the fold tier).
- Streaming-safe: fold runs on the same event loop, duration-bounded by
  the guard.

## Acceptance tests (write on landing)

1. Oracle-parity: same input window + same direction → same tier
   decision sequence (fixture windows from golden trajectories).
2. Breaker: 3 consecutive failures → open event + operator surface;
   success resets; override journaled.
3. Verifier: injected id violation detected and journaled
   (id_violations > 0), fold still safe.
4. Journal shape: compaction event carries summary_ref + direction +
   tier + dropped_sig_shas with drop_complete consistency.

## Landing notes (P2 closeout)

- `context/compact.py` — the ladder (tier 0 hygiene / 1 window trim /
  2 microcompact + the always-on B2 char-cap in
  `apply_tool_result_budget` / 3 fold), the 3-failure breaker
  (`CompactState`, journaled), the direction planner, the stripper, the
  continuation message, `verify_id_preservation`,
  `dropped_sig_shas`. Prompt assembly rides PORT-01 verbatim.
- Breaker: 3 consecutive failures open (journaled + operator surface),
  success resets, manual override journaled —
  `test_breaker_three_failures_open_reset_override`,
  `test_autocompact_failure_counts_toward_breaker`.
- Verifier: id violations counted into the compaction event
  (`id_violations` field); fold still lands.
- Journal shape: `compaction` carries summary_ref + direction + tier +
  chunks + dropped_sig_shas + drop_complete; `compaction_trim` carries
  the tier-1/2 surgery with `replaces` pairing for in-place stubs.
- Oracle-parity tier decisions: fixture windows exercised through the
  full engine (deterministic seeds, no LLM) in
  `test_autocompact_breaker_open_deterministic_only`; golden-trajectory
  A/B lands with P3's parallel-run per the phase plan.
- E2E discovery fixed in-engine: full protection on a short channel
  left nothing foldable and walked into the blocking limit — the fold
  now degrades the protected window (halving to a 1-group floor) when
  the fold range is empty.
