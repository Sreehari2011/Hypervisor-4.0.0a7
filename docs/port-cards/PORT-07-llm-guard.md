# PORT-07 — llm_guard: bounds, breaker, sanitizer

**Status: ✅ DONE (P1)** · Target: `hypervisor/guard.py`
· Source: `src/core/llm_guard.py` (335 lines) → 470 lines, stream-shaped

## What ports

The four defenses born from the 24-minute-hang post-mortem (one LLM
call parked the agent; interval-based watchdog never fired; the
degenerate `|>think<|sep|>` delta stream fooled the health check):

1. **Per-attempt timeout**: connect + first-byte + inter-chunk bounds.
2. **Total bound per call** with cancellation-completion verification —
   if cancellation cannot complete (peer holds the socket), the child
   task is abandoned (`llm_abandon`) and transport timeouts reclaim.
3. **Consecutive-failure breaker**: counted → open; mirrors
   compaction_breaker semantics (`llm_breaker`).
4. **Degenerate-delta sanitizer**: detects content-free chunk streams;
   treats them as failures, not progress.

## Contracts preserved

- Journal surfaces: `llm_call` (start, bounds), `llm_call_end`
  (ok/error/timeout/late_error_after_cancel), `llm_retry`,
  `llm_abandon`, `llm_breaker`.
- The guard NEVER silently swallows: every defense writes its event.
- Bounds are engagement-configurable, never unbounded.

## 4.0 deltas

- Becomes a **loop invariant** (every LLM call in 4.0 — main loop,
  subagents, side queries — goes through the guard; no call site may
  bypass it).
- Pairs with the debug kit's reaper (external view) — the guard's
  abandon events cross-check against wire `reaped` events in
  post-mortems.
- Turn watchdog (turn_watchdog events) wraps the whole iteration above
  the per-call bounds.

## Acceptance tests (write on landing)

1. Oracle defect repro: `hardening/repro_hang.py` scenario re-run
   against the 4.0 adapter + guard → bounded in ≤ REAP_SECONDS + slack,
   llm_abandon journaled, reaper event correlated.
2. Breaker: N consecutive failures → open; recovery resets.
3. Sanitizer: degenerate delta fixture → treated as failure.
4. Green path: no false trips across a golden-trajectory-length run.

## Landing results (P1)

- All four defenses ported as LOOP INVARIANTS on async streams
  (`LLMGuard.call_stream` wraps every factory — main loop, subagents
  and side queries all route through it; no call site may bypass):
  1. transport bounds live in the adapter's httpx.Timeout
     (connect 5s / read max(idle,30)s / write 60s / pool 10s);
  2. caller-side total bound via the child pump + queue pattern —
     the 3.7.3 cancellation pathology cannot park the caller
     (test_total_bound_replaces_the_hang: hang bounded < 2s);
  3. Breaker per purpose, fail-fast + reset on success
     (test_breaker_opens_and_resets);
  4. sanitizer catches BOTH content-free streams and looping deltas
     (the exact `|>think<|sep|>` fixture trips the repeat-streak rule
     at 101 chunks).
- NEW vs 3.7.3: the parsed-chunk IDLE bound (keepalive-only streams
  trip BETWEEN chunks, before the total bound —
  test_idle_bound_catches_keepalive_only_streams).
- Journal family verified end-to-end: llm_call, llm_call_end
  (ok/error/timeout/degenerate), llm_retry, llm_abandon, llm_breaker
  (test_guard_journals_the_full_event_family).
- Acceptance item 1 (full repro_hang.py replay vs the mock gateway
  with reaper correlation) moves to the P4 fault matrix per the
  phase plan; the E2E socket run (test_e2e.py) covers the guard on
  the real wire path meanwhile.
