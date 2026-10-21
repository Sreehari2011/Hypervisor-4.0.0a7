# PORT-08 — aegis_debug kit

**Status: ☑ DONE (P0)** · Target: `hypervisor/debug/` (7 modules)
· Source: `src/aegis_debug/` (8 modules, 1,596 lines) + `debug/sitecustomize.py`

## What ports

The centralized debugging and logging module — the one subsystem the
operator explicitly designated to keep whole. Zero-intrusion
instrumentation: transport patches and observation only, never agent
source.

## Contracts preserved

- **Fail-silent absolutism**: no kit path may ever break the platform;
  `install()` swallows and reports; timeline emit never raises.
- **Crash-forensic sink**: every timeline event flushed on write — a
  hard hang leaves the timeline complete to the last observed event.
- **Wire tap mechanics**: request written to disk BEFORE the call (hung
  requests visible as open); streaming tee over the iter_bytes family
  with the active-tee guard against double-counting; TTFB / chunk
  count / worst inter-chunk gap / accumulated body; **SSE data-line
  silence tracking** (keepalive comments don't reset the clock — the
  2026-10-06 fix); non-streaming usage extraction.
- **Dead-stream reaper**: closes streams silent past REAP_SECONDS=180
  (deliberately above the client watchdog's 120s — only condemned
  streams are touched); async closes scheduled ON the owning loop,
  non-blocking, failures surfaced as reap_failed events.
- **Header redaction** (authorization/x-api-key/cookie) + BODY_CAP.
- **Loop monitor**: lag probe via run_coroutine_threadsafe ping;
  faulthandler all-thread stack dumps on STALL_SECONDS silence,
  repeated at STALL_REPEAT_SECONDS, with open-wire-request headers.
- **Log tap**: whole-tree tee to run.log; WARNING+ mirrored to
  timeline.
- **Deterministic import-hook taps** (patch before any caller can bind
  names) + watcher fallback.
- **Env knobs**: same names, same defaults — operator runbooks carry
  over unchanged (AEGIS_DEBUG, AEGIS_DEBUG_DIR, _STALL_SECONDS,
  _STALL_REPEAT, _BODY_CAP, _LOOP_DEBUG, _VERBOSE_LOG, _LOOP_LAG_WARN,
  _REAP_SECONDS, _REDACT_HEADERS, _QUIET).

## 4.0 deltas (Blueprint 9.10)

- `callbacks.py` (LangChain BaseCallbackHandler + callback-manager
  injection) → **`loop_events.py`**: `LoopObserver` called directly by
  the P1 loop at phase boundaries. Same span vocabulary (llm start/
  prompt/first_token/end/error/retry; tool start/end/error), prompt
  dump logic carried verbatim. Added: loop start/end/transition,
  `cat=perm` permission decisions, depth/label markers so subagent
  spans stay distinguishable.
- `patcher.py` re-aimed: journal tap → `hypervisor.persist.journal`
  (same wrap of `Journal.append`, same 120-char/12-key data cap);
  **EKD tap** armed via the deterministic import hook on
  `hypervisor.memory.ekd` (P2); **sessions tap** armed on
  `hypervisor.persist.sessions` (P1); the **saver tap is deleted**
  with the grid (AsyncSqliteSaver has no 4.0 successor — sessions.py
  replaces it).
- Timeline categories: chain/saver/dag retire with the grid; loop/perm/
  memory/persist join. Category set is documented, not enforced (same
  as 3.7.3).
- `loop_monitor` gains `note_turn_activity()` / `current_turn()` — the
  P1 turn watchdog's signal; stall headers now include the turn.
- wire tap: unchanged mechanism; the 4.0 adapter riding httpx is
  covered by the existing patch (httpx2 retained for oracle-parity
  captures on the 3.x stack).

## Acceptance tests (tests/test_debug.py — all passing)

1. Kit install (AEGIS_DEBUG=1, tmp AEGIS_DEBUG_DIR): run dir +
   kit_meta.json + timeline.jsonl created; install idempotent.
2. Timeline event shape: t/ts/cat/ev/dur_ms/id + data; JSONL parseable;
   `last_event_time` advances.
3. Journal tap: Journal.append through the kit lands cat=journal
   events with seq/turn/rev; capped data; tap never breaks the journal
   (exception in tap swallowed).
4. Wire tap unit pass on a fake httpx module: sync + async send
   patched; request/response events with redacted headers; req_/resp_
   JSON files written; streaming tee counts chunks and writes
   stream_end with chunks/max_gap; SSE data-line silence tracked
   (last_data set).
5. LoopObserver: llm span (start → prompt dump file → first_token →
   end with usage), tool span, transition, permission decision events.
6. `empty_loop_smoke` (query.py): produces a complete timeline with no
   model — the P0 exit criterion.
7. Fail-silence: timeline emit with an unwritable run dir does not
   raise (covered by config.safe_cap edge + emit guard).

## Oracle cross-check

Line-for-line against oracle `src/aegis_debug/*`; deviations limited to
the deltas above. The oracle's debug selftest (`src/debug_selftest.py`)
validated handler signatures against langchain 1.6.5 — its 4.0
successor is the LoopObserver API above, verified by tests 5–6.
