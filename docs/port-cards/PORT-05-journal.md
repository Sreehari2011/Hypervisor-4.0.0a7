# PORT-05 — Engagement journal

**Status: ☑ DONE (P0)** · Target: `hypervisor/persist/journal.py`
· Source: `src/journal.py` (1,062 lines, oracle sha in MANIFEST.json)

## What ports

The append-only JSONL event stream — the lossless ground truth every
working context derives from. The single most load-bearing module of
the 3.x lineage.

## Contracts preserved (verbatim behavior — frozen by production data)

- **J1 write-ahead**: journal entries precede the durable state change
  they describe; a crash between journal and state is detectable and
  repairable by replay.
- **J2 revision carriage**: entries carry the rev they produced or
  observed; any brief ever rendered is reconstructible from the journal
  alone (rev + budget + pinned now).
- **J3 never compacted**; export tooling owns external compression.
- **J4 never a gate**: write failures queue (in order), surface through
  `health()`, never raise, never block. H8 opportunistic retry drain at
  `append()` head; TypeError/ValueError payloads clamp-and-retry inline.
- **B1 resume continuation**: `_scan_tail` continues seq/turn/rev from
  the file's last parseable event (bounded 256KB tail read), never
  restarts.
- **M5 torn-tail visibility**: skipped tail lines counted in
  `health().torn_tail_lines`.
- **Sidecar discipline** (refs over blobs, content-derived names,
  sidecar-then-event ordering, 0o600 + fsync): `messages/sig_<sha>.txt`,
  `compaction/summary_<key>.md`, `objective/objective_<hash>.txt`,
  `prompts/prompt_<sha>.txt`, `briefs/brief_<hash>.md`.
- **`message_sig` formula frozen** — window hashes ever journaled were
  computed with exactly this clamp.
- **Event vocabulary v1**: all 33 event type names and shapes unchanged.
- **Payload guard**: MAX_DATA_CHARS=4000 clamp with the `...[N chars]`
  suffix; MAX_INLINE_SIG_CHARS=3990 margin.

## 4.0 deltas

- SCHEMA_VERSION 1 → **2**; `verify_integrity` accepts both, reports
  `unsupported_versions`. V2_EVENT_TYPES = {loop_transition,
  permission_decision, turn_watchdog}.
- New helpers: `record_loop_transition` (CC-style transition table
  surface), `record_permission_decision` (SLO-1 audit: every allow AND
  deny writes one — deny-by-default must be auditable),
  `record_turn_watchdog` (duration-bound trips/abandons/recoveries).
- Config decoupled: the 3.7.3 reach-ins to the flat app `config` module
  (AEGIS_JOURNAL_PROMPTS / _PROMPT_CAP) become env-driven module
  constants, same names and defaults.
- Dead code dropped: the `from journal import sig_sha` self-import
  inside `record_llm_prompt` (imported, never called in 3.7.3).
- "mesh agent output" comment on agent_message generalized to loop
  output; semantics unchanged.

## Acceptance tests (tests/test_journal.py — all passing)

1. seq integrity: strict +1 from 1; `verify_integrity().ok` true.
2. Unknown event type → None; `force=True` → appended.
3. J4: `_write` raising OSError → event queued, `health().degraded`
   true, append still returns the event; disk recovery via
   `flush_retry()` preserves order.
4. B1: second Journal on the same file continues seq (5 → 6), turn,
   rev; integrity still ok across the seam.
5. M5: torn tail line counted, last parseable event still found.
6. Sidecars: oversized sig → `messages/sig_<sha>.txt` (0o600); compaction
   residual → `compaction/summary_<key>.md`; >4KB objective →
   `objective/objective_<hash>.txt`; `record_llm_prompt` writes
   `prompts/prompt_<sha>.txt` + prompt_ref; brief_render writes
   `briefs/brief_<hash>.md`.
7. `message_sig` byte-stability: known-vector sha16 pinned
   (`test_message_sig_frozen_vector`).
8. v2 events: loop_transition / permission_decision / turn_watchdog
   round-trip with full fields; verify_integrity ok.
9. Clamp: 10k-char string field clamped to 4000 + marker.
10. `iter_journal_events` reads v1-shaped lines (no `v` field drift
    handling needed — v1 events carry v:1) without a Journal instance.

## Oracle cross-check

Line-for-line review against oracle `src/journal.py`; only the deltas
above deviate. Every carried comment's invariant re-verified. The
oracle's own test suite (src/tests/test_phase0_v37.py) exercises the
same contracts — its expectations informed tests 1–6.
