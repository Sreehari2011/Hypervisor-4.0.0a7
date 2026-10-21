# REFACTOR-02 — Zone assembler → byte-stable assembly

Phase: P2 · Target: `hypervisor/context/assemble.py`

**Status: ☑ done (P2)**
· Source: `src/core/context_assembler.py` (549 lines)

Zones S (static: system + engagement brief), W (working window), T
(attachments: EKD expansions) survive as the assembly layout — now
feeding a plain messages array instead of a LangGraph prompt. The
byte-stability contract tightens: prefix-cache-stable ordering (zone S
never changes within a phase; changes only at journaled causes), full
prompt hash + window hash pinned per render (journal brief_render
already carries them), fingerprint guard from PORT-10. Zone T's
expansion injection caps at injection time (the journal never distorts
what the model received — side_query events carry the capped text).
Acceptance: same state → byte-identical prompt; drift only at journaled
causes; window hashes replay-verified.

## Landing notes (P2 closeout)

- `context/assemble.py` — zones S/W/T: S static (system prompt only —
  the oracle's final L2 shape after the 2026-10-06 strip; the earlier
  blueprint card text placing the brief in S documented as superseded
  by the oracle's C1 ruling), W the post-preflight channel the loop
  owns, T the single injector (brief attachment + drilldown expansions
  immediately before the current turn's group).
- Byte-stability: prompt-only injection (state.messages never mutated
  by assembly); system+window prefix stable turn over turn; the
  attachment sits at the tail by construction. Full prompt hash +
  window hash pinned per render via the renderer's J2 events
  (`test_zone_assembly_s_w_t`).
- Pairing discipline: `group_message_indices` / `select_working_window`
  / `window_is_pairing_safe` adapted to 4.0's block-shaped dict
  messages; the frozen journal `message_sig` formula feeds on a
  read-only `_MsgView` adapter (the formula itself untouched).
- Drift only at journaled causes: the PORT-10 monitor rides the render
  path; `after_compact_boundary` implements the loop's step-1 contract
  (marker scan; live no-op, resume-active).
