# PORT-11 — Brief renderer

**Status: ☑ done** · Target: `hypervisor/memory/brief.py`
· Source: `src/core/semantic_store.py` render path (398-line module;
the store itself is DELETE-04 — the EKD supersedes it)

## What ports

The budgeted engagement brief renderer: pinned clock (`now`), revision
pinning, budget ladder, the render cache keyed on (revision, budget)
with byte-for-byte reuse — the J2-producing surface. Landing spot
splits from the 3.x file: the STORE dies, the RENDERER ports.

## Contracts preserved

- `render_brief(rev, budget, now)` determinism — same triple → same
  bytes, always (replay depends on it).
- Budget ladder (ceiling → floor) and overflow escalation
  (brief_overflow journal event; objective split to first line +
  journal pointer).
- Render cache reuse marks (`cache_hit` in brief_render events).

## 4.0 deltas

- Renders FROM the EKD (PORT-03), not from semantic_store's tiered
  blobs.
- Feeds `context/assemble.py`'s zone S (REFACTOR-02); the assembly
  pins the full prompt hash, the brief renderer pins the brief hash.
- Brief sidecar (`briefs/brief_<hash>.md`) already ported in the
  journal (P0) — the renderer just calls `record_brief_render`.

## Acceptance tests (write on landing)

1. Determinism: frozen (rev, budget, now) → frozen brief sha.
2. Budget floor: oversized briefs escalate + journal brief_overflow.
3. Cache: repeated (rev, budget) → single render, cache_hit marked.
4. Oracle parity: golden-trajectory EKD states → equivalent briefs
   (allowing zone-header deltas documented in REFACTOR-02).

## Landing notes (P2 closeout)

- `memory/brief.py` — `render_brief_l2` (the Table 8 contract: I1-I4,
  the P6->P5->P4->P3 degradation ladder, floor-guaranteed objective /
  tasks / drilldown, the objective-split escalation),
  `render_node_detail` (memory_query drilldown), `BriefRenderer`
  ((rev, budget)-keyed cache with byte-for-byte reuse + original pinned
  clock, J2 journaling through `record_brief_render` with prompt_hash /
  window_hash, `brief_overflow` on the floor-split).
- Determinism: `test_determinism_frozen_triple` — same triple -> same
  bytes; the pinned clock only moves the age string.
- Budget floor: `test_floor_overflow_escalates_and_journals` —
  escalation + journaled overflow payload; the ceiling violation raises
  (never a silent over-budget brief).
- Cache: `test_render_cache_reuse_marks_hit` — repeat render reuses
  bytes, cache_hit marked, rev bump / residual change invalidate.
- Renders FROM the EKD; feeds Zone T through the fixed
  <aegis-brief> delimiter pair (`test_render_attachment_wraps_delimiters`).
- Oracle parity: the section set / order / ladder / default caps are
  the 3.7 spec's fixed facts; zone-header deltas documented in
  REFACTOR-02's landing notes. Golden-trajectory equivalence joins the
  P3 parallel-run.
