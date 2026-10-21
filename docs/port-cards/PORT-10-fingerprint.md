# PORT-10 — Zone fingerprinting

**Status: ☑ done** · Target: `hypervisor/context/assemble.py` (guard)
· Source: `src/fingerprint.py` (221 lines)

## What ports

The zone fingerprint computation: stable digest of the assembled
prompt's static prefix (system + zone S), emitted as
`cache_fingerprint` journal events with drift detection — the
prefix-cache economics guard (CC's initFingerprint analog:
model | tools | sysLen).

## Contracts preserved

- Fingerprint formula over the same byte span (a changed span silently
  defeats drift detection).
- Drift = fingerprint change without a recorded cause (phase
  transition, scope change) → journaled + surfaced, never silent.

## 4.0 deltas

- Guard moves into the assembler's render path; every render emits or
  reuses the fingerprint (cache_hit events pair with brief_render).
- OpenAI-compatible endpoints have different cache economics than the
  Anthropic API — the fingerprint stays as the *drift* instrument; the
  cost model it feeds becomes vLLM-specific in P2 tuning.

## Acceptance tests (write on landing)

1. Same inputs → same fingerprint (frozen vector).
2. Zone S change without cause → drift event; with cause (phase
  transition) → no drift.
3. Golden-trajectory renders: fingerprint sequence matches the
   oracle's cache_fingerprint events for equivalent inputs.

## Landing notes (P2 closeout)

- `context/fingerprint.py` — `assembly_fingerprint` (M5 triple, M13
  content-digest), `FingerprintMonitor` with per-actor baselines,
  `set_phase` re-freeze, strict-mode `ZoneViolationError`.
- Frozen vector: `test_fingerprint_frozen_vector` — the digest formula
  pinned; same-length system rewrites ARE drift (content digest).
- Drift: `test_fingerprint_monitor_baseline_drift_strict` — attribution
  (model / tools(+diff) / system content), journaled cache_fingerprint
  events, strict mode raises within the phase and the phase transition
  re-freezes.
- Rides the assembler: `test_fingerprint_monitor_rides_assembly` —
  every `assemble_prompt` with a monitor attached checks the triple;
  wired in the CLI boot chain (model + frozen tool names).
- Golden-trajectory fingerprint-sequence A/B joins the P3 parallel-run
  (the harness defers golden capture to P3 kickoff per the phase plan).
