# PORT-04 — Tier-A extractors

**Status: ☑ done** · Target: `hypervisor/memory/extractors.py`
· Source: `src/core/dag_extractors.py` (1,230 lines)

## What ports

The deterministic regex/JSON parsers that turn tool results into
bounded EKD batch deltas: findings, hosts, services, ports, evidence
references, credential hints. No LLM in this path — ever (Tier-B
planner-model extraction was the 3.x hidden-LLM suspect; it does NOT
port as an automatic behavior — if 4.0 ever wants it, it goes through
the loop as an explicit side_query, card-amended).

## Contracts preserved

- Extractor table: one extractor per tool family, same regexes/schemas
  (parse behavior is oracle-parity surface).
- Crash containment: a failing extractor records
  `record_extractor_failure`, the batch skips it, the loop never sees
  the exception.
- Bounded deltas: node refs + keys, never raw blobs.
- `extract_tool_result` timing observable (the debug kit's
  tier_a_parse events — now via the memory tap).

## 4.0 deltas

- Runs as a tool post-hook on the loop's executor (off the hot path),
  duration-bounded.
- Emit point: after `tool_result` journal event, before EKD batch
  commit (ordering preserved).

## Acceptance tests (write on landing)

1. Fixture corpus: oracle-recorded tool outputs (nmap, dirb, nuclei,
   saj, httpx JSON from golden trajectories) → identical extracted
   nodes/edges.
2. Malformed inputs: extractor raises internally → journal error event
   + batch continues.
3. Timing: post-hook adds < 50ms p95 on the corpus.

## Landing notes (P2 closeout)

- `memory/extractors.py` — the parser family (nmap / nuclei / mobile /
  http / headless-DOM / free-text battery + CVE references), buffer
  artifact registration with full-output recovery, command-string
  targets via the scope engine's parser, `sync_todos` (the task-DAG
  mirror adapted to todo_write), and the fold auditor (MD-2 killer).
- Fixture corpus: `tests/test_extractors.py` — nmap JSON (hosts, ports,
  tech, state-change supersession, SD-1 scope admission), nuclei JSONL
  (findings, CVE nodes, observed_on), HTTP metadata + passive
  indicators, the security-entity battery (JWT/credential masked
  fingerprint/url/host:port/vuln-class/CVE) with the M14 truncation
  signal.
- Crash containment: `test_run_post_hook_crash_contained` — injected
  parser explosion rolls the batch back, journals the error, bumps the
  counters, the caller never sees it; `test_run_post_hook_ok_path`
  verifies the journal linkage (`tool_call_id` in the mutation event).
- Timing: the post-hook is synchronous regex work on capped renders,
  duration-bounded by the turn watchdog (p95 measurement joins the P3
  golden runs on the real endpoint).
- Tier-B (LLM extraction) did NOT port — per card, never automatic;
  the fold auditor covers hard facts deterministically.
