# The Ten-Fold Exit Criterion — Runbook

**Status: P4 deliverable** · Harness: `scripts/run_exit_criterion.py`
· Criterion (ratified, blueprint Ch.14): N consecutive full-stack
engagement runs, each with rc=0, PORT-06 replay OVERALL OK, and SLO
audit OVERALL PASS (no-data verdicts allowed for planes the run never
touched). Ten is the floor; the real-mode pass against cisai-ultra is
the acceptance run for analyst review.

## What each run is

A fresh workspace, a fresh signed scope, a fresh journal — the full
CLI chain (scope load → deny-by-default gate → registry freeze → EKD
recovery → THE loop) driven to `end_turn`, then verified by the same
battery replay uses. Nothing is mocked above the model wire: the
endpoint is either the in-process scripted SSE fake (deterministic,
CI-grade) or the real OpenAI-compatible endpoint.

## The scripted scenarios (default mode)

| # | Name | Exercises |
|---|------|-----------|
| 1 | quiet-probe | the minimal path: one run_command, one final |
| 2 | fold-pressure | window 6000 + heavy tool outputs → a mid-engagement fold (includes the duplicate-sig drop shape that found the replay multiset bug) |
| 3 | vapt-recon | check_port_listener + advanced_http_request through the permission gate |
| 4 | operator-frida | frida_hook with the fake frida runtime on PATH (bounded capture window) |
| 5 | operator-mitm | mitm_intercept with the fake mitmdump (window + proxy configuration block) |
| 6 | stop-hook | the CC-shaped stop hook blocks the first stop (exit 2), approves the second — the loop continues and the feedback rides the journaled channel |
| 7 | exec-harness | execute_code through the bounded subprocess harness |
| 8 | subagent | a task-tool spawn (the child loop at depth+1, session sidechain) |
| 9-10 | mixed-a/b | stability repeats of the mixed profile |

## Running it

```bash
# scripted (CI / pre-flight)
python3 scripts/run_exit_criterion.py
python3 scripts/run_exit_criterion.py --runs 5      # subset
python3 scripts/run_exit_criterion.py --json        # machine-readable
python3 scripts/run_exit_criterion.py --keep        # keep all workspaces

# REAL (the acceptance run — analyst review required)
export AEGIS_OPENAI_BASE_URL=https://<cisai-ultra>/v1
export AEGIS_MODEL=<name>
export AEGIS_OPENAI_API_KEY=<key>
python3 scripts/run_exit_criterion.py --real --runs 10 --max-turns 6
```

Exit code 0 = PASS. The consolidated verdict lands in
`.exit-criterion/exit-criterion.json`; failing runs keep their
workspaces for inspection (passing ones are swept unless `--keep`).

## The verification battery (per run)

1. **rc == 0** — the loop reached `end_turn` (not max_turns, not a
   watchdog, not an error).
2. **Replay OVERALL OK** — integrity (seq chain, v2 schema),
   revision chain (EKD mutations, snapshots, folds, sidecars, spawn/
   report linkage, permission decisions, watchdog spans, stop-hook
   runs), renders (byte-identical brief re-renders + Zone W window
   hashes), session linkage (sidechain transcripts pair with spawns),
   crash boundary.
3. **SLO OVERALL PASS** — the pure-journal performance audit: turn /
   model-call / tool-dispatch / stop-hook latency quantiles against
   the SLO table (env-tunable via `AEGIS_SLO_*`), zero watchdog
   trips, zero guard abandons, LLM error rate under bound.

## Analyst review protocol (real mode)

1. Read `exit-criterion.json` — every run's replay detail + SLO
   profile side by side.
2. Sample ≥ 3 run workspaces: `python -m hypervisor.persist.replay
   <workspace>/.aegis/journal` (expect OVERALL OK) and `python -m
   hypervisor.debug.slo <same>` (expect OVERALL PASS).
3. Confirm tool discipline: permission allows/denies in the SLO
   profile should match the engagement intent; denies are the gate
   working, never automatically a failure.
4. Confirm token accounting: the profile's prompt/completion totals
   vs the endpoint's own metering (they will not match exactly — the
   profile counts usage chunks — but the ratio should be stable
   across runs).
5. Record: date, endpoint, model, reviewed journals, verdict.

## History

- P4 development run (scripted): 10/10 PASS after fixing two real
  bugs the harness caught — (1) the stop-hook block feedback message
  was not a journaled channel member (Zone W mismatch), (2) replay's
  fold-drop check was set-based and miscounted duplicate sigs (two
  identical tool results folded together). Both fixes are regression-
  tested in `tests/test_stop_hook.py` and `tests/test_p4_e2e.py`.
- Post-acceptance fidelity fixup (after the first real-mode 10/10 on
  the engagement host): three scripted scenarios carried tool args
  that the REAL schemas reject — `check_port_listener` got a bogus
  `host` (the oracle tool is LOCAL-only by design), the `task` call
  used `description`/`prompt` instead of the required `{agent,
  task}`, and `sequential_thinking` omitted three required fields.
  Those runs passed the criterion but exercised the invalid-args
  error path, not the intended tools. All scenario args now match
  the schemas byte-for-byte: the subagent run performs a REAL spawn
  (journal `subagent_spawn`+`subagent_report`, child sidechain under
  `.aegis/sessions/` with parent linkage), and the mixed profile
  executes its full tool ladder. Also fixed: the fake-endpoint
  teardown TypeError (`run_until_complete(server.close())` fed a
  plain method's `None` to the loop — now a synchronous close plus a
  bounded `wait_closed`), and the real-mode objective now states the
  tool's local-port semantics explicitly. The first real-mode PASS
  stands: the criterion was met and the model's honest handling of
  the old objective wording (it called the tool within schema and
  caveated the local-vs-remote limitation unprompted) was itself
  good discipline evidence.
- Observability wiring fixup (after the second real-mode 10/10, run
  with `--keep` on Python 3.11): the analyst review found the SLO
  audit's model plane reading ZERO model calls and ZERO tokens from
  real journals. Three wiring defects, none of which the criterion's
  rc/replay/SLO gate could catch (no-data verdicts never fail): (1)
  `cli.py` built the main-loop guard via `production_deps` WITHOUT
  the engagement journal — every defense event (`llm_call`,
  `llm_call_end`, retry, abandon, breaker) was silently dropped;
  (2) the query loop never journaled `turn_end` (a registered event
  type, the SLO token plane's designed source) — the cumulative
  counters lived only in the `[completed]` line; (3) the guard
  journaled `llm_call` once per call without an attempt number while
  `llm_call_end` is per-attempt — the SLO's (purpose, turn, attempt)
  pairing could never match. Now: ONE journal-wired guard reaches
  every model call site (main loop, fold summarizer, subagents, side
  queries), `llm_call` is per-attempt with the matching number, and
  each assembled reply journals a `turn_end` with cumulative tokens.
  The same review caught the real-mode runs being byte-identical
  requests — run 1 took 13.5 s, runs 2-10 returned in 0.1-0.2 s from
  the gateway's response cache (an effective n=1 for model-side
  evidence); the objective now carries the run number and engagement
  id so each run is a fresh inference. Regression-tested in
  `tests/test_observability.py`; version 4.0.0a4 -> 4.0.0a5.
