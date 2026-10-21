# Cutover Checklist — Hypervisor 3.7.3 → 4.0

**Status: P4 deliverable** · Audience: the engagement operator owning
production retirement of 3.7.3 · Precondition: `hypervisor` 4.0.0a5+,
258→302 tests green, oracle FROZEN, both goldens replay OVERALL OK.

This is the formal retirement path. Nothing here is aspirational —
every verification step names the exact command and the exact expected
result. Do not skip steps; the ordering is load-bearing (each stage
gates the next).

---

## Stage 0 — Host readiness (the doctor)

```bash
python -m hypervisor.cli --doctor
```

Expected: `DOCTOR: host ready — no blocking failures`. Soft failures
(endpoint vars, optional runtimes like frida/mitmdump/sshpass/nmap)
are acceptable ONLY if the engagements being cut over don't exercise
the corresponding tools — an operator attachment that is missing
refuses honestly at call time, but a cutover that needs it must have
it installed.

Blocking (hard) checks: Python ≥ 3.11, stdlib-only runtime contract,
registry composition (platform 9 / VAPT / operator / task), the
replay + SLO + hooks modules importing cleanly.

## Stage 1 — Build verification (the phase-completeness gate)

```bash
python3 /home/z/my-project/scripts/validate_build.py   # 52 checks, 9 families
```

Expected: `VALIDATION PASSED`. This proves the artifact carries the
complete P1+P2+P3(+P4) change set: phase commit ladders, module
inventories, port-card closure, exact cumulative test counts
(125 → 196 → 258 → 302), oracle freeze, golden replays.

## Stage 2 — The ten-fold exit criterion (scripted)

```bash
python3 scripts/run_exit_criterion.py           # 10 scripted runs
```

Expected: `VERDICT: PASS` — every run rc=0, replay OVERALL OK, SLO
OVERALL PASS. The ten scenarios cover: quiet probe, fold pressure
(duplicate-sig folds included), VAPT recon/web, operator frida +
mitm fakes, the stop-hook block+continue, the exec harness, a
subagent spawn, and two stability repeats.

## Stage 3 — The REAL exit criterion (cisai-ultra)

The scripted pass proves the harness; the real pass proves the model
pairing. On the engagement host with the Kemi K2.7 endpoint:

```bash
export AEGIS_OPENAI_BASE_URL=https://<cisai-ultra-endpoint>/v1
export AEGIS_MODEL=<deployment-name>
export AEGIS_OPENAI_API_KEY=<key>
python3 scripts/run_exit_criterion.py --real --runs 10 --max-turns 6
```

Expected: `VERDICT: PASS` with the same criteria. **Analyst review**
(the human gate): read `.exit-criterion/exit-criterion.json`, sample
at least three run journals (`python -m hypervisor.persist.replay
<run-workspace>/.aegis/journal`), and confirm the model's tool
discipline inside scope (permission_denies in the SLO profile are the
GATE WORKING, never a failure by themselves). Sign-off: record the
run date, endpoint, model name, and the reviewed journals in the
engagement record.

## Stage 4 — Parallel run (the two-week shadow)

Run 3.7.3 and 4.0 side by side on engagement copies (never the live
engagement):

1. Clone the engagement workspace; point both stacks at the copy.
2. Run the same objective through each; diff the findings surface
   (not the prose — the finding classes, affected entities, evidence
   references).
3. Verify each 4.0 run replays clean (`python -m hypervisor.persist.replay`).
4. Track divergences in the engagement record; a divergence is a
   finding-class difference, not a wording difference.

Exit: two consecutive weeks with zero unexplained finding-class
divergences.

## Stage 5 — Data migration

| 3.7.3 artifact | 4.0 home | Notes |
|---|---|---|
| Engagement workspaces | unchanged (the workspace IS the unit) | Point the 4.0 CLI at the same workspace root |
| `.aegis/journal/journal.jsonl` | readable as-is | 4.0's replay verifies 3.7.3 journals (the v2 schema was designed back-compatible) |
| SQLite checkpointer state | NOT migrated | 4.0 sessions are 0600 JSONL sidechains; a resumed engagement starts a fresh loop with the journal as history |
| memory SQLite (episodic) | NOT migrated | The EKD rebuilds from the journal's write-ahead mutations — run the engagement objective again or accept a cold memory |
| Scope files | unchanged | Same signed-scope JSON contract |

## Stage 6 — Cutover (the switch)

1. Freeze 3.7.3: no new engagements; record the final commit hash.
2. Stand up 4.0 as the engagement entry point (CLI or the SDK-style
   engine); re-run Stage 0 on the production host.
3. First production engagement: run with `--stop-hook` armed (a
   review hook: block if the final summary lacks the scope
   reference) — the operator's seat belt for the first weeks.
4. Keep the 3.7.3 tree mounted read-only for one engagement cycle
   (rollback window).

Rollback criteria (any one triggers): a scope violation that the 4.0
gate failed to deny (severity: immediate), replay failures on
production journals (severity: within the cycle), SLO regressions the
analyst flags as engagement-impacting (severity: at cycle review).

## Stage 7 — Decommission

After one full engagement cycle on 4.0 with a clean record:

1. Archive: the 3.7.3 tree + its engagement records → cold storage
   with sha256 manifest (the same discipline as the program backup).
2. Preserve: the frozen oracle stays (port-acceptance tests still
   derive from it).
3. Record: the cutover date, the sign-offs, the archive location.

---

## Acceptance summary (what "cutover complete" means)

- [ ] Stage 0 doctor clean on the production host
- [ ] Stage 1 validation 52/52
- [ ] Stage 2 scripted exit criterion 10/10
- [ ] Stage 3 real exit criterion 10/10 + analyst sign-off recorded
- [ ] Stage 4 parallel run: 2 weeks, zero unexplained divergences
- [ ] Stage 5 migration notes in the engagement record
- [ ] Stage 6 first production engagement clean (replay + SLO)
- [ ] Stage 7 archive manifest sha256 recorded, oracle preserved
