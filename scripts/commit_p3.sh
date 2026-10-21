#!/usr/bin/env bash
# P3 closeout commits (logical chunks, in order).
set -e
cd /home/z/my-project/hypervisor-4.0

git reset -q

git add hypervisor/agents/prompts.py hypervisor/agents/defs.py \
        scripts/port_agent_prompts.py
git commit -q -m "P3: REFACTOR-03 (1/4) - verbatim agent prompts port (byte-identity asserted) + the 22 agent definitions (6 Table 11 phases + 15 registry_v2 experts + general-purpose)"

git add hypervisor/agents/task.py hypervisor/agents/__init__.py \
        hypervisor/persist/journal.py
git commit -q -m "P3: REFACTOR-03 (2/4) - the Task tool + run_agent: THE loop at depth+1, write-ahead spawn/report linkage, session sidechains, ChildJournal per-channel discipline, done-so-far ceiling clause"

git add hypervisor/memory/sidequery.py hypervisor/query.py hypervisor/cli.py
git commit -q -m "P3: REFACTOR-04 - the L3 side-query engine as a loop deps slot (revision-bump gate, guard-bounded selector, Zone T expansions, J4 never-gates) + CLI wiring (agent_runtime, render_params in boot, AEGIS_SIDEQUERY)"

git add hypervisor/tools/vapt hypervisor/tools/core.py \
        hypervisor/permissions.py
git commit -q -m "P3: REFACTOR-05 (P3 part) - the VAPT toolset: recon (nmap N5, passive scanner battery, OOB), web (http/fetch/waf/static-dom/osint/vhost), exec harness + PoC-only battery, report compiler, mobile static analysis + local tools; code-attr suffix rule in target extraction"

git add hypervisor/persist/replay.py hypervisor/context/assemble.py \
        hypervisor/context/compact.py
git commit -q -m "P3: PORT-06 (1/2) - the replay pass family: integrity, revision chain + v2 surfaces + session linkage, Zone W sim with continuation-insert + per-channel surgery, J2 byte re-render, crash-boundary repair; channel message journaling wired (loop/fold/stubs)"

git add scripts/capture_golden.py tests/golden
git commit -q -m "P3: PORT-06 (2/2) - golden trajectory capture harness + the two captured goldens (fold + quiet), both replay clean"

git add tests/test_agents.py tests/test_sidequery.py \
        tests/test_vapt_tools.py tests/test_replay.py \
        tests/test_p3_e2e.py tests/test_p2_e2e.py \
        tests/test_scaffold.py scripts/p3_smoke.py \
        scripts/run_tests.sh scripts/count_tests.sh \
        scripts/test_summary.sh scripts/update_cards.py
git commit -q -m "P3: acceptance suites (agents 12, sidequery 11, vapt 22, replay 16, e2e 1) - 258 green"

git add -A
git commit -q -m "P3: port cards REFACTOR-03/04/05 + PORT-06 closed with landing notes; version 4.0.0a2 -> 4.0.0a3"

git log --oneline | head -10
