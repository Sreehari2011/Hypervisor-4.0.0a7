# ENG-01-DVWA-FULL — Engagement Runbook (step-by-step, with expected outputs)

The decisive test: a full-capability engagement (real exploitation, chaining,
post-exploitation proof) against your DVWA lab at `http://10.31.0.87:3000/`.

This runbook is executed top-to-bottom. Every step shows WHERE you run it,
WHAT to paste, and the EXPECTED output. If a step shows something different,
stop and read the "If different" note under it before continuing.

---

## 0. The transfer question, answered plainly

**YES. You download `aegis-ENG01-DVWA.zip` from this chat to your laptop,
then scp it to the scanner VM. That is the only way the kit travels.**

- Exact filename: `aegis-ENG01-DVWA.zip` — it is **ENG**-01 (engagement 01),
  not END-01. Watch the spelling when you scp.
- Size: ~21 KB.
- The VM cannot get the kit any other way — nothing was pushed to it when
  this kit was built. (This is the exact step that was missing when the
  UX-02 hermetic zip failed to unzip on the scanner: the zip had never been
  transferred.)

Everything from Step 3 onward happens on the VM, inside the repo.

## 0.1 The whole engagement at a glance

| Step | Where | What | Your time |
|---|---|---|---|
| 0 | browser | initialize DVWA + snapshot | 5 min |
| 1 | laptop | download the zip from this chat | 1 min |
| 2 | laptop → VM | scp the zip; verify sha256 | 1 min |
| 3 | VM | unzip; install the 3 kit files; verify hashes | 2 min |
| 4 | VM | append 3 runtime knobs to `.env` (no rebuild) | 1 min |
| 5 | VM | pre-flight: scope check + target reachability | 2 min |
| 6 | VM | clean-workspace gate | 10 s |
| 7 | VM, in tmux | **LAUNCH — this starts the engagement** | 1 min |
| 8 | VM | supervise (optional, hands-off) | hours |
| 9 | VM | post-flight + collect deliverables | 10 min |

Your active work is Steps 0–7, about 10 minutes total. After Step 7 the
agent runs autonomously for hours; you only watch (Step 8) and collect
(Step 9).

What rides inside the zip (3 working files + this runbook):

| File | Role |
|---|---|
| `tree/workspace/scopes/eng-dvwa-01.json` | signed scope card — host 10.31.0.87 in full, `poc_only: false` |
| `tree/workspace/objectives/eng-dvwa-01-objective.txt` | the 23.6 KB master engagement brief (your legacy prompt, re-grounded in the real tool registry), fed to the agent via stdin at launch |
| `tree/workspace/hooks/review-stop-eng-01.py` | operator stop-hook — quality gate on the final summary |

**Nothing in this kit rebuilds the image or modifies repo code.** The
engine (image `aegis-hypervisor:4.0.0a6` with UX-02 + hermetic conftest,
verified green in the last session) is already built. This kit is fuel and
a route card, not engine work. There is no `patch` and no
`docker compose build` anywhere below.

## 0.2 How this differs from the pilots

| Dial | Pilots | ENG-01 (this run) |
|---|---|---|
| Turn ceiling | `--max-turns 25/35` | **UNLIMITED** — no `--max-turns` flag (your legacy 1,500,000 expressed the 4.0 way) |
| RoE | `poc_only: true` | **`poc_only: false`** — web shells, reverse shells, payload upload + execution, persistence proof are ALLOWED |
| Scope | 1 host, recon-adjacent | whole host 10.31.0.87 — port 3000 app plus any other service on it, for chaining |
| Objective | 4-line recon note | 23.6 KB full master brief |
| Stop discipline | thin-summary gate | coverage gate: per-class verdicts + negative results + `final_report.json` |

Still blocked by the platform regardless of RoE (correct for a lab): the
destructive class (`rm -rf /`, `mkfs`, fork bombs) and interactive client
prefixes (ssh/telnet/ftp/`mysql -u`/`psql -U` — non-interactive flag forms
pass). The stop-hook can block at most ONCE per engagement (recursion
guard); its single block reason is cumulative.

---

## Step 0 — DVWA housekeeping (BROWSER, 5 min, before launching)

1. Open `http://10.31.0.87:3000/setup.php`. If the page offers
   **Create / Reset Database**, click it once.
   Expected: "Database has been created." and a link back to the login page.
   Why: an uninitialized DVWA redirects every page to setup and wastes the
   first phase of the run.
2. Log in once manually (`admin` / `password`) just to confirm the app works.
   You do NOT need to change the security level — the brief tells the agent
   to work the Low → Medium → High ladder itself via `/security.php`.
3. Snapshot or back up whatever backs the DVWA (docker volume or VM
   snapshot). Full capability means the agent will upload files and may
   modify DB rows; a reset path is good hygiene.

## Step 1 — Download the kit (YOUR LAPTOP, 1 min)

Download `aegis-ENG01-DVWA.zip` from this chat's deliverables. It lands in
your Downloads folder (~21 KB). The zip-level sha256 is published in the
chat message that delivered this kit — compare it if you want
belt-and-braces before transferring.

## Step 2 — Transfer to the VM (LAPTOP → VM, 1 min)

On your laptop:

```
scp ~/Downloads/aegis-ENG01-DVWA.zip user1@vts-scanner:~/
```

Expected: one progress line, then your prompt back. Nothing else.

Then ssh in and verify the copy landed intact:

```
ssh user1@vts-scanner
sha256sum ~/aegis-ENG01-DVWA.zip
```

Expected: the sha256 published in the delivery chat message.

If different → the transfer corrupted the file; re-run the scp.
If `No such file or directory` → the scp did not land; repeat Step 2.

## Step 3 — Install the kit files (VM, 2 min)

```
cd ~/Hypervisor/hypervisor-4.0
unzip -o ~/aegis-ENG01-DVWA.zip
```

Expected (the inflate listing; order may vary):

```
Archive:  /home/user1/aegis-ENG01-DVWA.zip
   creating: eng-dvwa-01-kit/tree/workspace/hooks/
  inflating: eng-dvwa-01-kit/tree/workspace/hooks/review-stop-eng-01.py
   creating: eng-dvwa-01-kit/tree/workspace/scopes/
  inflating: eng-dvwa-01-kit/tree/workspace/scopes/eng-dvwa-01.json
   creating: eng-dvwa-01-kit/tree/workspace/objectives/
  inflating: eng-dvwa-01-kit/tree/workspace/objectives/eng-dvwa-01-objective.txt
  inflating: eng-dvwa-01-kit/SHA256.txt
  inflating: eng-dvwa-01-kit/ENG-RUNBOOK.md
```

Now place the three files into the repo's workspace tree:

```
mkdir -p workspace/scopes workspace/hooks workspace/objectives
cp eng-dvwa-01-kit/tree/workspace/scopes/eng-dvwa-01.json              workspace/scopes/
cp eng-dvwa-01-kit/tree/workspace/hooks/review-stop-eng-01.py          workspace/hooks/
cp eng-dvwa-01-kit/tree/workspace/objectives/eng-dvwa-01-objective.txt workspace/objectives/
chmod +x workspace/hooks/review-stop-eng-01.py
```

Expected: silent — `cp` and `chmod` print nothing on success.

Verify integrity (must match exactly):

```
sha256sum workspace/scopes/eng-dvwa-01.json \
          workspace/hooks/review-stop-eng-01.py \
          workspace/objectives/eng-dvwa-01-objective.txt
```

Expected:

```
676594636938f18f7a05cffd7ce0742c56b62f4e12ded20b3e244f88dbb6a97d  workspace/scopes/eng-dvwa-01.json
d12ab7066b806588e473252d5dbe7ca1aebf23476ead893b80c2a6527e8c7ef3  workspace/hooks/review-stop-eng-01.py
3d5afc71d5b73d16f5e53cbe9b2fa5e2365ac6e9003e454541baa9eeb98083ab  workspace/objectives/eng-dvwa-01-objective.txt
```

If any line differs → do not launch; re-download the zip (Step 1) and
repeat Steps 2–3.

## Step 4 — Runtime knobs (VM, 1 min, NO rebuild)

`.env` is read at container creation time, so appending is enough. There is
deliberately no `docker compose build` in this procedure.

```
cd ~/Hypervisor/hypervisor-4.0
grep -q '^AEGIS_TURN_BUDGET_S=' .env      || echo 'AEGIS_TURN_BUDGET_S=5400'    >> .env
grep -q '^AEGIS_SUBAGENT_MAX_TURNS=' .env || echo 'AEGIS_SUBAGENT_MAX_TURNS=16' >> .env
grep -q '^AEGIS_AGENT_TIMEOUT_S=' .env    || echo 'AEGIS_AGENT_TIMEOUT_S=3600'  >> .env
```

Expected: silent. The lines are guarded — re-running never duplicates them.

Confirm the knobs actually reach a fresh container:

```
docker compose run --rm aegis sh -c \
  'env | grep -E "AEGIS_(TURN_BUDGET_S|SUBAGENT_MAX_TURNS|AGENT_TIMEOUT_S|CONTEXT_WINDOW_TOKENS|MAX_OUTPUT_TOKENS)" | sort'
```

Expected — after the usual doctor preflight banners, exactly these five lines:

```
AEGIS_AGENT_TIMEOUT_S=3600
AEGIS_CONTEXT_WINDOW_TOKENS=200000
AEGIS_MAX_OUTPUT_TOKENS=3072
AEGIS_SUBAGENT_MAX_TURNS=16
AEGIS_TURN_BUDGET_S=5400
```

Why these three: `AEGIS_TURN_BUDGET_S=5400` raises the per-turn watchdog
(the default 1800 s would TERMINATE the whole engagement if one turn's tool
batch runs long — it bounds a turn, never the engagement); 16 / 3600 give
subagents deeper headroom for `task` deep-dives. Your existing pins (200k
window / 3072 output) stay untouched — the brief already compensates for
the 3072-token output cap by sending long content to files.

## Step 5 — Pre-flight (VM, 2 min)

Get a shell inside a fresh container:

```
docker compose run --rm aegis
```

Expected: the doctor preflight you already know — endpoint
`http://10.31.5.112:4000/v1` reachable, model cisai-ultra, 9/33/34 tool
registry, binary execs OK — then a root prompt at `/app`. (Doctor prints
version `4.0.0a5` vs build banner `a6` — known cosmetic, a7 backlog, ignore.)

**a. Scope card validates, is signed, and RoE is full-capability:**

```
python3.11 -m hypervisor.cli --check-scope /app/workspace/scopes/eng-dvwa-01.json
```

Expected: exit code 0, and the output carries these tokens:
`sha256:a51b16899808f252@v1` together with `(signed)`, `strict`, and
`poc_only` = False. (Exact wording may vary — the tokens must be there.)
Anything else → do NOT launch; paste the output back into the chat.

**b. Target reachable from inside the container:**

```
curl -sSI http://10.31.0.87:3000/login.php
```

Expected: `HTTP/1.1 200 OK` plus `Server:` / `X-Powered-By:` headers and a
`PHPSESSID` cookie line.
If you see a 302 redirect to `setup.php` → DVWA is uninitialized; go back
to Step 0.

Then leave the container:

```
exit
```

Note: `10.31.0.87` is inside the proxychains `localnet 10/8` exemption, so
target traffic goes DIRECT — the proxy mount only matters for external
egress, which this engagement does not need.

## Step 6 — Clean-workspace gate (VM, 10 seconds)

One engagement, one fresh workspace:

```
cd ~/Hypervisor/hypervisor-4.0
ls workspace/eng-dvwa-01
```

Expected — this exact error is what you WANT to see:

```
ls: cannot access 'workspace/eng-dvwa-01': No such file or directory
```

If it lists files instead → a previous run exists; archive it first
(`workspace/archive/` or out-of-tree `~/aegis-archive/`), never delete.

## Step 7 — LAUNCH (VM, inside tmux — this is where the engagement starts)

The run is hours long. tmux protects it from an SSH drop.

```
tmux new -s eng01
```

You are now inside a tmux session. Detach any time with `Ctrl-b d`; come
back with `tmux attach -t eng01`.

Then the launch command — paste as one block:

```
cd ~/Hypervisor/hypervisor-4.0
docker compose run --rm aegis python3.11 -m hypervisor.cli \
  --scope /app/workspace/scopes/eng-dvwa-01.json \
  --objective - \
  --workspace /app/workspace/eng-dvwa-01 \
  --stop-hook /app/workspace/hooks/review-stop-eng-01.py \
  < workspace/objectives/eng-dvwa-01-objective.txt
```

Reading the launch line:

- `--objective -` plus the `< file` redirect: the 23.6 KB brief streams in
  via stdin from the host-side file. No shell-quoting games with the master
  prompt, and the file never needs to exist in-container.
- **NO `--max-turns` flag**: omitted = the designed UNLIMITED main loop
  (your legacy 1,500,000 turns, expressed the 4.0 way). If the literal
  number feels better, adding `--max-turns 1500000` is equivalent at any
  realistic scale.
- `--stop-hook`: arms the coverage gate.
- `--workspace /app/workspace/eng-dvwa-01`: everything the agent produces
  (evidence, ledgers, `final_report.json`, `report.md`) lands under this
  one directory — on the host at
  `~/Hypervisor/hypervisor-4.0/workspace/eng-dvwa-01/`.

First minute — the stderr banners must show:

```
[scope] sha256:a51b16899808f252@v1(signed) | mode=strict | 1 rules | 0 excludes
[context] ... (the 200000-token window pin)
[hooks] stop-hook armed: /app/workspace/hooks/review-stop-eng-01.py
```

and must NOT show `[ekd] crash recovery applied` (that would mean a reused
workspace). After the banners, the agent begins Phase 1 recon and you will
see tool calls start. **THE ENGAGEMENT IS NOW RUNNING.** Detach with
`Ctrl-b d` and check in occasionally.

Single-boot freshness check (in another shell, after a few turns):

```
docker exec $(docker ps -q --filter ancestor=aegis-hypervisor:4.0.0a6) \
  grep -c '"type": "boot"' /app/workspace/eng-dvwa-01/.aegis/journal/journal.jsonl
```

Expected: `1`

## Step 8 — Supervision (VM, optional but recommended for the decisive run)

A second shell INSIDE the running engagement container:

```
CID=$(docker ps -q --filter ancestor=aegis-hypervisor:4.0.0a6)
docker exec -it $CID zsh
tail -f /app/workspace/eng-dvwa-01/.aegis/journal/journal.jsonl | \
  jq -c 'select(.type=="turn_end") | {turn: .turn, tool_calls: .data.tool_calls}'
```

What to watch (all of these are NORMAL):

- Early `permission_decision` denials — the agent forgetting to name the
  target inline; the brief tells it to re-issue with the target named.
  Persistent denials against 10.31.0.87 itself would be a scope problem
  (none expected — verified during kit build).
- `autocompact` folds — under real exploitation volume the 200k window
  folds several times; that is the memory system doing its job. Watch that
  the agent re-orients after each fold.
- Watchdog silence — that is what `TURN_BUDGET_S=5400` buys.
- At most ONE `stop_hook_blocked` transition — a second natural stop is
  always accepted (recursion guard). If coverage is still visibly thin at
  that point, it is a findings-quality call for the engagement record, not
  a platform defect.

Abort if you must: `Ctrl-C` in the tmux pane — a clean, journaled stop
(rc 130); the workspace and journal persist.

## Step 9 — Post-flight (VM, 10 min, after the agent stops)

```
docker compose run --rm aegis
python3.11 -m hypervisor.persist.replay /app/workspace/eng-dvwa-01/.aegis/journal
python3.11 -m hypervisor.debug.slo     /app/workspace/eng-dvwa-01/.aegis/journal
grep -c '"type": "boot"' /app/workspace/eng-dvwa-01/.aegis/journal/journal.jsonl
exit
```

Expected: replay verifies clean (no hash mismatches), and the last command
prints `1`.

Exit code of the launch command, for the record:
`0` = natural completion (end_turn — the good ending) · `2` = prompt_too_long
· `3` = turn watchdog · `4` = model error.

Deliverables, on the host under `~/Hypervisor/hypervisor-4.0/workspace/eng-dvwa-01/`:

| File | What it is |
|---|---|
| `final_report.json` | the structured report — findings + CVSS v3.1 + chains + negative results + novel findings |
| `report.md` | the EKD compile_report output |
| `evidence/<class>/...` | raw request/response/PoC per finding |

When the engagement closes, archive the whole workspace directory per the
standing runbook (`workspace/archive/` or out-of-tree `~/aegis-archive/`) —
never delete.

## Step 10 — Analyst review (record in the engagement record)

- run date, endpoint, model (cisai-ultra), journal reviewed
- fresh workspace: single boot event, no recovered prior EKD
- tool discipline inside scope (denials = the gate working)
- stop-hook: at most one block, then approve
- the decisive-test question, answered with evidence: did the agent
  EXPLOIT (proof of impact per finding, chains to RCE / DB dump / admin
  takeover, bypass matrix across security levels) or merely SCAN?
- fold behavior under exploitation volume; sanitizer behavior on
  sqlmap/nikto noise; watchdog quiet; subagent quality if `task` used

## Troubleshooting quick table

| Symptom | Meaning | Fix |
|---|---|---|
| `unzip: cannot find or open ... aegis-ENG01-DVWA.zip` | zip never transferred (the UX-02 lesson) | Step 2 — scp it to the VM |
| `cp: cannot create ... No such file or directory` | not in the repo root when pasting | `cd ~/Hypervisor/hypervisor-4.0` first |
| a kit file's sha256 differs | corrupted download | redo Steps 1–3 |
| `curl` shows 302 to `setup.php` | DVWA uninitialized | Step 0 |
| doctor endpoint check fails | model endpoint down | engagement cannot run; restore the endpoint first |
| `[ekd] crash recovery applied` banner at launch | workspace already existed | Step 6 was skipped; archive and relaunch |

## Rollback / teardown

- The three `.env` knobs are engagement-runtime only; comment them out or
  leave them — the hermetic conftest pops exactly these variables for the
  test suite, so they cannot pollute pytest runs.
- The scope file is an engagement artifact; keep it with the archive.
- Nothing in the image or the repo code was modified by this kit.
