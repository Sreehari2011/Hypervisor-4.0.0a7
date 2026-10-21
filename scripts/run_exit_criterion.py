#!/usr/bin/env python3
"""The ten-fold exit criterion harness (P4, blueprint Ch.14).

Runs N scripted full-stack engagements (default 10) — every run a
fresh workspace, fresh scope, fresh journal — then verifies EACH run
with the PORT-06 replay pass family and the P4 SLO audit, and emits a
consolidated analyst-reviewable verdict.

Exit criterion (ratified): N consecutive runs with
  * process rc == 0 (end_turn completion),
  * replay OVERALL OK (integrity, revision chain, renders, session
    linkage, crash boundary),
  * SLO audit OVERALL PASS (no-data verdicts allowed for planes the
    run never touched),
  * zero watchdog trips / guard abandons,
  * the fold discipline consistent (folds counted, continuations
    byte-verified by replay).

Modes:
  fake (default)  scripted engagements against the in-process fake
                  endpoint — deterministic, CI-grade; several runs
                  exercise the P4 surfaces (operator fakes on PATH,
                  the stop-hook, subagent spawns, fold pressure).
  --real          engagements against the endpoint configured in the
                  environment (AEGIS_OPENAI_BASE_URL / AEGIS_MODEL /
                  AEGIS_OPENAI_API_KEY — the cisai-ultra deployment):
                  the REAL exit-criterion run for analyst review; the
                  model drives, runs are turn-bounded, journals are
                  verified identically.

Usage:
  python3 scripts/run_exit_criterion.py [--runs N] [--real] [--json]
                                        [--keep] [--max-turns N]
"""
from __future__ import annotations

import argparse
import asyncio
import errno
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))

OUTPUT = PROJECT / ".exit-criterion"


# ─── the scripted engagements (fake mode) ───────────────────────────────

def _scenarios() -> list:
    """Ten scripted engagements covering the acceptance surface:
    quiet, fold pressure, VAPT tools, operator attachments (fake
    runtimes on PATH), the stop-hook block+continue, subagent spawn,
    exec harness, and repeats for stability."""
    S = []
    # 1 — quiet: one probe, done
    S.append(("quiet-probe", [
        ("tool", "run_command", {"command": "echo probe 10.10.0.5"}),
        ("final", "Run 1 complete: one host probed.", None)], {}))
    # 2 — fold pressure: heavy outputs force the ladder
    heavy = ("probe 10.10.0.5 CVE-2021-44228 password=hunter2 ") * 150
    S.append(("fold-pressure", [
        ("tool", "run_command", {"command": f'echo "{heavy}"'}),
        ("tool", "run_command", {"command": f'echo "{heavy}"'}),
        ("final", "Run 2 complete: fold exercised.", None)],
        {"AEGIS_CONTEXT_WINDOW_TOKENS": "6000"}))
    # 3 — VAPT recon + web through the gate (check_port_listener is
    # LOCAL-only by oracle design — reverse-shell handler verification;
    # the args must match the real schema: {port} and nothing else)
    S.append(("vapt-recon", [
        ("tool", "check_port_listener", {"port": 80}),
        ("tool", "advanced_http_request",
         {"url": "http://10.10.0.5/app", "method": "GET"}),
        ("final", "Run 3 complete: recon + web done.", None)], {}))
    # 4 — operator attachments (fake frida/mitmdump on PATH)
    S.append(("operator-frida", [
        ("tool", "frida_hook",
         {"package_name": "com.lab.app", "hook_type": "api_monitor",
          "duration": 4}),
        ("final", "Run 4 complete: frida capture window harvested.", None)],
        {"_operator_fakes": True}))
    S.append(("operator-mitm", [
        ("tool", "mitm_intercept", {"port": 18082, "duration": 4}),
        ("final", "Run 5 complete: mitm window harvested.", None)],
        {"_operator_fakes": True}))
    # 6 — the stop-hook block + continue (hook blocks the first stop)
    S.append(("stop-hook", [
        ("tool", "run_command", {"command": "echo scope-check"}),
        ("final", "Run 6 first attempt.", None),
        ("final", "Run 6 complete after the hook's guidance.", None)],
        {"_stop_hook": "block-once"}))
    # 7 — exec harness
    S.append(("exec-harness", [
        ("tool", "execute_code",
         {"python_code": "print('evidence: 2+2=', 2+2)\n"
                         "import hashlib\n"
                         "print(hashlib.sha256(b'poc').hexdigest()[:16])"}),
        ("final", "Run 7 complete: code harness exercised.", None)], {}))
    # 8 — subagent spawn through the task tool (schema: {agent, task};
    # the child's model calls hit the same scripted endpoint — it
    # receives the scripted final as its end_turn, reports it, and the
    # exhausted script replays its last item for the parent's final)
    S.append(("subagent", [
        ("tool", "task",
         {"agent": "general-purpose",
          "task": "Probe the lab segment with one echo command "
                  "mentioning 10.10.0.5 and report the result in one "
                  "sentence."}),
        ("final", "Run 8 complete: subagent reported.", None)], {}))
    # 9 + 10 — stability repeats of the mixed profile
    mixed = [
        ("tool", "run_command", {"command": "echo step-1 10.10.0.5"}),
        ("tool", "check_port_listener", {"port": 22}),
        ("tool", "sequential_thinking",
         {"thought": "two hosts up; prioritize the web face",
          "next_thought_needed": True,
          "thought_number": 1, "total_thoughts": 1}),
        ("final", "Run complete: mixed profile done.", None)]
    S.append(("mixed-a", list(mixed), {}))
    S.append(("mixed-b", list(mixed), {}))
    return S


COMPACT_SYSTEM_MARK = "CRITICAL: Respond with TEXT ONLY"
COMPACT_REPLY = (
    "<analysis>draft</analysis>\n<summary>\n"
    "1. Primary Request and Intent: exercise the lab.\n"
    "3. Files and Code Sections: host 10.10.0.5 e2.\n"
    "5. Problem Solving: probes completed.\n</summary>"
)


class Endpoint:
    """The scripted SSE endpoint (fake mode) — same wire contract as
    tests/fake_endpoint.py, with stop-hook + subagent awareness."""

    def __init__(self, script):
        from fake_endpoint import _delta, _sse, _tc_args, _tc_start, \
            _usage_chunk
        self._delta, self._sse = _delta, _sse
        self._tc_args, self._tc_start = _tc_args, _tc_start
        self._usage_chunk = _usage_chunk
        self.script = script
        self.calls = 0

    async def handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if line.startswith(b"POST "):
                    path = line.split()[1].decode()
                    headers = {}
                    while True:
                        h = await reader.readline()
                        if h in (b"\r\n", b"\n", b""):
                            break
                        k, _, v = h.decode().partition(":")
                        headers[k.strip().lower()] = v.strip()
                    n = int(headers.get("content-length", 0))
                    body = await reader.readexactly(n) if n else b""
                    if path not in ("/chat/completions",
                                    "/v1/chat/completions"):
                        writer.write(b"HTTP/1.1 404 Not Found\r\n"
                                     b"Content-Length: 0\r\n\r\n")
                        await writer.drain()
                        continue
                    is_compact = b"CRITICAL: Respond with TEXT ONLY" in body
                    if is_compact:
                        payload = self._sse([
                            self._delta(content=COMPACT_REPLY,
                                        finish="stop"),
                            self._usage_chunk(300, 60)])
                    else:
                        idx = min(self.calls, len(self.script) - 1)
                        kind, name, args = self.script[idx]
                        self.calls += 1
                        if kind == "tool":
                            payload = self._sse([
                                self._delta(content="Working.\n"),
                                self._delta(tool_calls=[
                                    self._tc_start(0, name)]),
                                self._delta(tool_calls=[
                                    self._tc_args(0, json.dumps(args))],
                                    finish="tool_calls"),
                                self._usage_chunk(150, 24)])
                        else:
                            payload = self._sse([
                                self._delta(content=name, finish="stop"),
                                self._usage_chunk(220, 40)])
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/event-stream\r\n"
                        b"Cache-Control: no-cache\r\n"
                        b"Connection: keep-alive\r\n"
                        b"Content-Length: " +
                        str(len(payload)).encode() + b"\r\n\r\n" + payload)
                    await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def start_endpoint(ep):
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def _run():
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(
            asyncio.start_server(ep.handle, "127.0.0.1", 0))
        ep.port = server.sockets[0].getsockname()[1]
        ready.set()
        try:
            loop.run_forever()
        finally:
            # Server.close() is a PLAIN (non-awaitable) method — the
            # old run_until_complete(server.close()) fed it None and
            # raised TypeError in this thread once per run. Close
            # synchronously, then bound the wait for socket teardown.
            try:
                server.close()
                loop.run_until_complete(
                    asyncio.wait_for(server.wait_closed(), timeout=2.0))
            except Exception:
                pass
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    return loop


# ─── the operator fake runtimes ─────────────────────────────────────────

FAKE_BINARIES = {
    "frida": """#!/bin/sh
echo '[*] API Monitor Active'
echo '[URL] http://10.10.0.5/api/v1/login'
echo '[OKHTTP] GET http://10.10.0.5/api/v1/login'
sleep 30
""",
    "mitmdump": """#!/bin/sh
echo 'Proxy server listening at *:18082'
echo '[REQ] GET http://10.10.0.5/app'
echo '[RES] 200 http://10.10.0.5/app'
sleep 30
""",
    "ssh": """#!/bin/sh
echo 'remote-output: ok'
echo 'uid=0(root) gid=0(root) groups=0(root)'
exit 0
""",
    "sshpass": """#!/bin/sh
shift 2 2>/dev/null
exec "$@"
""",
}


def install_operator_fakes(bindir: Path) -> None:
    bindir.mkdir(parents=True, exist_ok=True)
    for name, body in FAKE_BINARIES.items():
        p = bindir / name
        p.write_text(body)
        p.chmod(0o755)
    _assert_fakes_runnable(bindir)


def _assert_fakes_runnable(bindir: Path) -> None:
    """A noexec mount makes os.access(X_OK) fail, so shutil.which
    silently SKIPS the fakes and the scenario rides the REAL operator
    binaries — the scripted leg stops being the scripted leg (Test-4:
    the container's /tmp tmpfs is noexec by Docker default, the fakes
    landed there via tempfile.mkdtemp, and the image's real frida ran
    and rejected the since-removed --no-pause flag). Refuse loudly."""
    dead = [n for n in FAKE_BINARIES
            if not os.access(bindir / n, os.X_OK)]
    if dead:
        raise SystemExit(
            f"[!] operator fakes not executable in {bindir} "
            f"({', '.join(dead)}) — the directory is on a noexec mount; "
            "the scripted leg would silently run the REAL frida/mitmdump. "
            "Run the criterion with its output (and thus the run scratch) "
            "on an exec-allowed filesystem.")


# ─── the stop-hook fake ─────────────────────────────────────────────────

def write_stop_hook(path: Path, mode: str) -> None:
    """block-once: blocks the first stop (persists a marker file),
    approves every later consultation. CC exit-code semantics."""
    path.write_text(f"""#!/bin/sh
MARKER={path.parent / '.stop-hook-marker'}
read -r PAYLOAD
if [ "{mode}" = "block-once" ] && [ ! -f "$MARKER" ]; then
    echo "$PAYLOAD" > "$MARKER"
    echo "the engagement must not stop before the findings summary names the lab scope" >&2
    exit 2
fi
echo '{{"decision": "approve"}}'
exit 0
""")
    path.chmod(0o755)


# ─── run machinery ──────────────────────────────────────────────────────

import hashlib  # noqa: E402


def make_scope(path: Path, eid: str) -> Path:
    from hypervisor.adapters.openai import frozen_json
    scope = {
        "version": 1, "engagement_id": eid, "mode": "strict",
        "targets": [{"target": "10.10.0.0/24", "type": "cidr",
                     "ports": [22, 80, 443]}],
        "excludes": [], "roe": {"poc_only": True},
    }
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"operator": "aegis-ops",
                              "signed_sha256": fp}
    p = path / "scope.json"
    p.write_text(json.dumps(scope, indent=2))
    return p


def run_one_fake(idx: int, name: str, script, cfg: dict,
                 outdir: Path) -> dict:
    from hypervisor.cli import main as cli_main
    scratch = outdir / f"run-{idx + 1}-{name}"
    if scratch.exists():
        shutil.rmtree(scratch)
    (scratch / "ws").mkdir(parents=True)
    scope = make_scope(scratch, f"ENG-EXIT-{idx + 1:02d}-{name.upper()}")

    ep = Endpoint(script)
    loop = start_endpoint(ep)

    env = dict(os.environ)
    env["AEGIS_SIDEQUERY"] = "0"
    env.pop("AEGIS_CONTEXT_WINDOW_TOKENS", None)
    if cfg.get("AEGIS_CONTEXT_WINDOW_TOKENS"):
        env["AEGIS_CONTEXT_WINDOW_TOKENS"] = cfg[
            "AEGIS_CONTEXT_WINDOW_TOKENS"]
    fakebin = None
    if cfg.get("_operator_fakes"):
        # NOT tempfile.mkdtemp(): the engagement container's compose
        # mounts /tmp as a noexec tmpfs (Docker default), a fake placed
        # there fails shutil.which's X_OK check, and the scenario
        # silently rides the REAL operator binaries (Test-4 finding).
        # The run scratch lives under OUTPUT — the container's evidence
        # volume bind-mount, which is exec-allowed — and the guard
        # inside install_operator_fakes refuses loudly if even that
        # is not. Keeping the fakes in the scratch also leaves them in
        # the --keep evidence for the analyst record.
        fakebin = scratch / "fake-bin"
        install_operator_fakes(fakebin)
        env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
    stop_hook_path = None
    if cfg.get("_stop_hook"):
        stop_hook_path = scratch / "stop-hook.sh"
        write_stop_hook(stop_hook_path, cfg["_stop_hook"])
        env["AEGIS_STOP_HOOK"] = str(stop_hook_path)

    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    t0 = time.monotonic()
    try:
        rc = cli_main([
            "--scope", str(scope),
            "--objective", f"exit-criterion run {idx + 1}: {name}",
            "--base-url", f"http://127.0.0.1:{ep.port}/v1",
            "--workspace", str(scratch / "ws"),
            "--no-debug",
        ])
    finally:
        os.environ.clear()
        os.environ.update(old)
        loop.call_soon_threadsafe(loop.stop)
    elapsed = time.monotonic() - t0
    return {"name": name, "rc": rc, "elapsed_s": round(elapsed, 1),
            "workspace": str(scratch / "ws"),
            "endpoint_calls": ep.calls}


def run_one_real(idx: int, outdir: Path, max_turns: int) -> dict:
    from hypervisor.cli import main as cli_main
    name = "real"
    scratch = outdir / f"run-{idx + 1}-{name}"
    if scratch.exists():
        shutil.rmtree(scratch)
    (scratch / "ws").mkdir(parents=True)
    scope = make_scope(scratch, f"ENG-EXIT-REAL-{idx + 1:02d}")
    objective = (
        f"Exit-criterion probe, run {idx + 1} of the series (engagement "
        f"ENG-EXIT-REAL-{idx + 1:02d}): run one check_port_listener "
        "probe on LOCAL port 80 (the tool verifies local listeners, "
        "e.g. a reverse-shell handler — it cannot probe remote hosts), "
        "then summarize the result and stop.")
    t0 = time.monotonic()
    rc = cli_main([
        "--scope", str(scope),
        "--objective", objective,
        "--workspace", str(scratch / "ws"),
        "--max-turns", str(max_turns),
        "--no-debug",
    ])
    elapsed = time.monotonic() - t0
    return {"name": f"real-{idx + 1}", "rc": rc,
            "elapsed_s": round(elapsed, 1),
            "workspace": str(scratch / "ws"), "endpoint_calls": -1}


# ─── verification ───────────────────────────────────────────────────────

def verify_one(run: dict) -> dict:
    """Replay + SLO audit on the run's journal; mutates the run dict
    with the verdicts."""
    from hypervisor.debug.slo import _load_events, slo_audit
    from hypervisor.persist.replay import JournalReplay
    ws = Path(run["workspace"])
    jdir = ws / ".aegis" / "journal"
    jfile = jdir / "journal.jsonl"
    run["journal_events"] = 0
    run["replay_ok"] = None
    run["replay_detail"] = "no journal"
    if jfile.exists():
        try:
            v = JournalReplay(
                jdir,
                ekd_dir=jdir / "ekd",
                compaction_dir=jdir / "compaction",
                objective_dir=jdir / "objective",
                messages_dir=jdir / "messages",
                sessions_dir=ws / ".aegis" / "sessions")
            report = v.full_report(verify_renders=True)
            run["journal_events"] = len(v.events)
            run["replay_ok"] = bool(report.get("ok"))
            rc = report.get("revision_chain") or {}
            rr = report.get("renders") or {}
            sl = report.get("session_linkage") or {}
            cb = report.get("crash_boundary") or {}
            run["replay_detail"] = (
                f"mutations={rc.get('mutations')} folds="
                f"{rc.get('compactions')} renders={rr.get('verified')}/"
                f"{rr.get('total_render_events')} issues="
                f"{len(report.get('integrity', {}).get('issues', []))}"
                f"+{len(rc.get('issues', []))}+"
                f"{len(rr.get('issues', []))} sessions={sl.get('ok')} "
                f"boundary={cb.get('ok')}")
        except Exception as exc:
            run["replay_ok"] = False
            run["replay_detail"] = f"replay raised: {type(exc).__name__}"
        try:
            events = _load_events(jdir)
            slo = slo_audit(events)
            run["slo_overall"] = slo["overall"]
            p = slo["profile"]
            run["slo_profile"] = {
                "turns": p["turns"],
                "folds": p["memory_plane"]["folds"],
                "tool_calls": p["tools"]["calls"],
                "watchdog": p["watchdog_events"],
                "tokens": p["tokens"]}
            fails = [v["slo"] for v in slo["slo_verdicts"]
                     if v["verdict"] == "fail"]
            run["slo_failures"] = fails
        except Exception as exc:
            run["slo_overall"] = None
            run["slo_failures"] = [f"audit raised {type(exc).__name__}"]
    return run


def _clear_dir_contents(path: Path) -> None:
    """Remove every child of path (dirs, files, symlinks), keep path."""
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _reset_output(path: Path) -> None:
    """Reset the criterion output directory (clean slate per invocation).

    On the workstation OUTPUT is a plain directory: rmtree + recreate.
    Inside the engagement container OUTPUT may be a bind-mounted
    evidence volume (compose: ./exit-criterion:/app/.exit-criterion);
    rmdir(2) on a mountpoint fails with EBUSY, so clear the CONTENTS
    instead and keep the mounted directory itself. Either way a fresh
    invocation starts empty — re-running a leg wipes the evidence of
    the previous one (unchanged workstation semantics).
    """
    if not path.exists():
        path.mkdir(parents=True)
        return
    if os.path.ismount(path):
        _clear_dir_contents(path)
        return
    try:
        shutil.rmtree(path)
    except OSError as exc:
        if exc.errno != errno.EBUSY or not path.is_dir():
            raise
        # Exotic mountpoint whose st_dev matches the parent (ismount
        # missed it): rmtree already cleared the contents and only the
        # mountpoint rmdir failed — the directory itself must survive.
        pass
    path.mkdir(parents=True, exist_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AEGIS 4.0 ten-fold exit criterion harness")
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--real", action="store_true",
                    help="run against the env-configured endpoint "
                         "(cisai-ultra) instead of the fake")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep", action="store_true",
                    help="keep the .exit-criterion workspaces")
    ap.add_argument("--max-turns", type=int, default=6,
                    help="turn ceiling per real run (default 6)")
    args = ap.parse_args()

    _reset_output(OUTPUT)

    runs = []
    if args.real:
        base = os.environ.get("AEGIS_OPENAI_BASE_URL", "").strip()
        if not base:
            print("--real requires AEGIS_OPENAI_BASE_URL", file=sys.stderr)
            return 2
        print(f"REAL exit-criterion run: {args.runs} engagements "
              f"against {base} (model "
              f"{os.environ.get('AEGIS_MODEL', '?')})", file=sys.stderr)
        for i in range(args.runs):
            run = run_one_real(i, OUTPUT, args.max_turns)
            runs.append(verify_one(run))
            print(f"  [{i + 1}/{args.runs}] {run['name']}: rc={run['rc']} "
                  f"replay={run['replay_ok']} slo={run['slo_overall']}",
                  file=sys.stderr)
    else:
        scenarios = _scenarios()[:args.runs]
        print(f"Scripted exit-criterion run: {len(scenarios)} engagements "
              f"(fake endpoint)", file=sys.stderr)
        for i, (name, script, cfg) in enumerate(scenarios):
            run = run_one_fake(i, name, script, cfg, OUTPUT)
            runs.append(verify_one(run))
            print(f"  [{i + 1}/{len(scenarios)}] {name}: rc={run['rc']} "
                  f"replay={run['replay_ok']} slo={run['slo_overall']}",
                  file=sys.stderr)

    # ── the consolidated verdict ───────────────────────────────────
    def _ok(r: dict) -> bool:
        return (r.get("rc") == 0
                and r.get("replay_ok") is True
                and r.get("slo_overall") == "pass")

    passed = sum(1 for r in runs if _ok(r))
    verdict = "PASS" if passed == len(runs) and runs else "FAIL"
    report = {
        "mode": "real" if args.real else "scripted",
        "runs": len(runs), "passed": passed, "verdict": verdict,
        "criterion": ("every run: rc==0 AND replay OVERALL OK AND SLO "
                      "OVERALL PASS (no-data allowed)"),
        "runs_detail": [{k: v for k, v in r.items()
                         if k != "workspace"} for r in runs],
    }
    out = OUTPUT / "exit-criterion.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print()
        print("=" * 64)
        print(f"EXIT CRITERION — {report['mode']} mode, "
              f"{passed}/{len(runs)} runs passed")
        for r in runs:
            mark = "+" if _ok(r) else "!"
            print(f"  [{mark}] {r['name']}: rc={r['rc']} "
                  f"replay={r['replay_ok']} ({r['replay_detail']}) "
                  f"slo={r['slo_overall']} "
                  f"fails={r.get('slo_failures', [])}")
        print(f"VERDICT: {verdict}  (detail: {out})")
    if not args.keep:
        for r in runs:
            if _ok(r):
                shutil.rmtree(r["workspace"], ignore_errors=True)
        for extra in OUTPUT.iterdir():
            if extra.is_dir() and extra.name.startswith("run-"):
                # sweep only the passing workspaces; failures stay for
                # the analyst
                name = extra.name
                matching = [r for r in runs
                            if f"run-" in name and r["name"] in name
                            and _ok(r)]
                if matching:
                    shutil.rmtree(extra, ignore_errors=True)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
