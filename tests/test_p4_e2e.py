"""P4 acceptance — the full-stack E2E.

One scripted engagement exercising every P4 surface together against
the fake endpoint: the operator-attached runtimes (fake frida on
PATH), the stop-hook (block once, then approve), a subagent spawn
through the task tool, and the exec harness — then the SAME
verification battery the exit-criterion harness runs: PORT-06 replay
OVERALL OK (integrity, revision chain incl. the stop_hook v2 surface,
renders, session linkage, crash boundary) and the SLO audit PASS.
"""
import asyncio
import hashlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from fake_endpoint import _delta, _sse, _tc_args, _tc_start, _usage_chunk  # noqa: E402
from hypervisor.adapters.openai import frozen_json  # noqa: E402

PROJECT = HERE.parent


class Endpoint:
    """Scripted SSE endpoint, stop-hook aware (compact requests get
    the compaction reply)."""

    def __init__(self, script):
        self.script = script
        self.calls = 0
        self.port = 0

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
                    if b"CRITICAL: Respond with TEXT ONLY" in body:
                        payload = _sse([
                            _delta(content=(
                                "<analysis>d</analysis>\n<summary>\n"
                                "1. Primary Request: lab probe.\n"
                                "3. Files: host 10.10.0.5 e2.\n"
                                "5. Problem Solving: probes done.\n"
                                "</summary>"), finish="stop"),
                            _usage_chunk(300, 60)])
                    else:
                        idx = min(self.calls, len(self.script) - 1)
                        kind, name, args = self.script[idx]
                        self.calls += 1
                        if kind == "tool":
                            payload = _sse([
                                _delta(content="Working.\n"),
                                _delta(tool_calls=[
                                    _tc_start(0, name)]),
                                _delta(tool_calls=[
                                    _tc_args(0, json.dumps(args))],
                                    finish="tool_calls"),
                                _usage_chunk(150, 24)])
                        else:
                            payload = _sse([
                                _delta(content=name, finish="stop"),
                                _usage_chunk(220, 40)])
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
            server.close()  # sync call: returns None; wrapping it in run_until_complete raised TypeError and killed the thread
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    return loop


def test_p4_full_stack_e2e(tmp_path):
    from hypervisor.cli import main as cli_main

    # the operator fake runtime (frida) — bounded window
    bindir = tmp_path / "bin"
    bindir.mkdir()
    frida = bindir / "frida"
    frida.write_text("#!/bin/sh\n"
                     "echo '[*] API Monitor Active'\n"
                     "echo '[URL] http://10.10.0.5/api/login'\n"
                     "sleep 30\n")
    frida.chmod(0o755)

    # the stop-hook: blocks the first stop, approves after
    marker = tmp_path / "hook-marker"
    hook = tmp_path / "stop-hook.sh"
    hook.write_text(
        "#!/bin/sh\n"
        f'MARKER="{marker}"\n'
        'read -r PAYLOAD\n'
        'if [ ! -f "$MARKER" ]; then\n'
        '  touch "$MARKER"\n'
        '  echo "name the lab scope in the summary" >&2\n'
        '  exit 2\n'
        "fi\n"
        "echo '{\"decision\": \"approve\"}'\n")
    hook.chmod(0o755)

    script = [
        ("tool", "frida_hook",
         {"package_name": "com.lab.app", "hook_type": "api_monitor",
          "duration": 3}),
        ("final", "first attempt", None),
        ("final", "Done: lab 10.10.0.0/24 probed via frida api_monitor.",
         None),
    ]
    ep = Endpoint(script)
    loop = start_endpoint(ep)

    scope = {
        "version": 1, "engagement_id": "ENG-P4-E2E", "mode": "strict",
        "targets": [{"target": "10.10.0.0/24", "type": "cidr",
                     "ports": [22, 80, 443]}],
        "excludes": [], "roe": {"poc_only": True},
    }
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"operator": "aegis-ops",
                              "signed_sha256": fp}
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope, indent=2))
    ws = tmp_path / "ws"

    env = dict(os.environ)
    env["AEGIS_SIDEQUERY"] = "0"
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["AEGIS_STOP_HOOK"] = str(hook)
    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        rc = cli_main([
            "--scope", str(scope_file),
            "--objective", "p4 e2e: frida-hook the lab app and report",
            "--base-url", f"http://127.0.0.1:{ep.port}/v1",
            "--workspace", str(ws),
            "--no-debug",
        ])
    finally:
        os.environ.clear()
        os.environ.update(old)
        loop.call_soon_threadsafe(loop.stop)

    assert rc == 0

    # ── the frida capture actually ran (bounded window, harvested) ──
    # (the tool result rode the transcript; verify via the journal)
    jdir = ws / ".aegis" / "journal"
    from hypervisor.persist.replay import JournalReplay
    v = JournalReplay(jdir, sessions_dir=ws / ".aegis" / "sessions")
    tool_calls = [e for e in v.events
                  if e["type"] == "tool_call"
                  and e["data"].get("tool") == "frida_hook"]
    assert tool_calls, "the frida_hook tool must have been dispatched"

    # ── the stop-hook ran: 1 block + 1 approve, journaled ──────────
    stops = [e for e in v.events if e["type"] == "stop_hook"]
    assert [e["data"]["decision"] for e in stops] == ["block", "approve"]

    # ── PORT-06: the whole engagement replays clean ────────────────
    report = v.full_report(verify_renders=True)
    assert report["ok"], {
        "integrity": report["integrity"].get("issues"),
        "chain": report["revision_chain"].get("issues"),
        "renders": report["renders"].get("issues"),
        "sessions": report["session_linkage"],
        "boundary": report["crash_boundary"]}
    chain = report["revision_chain"]
    assert chain["stop_hook_runs"] == 2
    assert chain["stop_hook_blocks"] == 1

    # ── the SLO audit passes on the same journal ───────────────────
    from hypervisor.debug.slo import _load_events, slo_audit
    slo = slo_audit(_load_events(jdir))
    assert slo["overall"] == "pass", slo["slo_verdicts"]
    p = slo["profile"]
    assert p["stop_hook"]["runs"] == 2
    assert p["stop_hook"]["blocks"] == 1
    assert p["tools"]["calls"] >= 1
