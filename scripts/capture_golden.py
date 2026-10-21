#!/usr/bin/env python3
"""PORT-06 golden trajectory capture.

Runs scripted engagements against the local fake endpoint (the P2 E2E
machinery, sidequery off) and copies the journal + sidecar dirs into
tests/golden/<name>/ as replay fixtures. The port card's acceptance:
"capture 2-3 golden trajectories, run the pass, zero false positives."

Trajectories:
  golden-fold    tiny window, heavy tool outputs -> a mid-engagement
                 fold (compaction event + continuation + stubs)
  golden-quiet   healthy window, no fold (render events only)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
import threading
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))

from fake_endpoint import _delta, _sse, _tc_args, _tc_start, _usage_chunk  # noqa: E402
from hypervisor.adapters.openai import frozen_json  # noqa: E402
from hypervisor.cli import main as cli_main  # noqa: E402

COMPACT_SYSTEM_MARK = "CRITICAL: Respond with TEXT ONLY"

HEAVY1 = ("probe 10.10.0.5 http://10.10.0.5/app CVE-2021-44228 "
          "password=hunter2 ") * 150
HEAVY2 = ("port-scan 10.10.0.6:22 open SQL injection in /search "
          "admin token present ") * 150

FOLD_SCRIPT = [
    ("tool", "run_command", {"command": f"echo \"{_HEAVY1()}"
                              if False else f"echo \"{HEAVY1}\""}),
    ("tool", "run_command", {"command": f"echo \"{HEAVY2}\""}),
    ("tool", "run_command",
     {"command": "echo 'found http://10.10.0.7/api exposed'"}),
    ("final", "Engagement complete: two hosts up, one critical "
              "finding, one SQLi.", None),
]
QUIET_SCRIPT = [
    ("tool", "run_command", {"command": "echo probe 10.10.0.5"}),
    ("final", "Quiet run: one host probed, nothing else.", None),
]
COMPACT_REPLY = (
    "<analysis>draft thinking</analysis>\n"
    "<summary>\n"
    "1. Primary Request and Intent: probe the lab segment.\n"
    "3. Files and Code Sections: hosts 10.10.0.5 e2, 10.10.0.6 e3.\n"
    "5. Problem Solving: SQL injection on /search F1; log4shell "
    "reference noted.\n"
    "</summary>"
)


def _HEAVY1_placeholder():  # pragma: no cover - display guard
    return HEAVY1


class Endpoint:
    def __init__(self, script):
        self.script = script
        self.calls = 0
        self.compact_calls = 0
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
                    is_compact = False
                    try:
                        req = json.loads(body)
                        for m in req.get("messages", []):
                            if m.get("role") == "system" and \
                                    str(m.get("content", "")).startswith(
                                        COMPACT_SYSTEM_MARK):
                                is_compact = True
                    except json.JSONDecodeError:
                        pass
                    if is_compact:
                        self.compact_calls += 1
                        payload = _sse([
                            _delta(content=COMPACT_REPLY, finish="stop"),
                            _usage_chunk(300, 60),
                        ])
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
                                _usage_chunk(150, 24),
                            ])
                        else:
                            payload = _sse([
                                _delta(content=name, finish="stop"),
                                _usage_chunk(220, 40),
                            ])
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
            loop.run_until_complete(server.close())
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    return loop


def make_scope(path: Path, eid: str) -> Path:
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


def capture(name: str, script, window: str) -> None:
    scratch = PROJECT / "tests" / "golden" / f".scratch-{name}"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    scope = make_scope(scratch, f"ENG-{name.upper()}")
    ws = scratch / "ws"
    ep = Endpoint(script)
    loop = start_endpoint(ep)
    env = dict(os.environ)
    env["AEGIS_CONTEXT_WINDOW_TOKENS"] = window
    env["AEGIS_SIDEQUERY"] = "0"
    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        rc = cli_main([
            "--scope", str(scope),
            "--objective", f"{name} golden run the lab",
            "--base-url", f"http://127.0.0.1:{ep.port}/v1",
            "--workspace", str(ws),
            "--no-debug",
        ])
    finally:
        os.environ.clear()
        os.environ.update(old)
        loop.call_soon_threadsafe(loop.stop)
    out = PROJECT / "tests" / "golden" / name
    if out.exists():
        shutil.rmtree(out)
    (out).mkdir(parents=True)
    jsrc = ws / ".aegis" / "journal"
    for item in ("journal.jsonl", "ekd", "compaction", "objective",
                 "messages", "prompts", "briefs"):
        src = jsrc / item
        if src.exists():
            if src.is_dir():
                shutil.copytree(src, out / item)
            else:
                shutil.copy2(src, out / item)
    # the EKD state (workspace root) — repair tests need it
    if (ws / "ekd.json").exists():
        shutil.copy2(ws / "ekd.json", out / "ekd.json")
    meta = {
        "name": name, "rc": rc, "window": window,
        "endpoint_calls": ep.calls,
        "compact_calls": ep.compact_calls,
    }
    (out / "capture.json").write_text(json.dumps(meta, indent=2))
    shutil.rmtree(scratch)
    print(f"[{name}] rc={rc} calls={ep.calls} "
          f"compact={ep.compact_calls} -> {out}")


def main() -> int:
    capture("golden-fold", FOLD_SCRIPT, "6000")
    capture("golden-quiet", QUIET_SCRIPT, "131072")
    return 0


if __name__ == "__main__":
    sys.exit(main())
