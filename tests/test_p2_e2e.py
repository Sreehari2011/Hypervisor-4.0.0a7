"""P2 E2E acceptance — the context engine + memory plane through the
REAL loop against a REAL local endpoint.

The P2 exit criterion: CLI bootstrap with the full P2 chain (EKD +
recovery + brief renderer + budget + compaction engine wired through
production deps) -> Tier-A extraction feeding the graph from live tool
results -> the <aegis-brief> Zone-T attachment in the actual prompt the
endpoint receives -> a mid-engagement fold fired by a tiny window with
the verbatim prompt family spoken to the model -> the autocompact
transition journaled -> the continuation message in the channel ->
end_turn with the graph persisted.

The fake endpoint here extends the P1 one with compact-call detection:
a call whose system prompt starts with the no-tools preamble gets a
drafted <analysis>/<summary> reply (exactly the contract the stripper
expects).
"""
import asyncio
import json
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from fake_endpoint import (  # noqa: E402
    FakeEndpoint, _delta, _sse, _tc_args, _tc_start, _usage_chunk,
)

from hypervisor.adapters.openai import frozen_json  # noqa: E402
from hypervisor.cli import main as cli_main  # noqa: E402

COMPACT_SYSTEM_MARK = "CRITICAL: Respond with TEXT ONLY"

# a heavy recon script: two fat tool outputs cross the tiny-window
# trigger mid-engagement (the fold must fire), then a light third
# probe, then final. The JWT stays inside a quoted phrase so the
# command-string target parser does not mistake it for a hostname.
_HEAVY1 = ("probe 10.10.0.5 http://10.10.0.5/app CVE-2021-44228 "
           "password=hunter2 ") * 150
_HEAVY2 = ("port-scan 10.10.0.6:22 open SQL injection in /search "
           "admin token present ") * 150
P2_SCRIPT = [
    ("tool", "run_command", {"command": f"echo \"{_HEAVY1}\""}),
    ("tool", "run_command", {"command": f"echo \"{_HEAVY2}\""}),
    ("tool", "run_command",
     {"command": "echo 'found http://10.10.0.7/api exposed'"}),
    ("final", "Engagement complete: two hosts up, one critical "
              "finding, one SQLi.", None),
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


class P2Endpoint(FakeEndpoint):
    """Extends the P1 fake: compact calls (no-tools preamble in the
    system message) get the drafted summary reply; main calls run the
    heavy P2 script."""

    def __init__(self):
        super().__init__()
        self.compact_calls = 0
        self.main_bodies = []
        self.compact_bodies = []

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
                    self.bodies.append(body)
                    if path not in ("/chat/completions",
                                    "/v1/chat/completions"):
                        writer.write(b"HTTP/1.1 404 Not Found\r\n"
                                     b"Content-Length: 0\r\n\r\n")
                        await writer.drain()
                        continue
                    if self._is_compact(body):
                        self.compact_calls += 1
                        self.compact_bodies.append(body)
                        payload = _sse([
                            _delta(content=COMPACT_REPLY, finish="stop"),
                            _usage_chunk(300, 60),
                        ])
                    else:
                        self.calls += 1
                        self.main_bodies.append(body)
                        idx = min(self.calls - 1, len(P2_SCRIPT) - 1)
                        kind, name, args = P2_SCRIPT[idx]
                        if kind == "tool":
                            payload = _sse([
                                _delta(content="Working.\n"),
                                _delta(tool_calls=[_tc_start(0, name)]),
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

    @staticmethod
    def _is_compact(body: bytes) -> bool:
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            return False
        for m in req.get("messages", []):
            if m.get("role") == "system" and \
                    str(m.get("content", "")).startswith(
                        COMPACT_SYSTEM_MARK):
                return True
        return False


@pytest.fixture()
def endpoint():
    ep = P2Endpoint()
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
            try:
                pending = [t for t in asyncio.all_tasks(loop)
                           if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(
                        *pending, return_exceptions=True))
                loop.run_until_complete(server.close())
            except Exception:
                pass
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    yield ep
    loop.call_soon_threadsafe(loop.stop())


@pytest.fixture()
def scope_file(tmp_path):
    scope = {
        "version": 1, "engagement_id": "ENG-P2E2E", "mode": "strict",
        "targets": [
            {"target": "10.10.0.0/24", "type": "cidr",
             "ports": [22, 80, 443]},
        ],
        "excludes": [],
        "roe": {"poc_only": True},
    }
    fp = __import__("hashlib").sha256(
        frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"operator": "aegis-ops",
                              "signed_sha256": fp}
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope, indent=2))
    return p


def read_journal(ws):
    jf = ws / ".aegis" / "journal" / "journal.jsonl"
    return [json.loads(l) for l in jf.read_text().splitlines()
            if l.strip()]


def test_p2_e2e_full_stack(endpoint, scope_file, tmp_path, monkeypatch):
    # tiny window: reserve 8000 floor -> trigger 2000; the heavy tool
    # outputs cross it mid-engagement and the fold must fire.
    # P3 note: the L3 side query is OFF here — the P2 acceptance
    # measures the fold path alone; the P3 E2E covers the selector.
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "6000")
    monkeypatch.setenv("AEGIS_SIDEQUERY", "0")
    ws = tmp_path / "ws"
    argv = ["--scope", str(scope_file),
            "--objective", "p2-e2e run the lab",
            "--base-url", f"http://127.0.0.1:{endpoint.port}/v1",
            "--workspace", str(ws),
            "--no-debug"]
    rc = cli_main(argv)
    assert rc == 0

    evs = read_journal(ws)
    types = [e["type"] for e in evs]

    # ── the memory plane came up: objective + EKD mutations ──────────
    assert "objective" in types
    muts = [e for e in evs if e["type"] == "ekd_mutation"]
    assert muts, "no EKD mutations journaled"
    assert any(m["data"]["extractor"] == "tier_a" for m in muts)

    # the graph: Tier-A extraction fed it from the LIVE tool results
    ekd_state = ws / "ekd.json"
    assert ekd_state.exists()
    from hypervisor.memory.ekd import EngagementDAG
    ekd = EngagementDAG.from_json(ekd_state.read_text())
    assert ekd.by_key("ip:10.10.0.5") is not None
    assert ekd.by_key("ip:10.10.0.6") is not None
    assert ekd.by_key("port:10.10.0.6:22/tcp") is not None
    assert ekd.by_key("url:http://10.10.0.5/app") is not None
    assert ekd.by_key("cve:CVE-2021-44228") is not None
    assert ekd.by_key("url:http://10.10.0.7/api") is not None
    findings = ekd.nodes_of_type("finding")
    assert any("SQL injection" in f.title for f in findings)
    # the capped renders advertised buffer files -> artifact nodes
    artifacts = ekd.nodes_of_type("artifact")
    assert artifacts and artifacts[0].attrs.get("kind") == "buffer"

    # ── the fold fired: compaction event + transition + continuation ─
    comps = [e for e in evs if e["type"] == "compaction"]
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert comps, "no compaction event"
    c = comps[-1]["data"]
    assert c["tier"] == 3 and c["direction"] in ("up_to", "from")
    assert c["messages_dropped"] > 0 and c["dropped_sig_shas"]
    assert "autocompact" in trans
    assert trans[-1] == "end_turn"

    # the compact calls actually spoke the verbatim family to the model
    assert endpoint.compact_calls >= 1
    compact_req = json.loads(endpoint.compact_bodies[0])
    sys_msg = next(m for m in compact_req["messages"]
                   if m["role"] == "system")
    assert sys_msg["content"].startswith(COMPACT_SYSTEM_MARK)
    assert "ID PRESERVATION (binding)" in sys_msg["content"]
    assert compact_req.get("tools") is None      # no-tools call

    # ── the brief rode Zone T in the real prompts ────────────────────
    assert endpoint.main_bodies
    brief_prompts = []
    for b in endpoint.main_bodies:
        req = json.loads(b)
        for m in req["messages"]:
            c = m.get("content")
            if m.get("role") == "user" and isinstance(c, str) \
                    and c.startswith("<aegis-brief>"):
                brief_prompts.append(c)
    assert brief_prompts, "no brief attachment in any main prompt"
    assert "p2-e2e run the lab" in brief_prompts[0]   # objective verbatim
    assert "10.10.0.5" in brief_prompts[-1]           # learned surface
    # renders journaled (J2) with window hashes
    renders = [e for e in evs if e["type"] == "brief_render"]
    assert renders and renders[-1]["data"].get("window_hash")

    # ── the continuation message landed in the channel ──────────────
    from hypervisor.persist.sessions import SessionStore
    sessions = list((ws / ".aegis" / "sessions").glob("*.jsonl"))
    assert len(sessions) == 1
    recs = SessionStore.resume(ws / ".aegis" / "sessions",
                               sessions[0].stem).read_all()
    summaries = [r for r in recs if r["type"] == "summary"]
    assert summaries
    assert "Summary:" in summaries[-1]["text"]
    assert summaries[-1].get("logicalParentUuid")

    # fold audit: the dropped slice's hard facts are all graph nodes
    # (already asserted above by key presence — the MD-2 guarantee)


def test_p2_e2e_no_fold_large_window(endpoint, scope_file, tmp_path,
                                     monkeypatch):
    """Same engagement, healthy window: no fold, no compact calls, the
    brief still rides Zone T (the engine is dormant, not absent)."""
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "131072")
    monkeypatch.setenv("AEGIS_SIDEQUERY", "0")
    ws = tmp_path / "ws-big"
    argv = ["--scope", str(scope_file),
            "--objective", "p2-e2e run the lab",
            "--base-url", f"http://127.0.0.1:{endpoint.port}/v1",
            "--workspace", str(ws),
            "--no-debug"]
    rc = cli_main(argv)
    assert rc == 0
    evs = read_journal(ws)
    assert not [e for e in evs if e["type"] == "compaction"]
    assert endpoint.compact_calls == 0
    assert [e for e in evs if e["type"] == "brief_render"]
    assert [e for e in evs if e["type"] == "ekd_mutation"]
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert "autocompact" not in trans
    assert trans[-1] == "end_turn"
