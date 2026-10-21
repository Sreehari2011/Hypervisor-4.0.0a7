"""P3 E2E acceptance — the Task tool, the L3 side query and the replay
pass through the REAL loop against a REAL local endpoint.

The exit criteria this file proves:
  * the main loop spawns a Task subagent mid-engagement; the child runs
    THE loop at depth+1 with its own registry, journals spawn/report
    (write-ahead preserved), writes a sidechain transcript, and its
    report lands as the task tool's result;
  * the child's tool results feed Tier-A extraction into the SHARED
    EKD (the world model is one);
  * the L3 side query fires on the revision bump the child caused,
    expands the selected entity into Zone T, and the <aegis-drilldown>
    attachment rides the NEXT main prompt (byte-verified by the
    endpoint);
  * a VAPT web tool (retrieve_url_content) runs against the endpoint's
    own HTTP surface, scope-gated on 127.0.0.1;
  * the engagement journal replays CLEAN through the PORT-06 pass
    family: integrity, revision chain, byte-identical brief re-renders,
    Zone W window hashes, session linkage with the sidechain.
"""
import asyncio
import hashlib
import json
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from fake_endpoint import _delta, _sse, _tc_args, _tc_start, _usage_chunk  # noqa: E402

from hypervisor.adapters.openai import frozen_json  # noqa: E402
from hypervisor.cli import main as cli_main  # noqa: E402

COMPACT_SYSTEM_MARK = "CRITICAL: Respond with TEXT ONLY"
SELECTOR_MARK = "Current turn:"

CHILD_TASK = ("p3-agent map the 10.10.0.0/24 segment: probe the web "
              "host and report entities found")

CHILD_SCRIPT = [
    ("tool", "run_command",
     {"command": "echo recon-child found host 10.10.0.9 alive with "
                 "http://10.10.0.9/app"}),
    ("final", "Recon subagent complete: host 10.10.0.9 up, endpoint "
              "/app exposed. Findings recorded with ids.", None),
]


class P3Endpoint:
    """Dispatches on the request shape:
      * selector calls (user msg starts with 'Current turn:') -> a
        scripted id list (the expansion target);
      * compact calls (system no-tools preamble) -> the drafted
        summary (not expected here, tolerated);
      * child calls (task text keys 'p3-agent') -> the child script;
      * main calls -> the main script (task spawn, web fetch, final).
    Records every main-call body for Zone T assertions."""

    def __init__(self):
        self.port = 0
        self.calls = 0
        self.compact_calls = 0
        self.selector_calls = 0
        self.selector_bodies = []
        self.child_calls = 0
        self.main_bodies = []
        self.http_gets = []

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _parse(body: bytes):
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            return None
        msgs = req.get("messages", [])
        last_user = ""
        system_head = ""
        for m in msgs:
            if m.get("role") == "system" and not system_head:
                system_head = str(m.get("content", ""))[:60]
            if m.get("role") == "user":
                c = m.get("content")
                last_user = c if isinstance(c, str) else str(c)
        return {"messages": msgs, "last_user": last_user,
                "system_head": system_head}

    # ------------------------------------------------------------ server

    async def handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if line.startswith(b"GET "):
                    self.http_gets.append(line.decode().strip())
                    body = (b"p3 target page\nServer: Apache/2.4.49\n")
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Server: Apache/2.4.49\r\n"
                        b"Content-Length: " +
                        str(len(body)).encode() + b"\r\n\r\n" + body)
                    await writer.drain()
                    continue
                if not line.startswith(b"POST "):
                    continue
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
                req = self._parse(body)
                if req is None:
                    payload = _sse([_delta(content="?", finish="stop")])
                elif req["last_user"].startswith(SELECTOR_MARK):
                    # NOTE: checked BEFORE the compact mark — the
                    # selector's system prompt shares the no-tools
                    # preamble with the compaction prompt; the user
                    # message shape is the discriminator
                    self.selector_calls += 1
                    self.selector_bodies.append(body)
                    payload = _sse([
                        _delta(content="e1\n", finish="stop"),
                        _usage_chunk(50, 2)])
                elif req["system_head"].startswith(COMPACT_SYSTEM_MARK):
                    self.compact_calls += 1
                    payload = _sse([_delta(
                        content="<analysis>x</analysis>\n<summary>\n"
                                "1. Primary Request: probe.\n"
                                "</summary>", finish="stop"),
                        _usage_chunk(100, 20)])
                elif "p3-agent" in req["last_user"]:
                    self.child_calls += 1
                    idx = min(self.child_calls - 1,
                              len(CHILD_SCRIPT) - 1)
                    kind, name, args = CHILD_SCRIPT[idx]
                    if kind == "tool":
                        payload = _sse([
                            _delta(content="Probing.\n"),
                            _delta(tool_calls=[_tc_start(0, name)]),
                            _delta(tool_calls=[
                                _tc_args(0, json.dumps(args))],
                                finish="tool_calls"),
                            _usage_chunk(120, 20)])
                    else:
                        payload = _sse([
                            _delta(content=name, finish="stop"),
                            _usage_chunk(200, 60)])
                else:
                    self.calls += 1
                    self.main_bodies.append(body)
                    if self.calls == 1:
                        args = {"agent": "recon", "task": CHILD_TASK}
                        payload = _sse([
                            _delta(content="Delegating recon.\n"),
                            _delta(tool_calls=[
                                _tc_start(0, "task")]),
                            _delta(tool_calls=[
                                _tc_args(0, json.dumps(args))],
                                finish="tool_calls"),
                            _usage_chunk(300, 40)])
                    elif self.calls == 2:
                        args = {"url":
                                f"http://127.0.0.1:{self.port}/"}
                        payload = _sse([
                            _delta(content="Fetching the page.\n"),
                            _delta(tool_calls=[
                                _tc_start(0, "retrieve_url_content")]),
                            _delta(tool_calls=[
                                _tc_args(0, json.dumps(args))],
                                finish="tool_calls"),
                            _usage_chunk(400, 30)])
                    else:
                        payload = _sse([
                            _delta(content=(
                                "Engagement complete: recon subagent "
                                "reported 10.10.0.9 with /app; the "
                                "target page fetched; one drilldown "
                                "expanded."),
                                finish="stop"),
                            _usage_chunk(500, 80)])
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


@pytest.fixture()
def endpoint():
    ep = P3Endpoint()
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
                loop.run_until_complete(server.close())
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    yield ep
    loop.call_soon_threadsafe(loop.stop())


@pytest.fixture()
def scope_file(tmp_path):
    scope = {
        "version": 1, "engagement_id": "ENG-P3E2E", "mode": "strict",
        "targets": [
            {"target": "10.10.0.0/24", "type": "cidr",
             "ports": [22, 80, 443]},
            {"target": "127.0.0.1"},
        ],
        "excludes": [],
        "roe": {"poc_only": True},
    }
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"operator": "aegis-ops",
                              "signed_sha256": fp}
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope, indent=2))
    return p


def read_journal(ws):
    jf = ws / ".aegis" / "journal" / "journal.jsonl"
    return [json.loads(l) for l in jf.read_text().splitlines()
            if l.strip()]


def test_p3_e2e_full_stack(endpoint, scope_file, tmp_path):
    ws = tmp_path / "ws"
    argv = ["--scope", str(scope_file),
            "--objective", "p3-e2e orchestrate the lab",
            "--base-url", f"http://127.0.0.1:{endpoint.port}/v1",
            "--workspace", str(ws),
            "--no-debug"]
    rc = cli_main(argv)
    assert rc == 0

    evs = read_journal(ws)
    types = [e["type"] for e in evs]

    # ── the Task spawn chain ─────────────────────────────────────────
    spawns = [e for e in evs if e["type"] == "subagent_spawn"]
    reports = [e for e in evs if e["type"] == "subagent_report"]
    assert len(spawns) == 1 and len(reports) == 1
    sp, rp = spawns[0], reports[0]
    assert sp["data"]["mode"] == "contract"
    assert sp["data"]["phase"] == "recon"
    assert sp["data"]["contract_hash"]
    assert sp["data"]["ceiling"] == 8
    assert sp["seq"] < rp["seq"]                      # write-ahead
    assert rp["data"]["spawn_seq"] == sp["seq"]
    assert rp["data"]["partial"] is False
    assert rp["data"]["turns_used"] == 2
    assert rp["data"]["report_sha"]

    # the report landed in the main channel (message event linkage)
    msg = [e for e in evs if e["type"] == "message"
           and e["data"].get("source") == "subagent:recon"]
    assert msg, "no linked report message event"
    import hashlib as _h
    body = msg[0]["data"]["sig"].split("|", 2)[-1]
    nl = body.find("\n")
    report_text = body[nl + 1:] if nl >= 0 else body
    assert (_h.sha256(report_text.encode()).hexdigest()[:16]
            == rp["data"]["report_sha"])

    # the task tool result carried the report
    tr = [e for e in evs if e["type"] == "tool_result"
          and e["data"].get("tool") == "task"]
    assert tr and not tr[0]["data"]["is_error"]

    # ── the sidechain transcript ─────────────────────────────────────
    sdir = ws / ".aegis" / "sessions"
    metas = list(sdir.glob("*.meta.json"))
    assert metas
    meta = json.loads(metas[0].read_text())
    assert meta["label"] == "agent:recon"
    assert meta["parent_session"]
    chain_f = sdir / f"{metas[0].name[:-len('.meta.json')]}.jsonl"
    assert chain_f.exists()
    kinds = [json.loads(l)["type"]
             for l in chain_f.read_text().splitlines() if l.strip()]
    assert "user" in kinds and "assistant" in kinds

    # ── the child fed the SHARED EKD (one world model) ───────────────
    muts = [e for e in evs if e["type"] == "ekd_mutation"]
    assert any("10.10.0.9" in json.dumps(m["data"])
               for m in muts), "child extraction missed the host"

    # ── the child's messages are channel-marked (per-channel sim) ────
    child_msgs = [e for e in evs if e["type"] == "message"
                  and str(e["data"].get("source", ""))
                  .startswith("subagent:recon:")]
    assert child_msgs, "child channel messages unmarked"

    # ── the L3 side query ────────────────────────────────────────────
    sq = [e for e in evs if e["type"] == "side_query"]
    assert sq, "no side_query events"
    ran = [e for e in sq if e["data"].get("expansions")]
    assert ran, "the selector never expanded"
    assert ran[0]["data"]["selected"]
    assert ran[0]["data"]["expansions"][0]["sha"]
    # the skip path journaled too (turn 1: no candidates yet)
    skipped = [e for e in sq if e["data"].get("skipped")]
    assert skipped

    # ── the drilldown rode Zone T in a REAL main prompt ─────────────
    drill = [b for b in endpoint.main_bodies
             if b"<aegis-drilldown>" in b]
    assert drill, "no drilldown attachment in any main prompt"
    # and the brief was in every main prompt (Zone T contract)
    assert all(b"<aegis-brief>" in b for b in endpoint.main_bodies)

    # ── the selector saw the index (not the raw graph) ──────────────
    assert endpoint.selector_calls >= 1
    sel_req = json.loads(endpoint.selector_bodies[0])
    sel_user = [m for m in sel_req["messages"]
                if m["role"] == "user"][0]["content"]
    assert sel_user.startswith("Current turn:")
    assert "Engagement entry index:" in sel_user
    assert "Already surfaced (do not re-pick):" in sel_user

    # ── the VAPT web tool ran scope-gated ────────────────────────────
    vr = [e for e in evs if e["type"] == "tool_result"
          and e["data"].get("tool") == "retrieve_url_content"]
    assert vr and not vr[0]["data"]["is_error"]
    assert endpoint.http_gets

    # ── PORT-06: the journal replays clean ──────────────────────────
    from hypervisor.persist.replay import JournalReplay
    rep = JournalReplay(ws / ".aegis" / "journal").full_report()
    assert rep["integrity"]["ok"], rep["integrity"]
    chain = rep["revision_chain"]
    assert chain["ok"], chain["issues"][:3]
    assert chain["subagent_spawns"] == 1
    assert chain["subagent_reports_linked"] == 1
    renders = rep["renders"]
    assert renders["ok"], renders["issues"][:3]
    assert renders["verified"] == renders["total_render_events"] >= 3
    w = renders["window_checks"]
    assert w["verified"] >= 2, w
    sess = rep["session_linkage"]
    assert sess["store_present"] is True
    assert sess["sidechains_linked"] == 1
    assert sess["ok"], sess["issues"]
    assert rep["crash_boundary"]["ok"]
    assert rep["ok"]
