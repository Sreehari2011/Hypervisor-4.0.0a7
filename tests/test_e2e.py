"""P1 E2E acceptance — the whole plane against a REAL local endpoint.

The P1 exit criterion (worklog Task 8 'next'): CLI bootstrap -> debug-kit
install -> journal boot -> signed scope load -> registry freeze ->
SessionStore -> production deps -> guard-wrapped adapter -> THE loop ->
dispatcher -> real tools, with the OpenAI wire protocol spoken over a
real socket by tests/fake_endpoint.py. Three scenarios:

  happy  — in-scope tool executes; loop completes end_turn
  deny   — out-of-scope tool denied by the gate; denial flows back as a
           tool_result; the model sees it and completes (scoped
           full-auto end to end)
  multi  — a batch of three tools (two serial-lane writes + ls) in one
           turn; workspace files land with 0600 permissions
"""
import asyncio
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from fake_endpoint import FakeEndpoint  # noqa: E402

from hypervisor.adapters.openai import frozen_json  # noqa: E402
from hypervisor.cli import main as cli_main  # noqa: E402


@pytest.fixture()
def endpoint():
    """Serve the fake OpenAI-compatible endpoint on a real socket."""
    ep = FakeEndpoint()
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
                pass            # teardown must never fail the test
            loop.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    yield ep
    loop.call_soon_threadsafe(loop.stop)


@pytest.fixture()
def scope_file(tmp_path):
    scope = {
        "version": 1, "engagement_id": "ENG-E2E", "mode": "strict",
        "targets": [
            {"target": "10.10.0.0/24", "type": "cidr",
             "ports": [22, 80, 443]},
            {"target": "*.demo.target", "type": "wildcard"},
        ],
        "excludes": ["10.10.0.1"],
        "roe": {"poc_only": True},
    }
    import hashlib
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"operator": "aegis-ops",
                              "signed_sha256": fp}
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope, indent=2))
    return p


def run_cli(endpoint, scope_file, tmp_path, objective, ws_name):
    ws = tmp_path / ws_name
    argv = ["--scope", str(scope_file),
            "--objective", objective,
            "--base-url", f"http://127.0.0.1:{endpoint.port}/v1",
            "--workspace", str(ws),
            "--no-debug"]
    rc = cli_main(argv)
    return rc, ws


def read_journal(ws):
    jf = ws / ".aegis" / "journal" / "journal.jsonl"
    return [json.loads(l) for l in jf.read_text().splitlines()
            if l.strip()]


def test_e2e_happy_path(endpoint, scope_file, tmp_path):
    rc, ws = run_cli(endpoint, scope_file, tmp_path, "e2e-happy", "ws")
    assert rc == 0
    # boot + scope events
    evs = read_journal(ws)
    boot = [e for e in evs if e["type"] == "boot"][0]
    assert boot["data"]["scope_ref"].startswith("sha256:")
    assert boot["data"]["mode"] == "strict"
    # in-scope decision allowed
    perm = [e for e in evs if e["type"] == "permission_decision"]
    assert perm and all(d["data"]["allowed"] for d in perm)
    # loop completed with the transition table present
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert trans[0] == "init" and "next_turn" in trans
    assert trans[-1] == "end_turn"
    # session chain intact
    from hypervisor.persist.sessions import SessionStore
    sessions = list((ws / ".aegis" / "sessions").glob("*.jsonl"))
    assert len(sessions) == 1
    rep = SessionStore.resume(ws / ".aegis" / "sessions",
                              sessions[0].stem).verify_chain()
    assert rep["records"] >= 5 and rep["orphans"] == []


def test_e2e_out_of_scope_denial(endpoint, scope_file, tmp_path):
    rc, ws = run_cli(endpoint, scope_file, tmp_path, "e2e-deny", "ws2")
    assert rc == 0
    evs = read_journal(ws)
    # the denial audit: permission_decision (allow AND deny are both
    # journaled); denied calls do not reach tool execution, so the
    # permission event IS the tool-side audit record
    perm = [e for e in evs if e["type"] == "permission_decision"]
    denied = [d for d in perm if not d["data"]["allowed"]]
    assert denied and denied[0]["data"]["rule"] == "scope:out-of-scope"
    assert denied[0]["data"]["scope_ref"].startswith("sha256:")
    # the loop still completed: denial flowed back as a tool_result
    # (session record), the model acknowledged it, end_turn
    from hypervisor.persist.sessions import SessionStore
    sessions = list((ws / ".aegis" / "sessions").glob("*.jsonl"))
    recs = SessionStore.resume(ws / ".aegis" / "sessions",
                               sessions[0].stem).read_all()
    tr = [r for r in recs if r["type"] == "tool_result"]
    assert tr and "PERMISSION DENIED" in \
        tr[0]["message"]["content"][0]["content"]
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert trans[-1] == "end_turn"


def test_e2e_multi_tool_batch(endpoint, scope_file, tmp_path):
    rc, ws = run_cli(endpoint, scope_file, tmp_path, "e2e-multi",
                     "ws3")
    assert rc == 0
    evs = read_journal(ws)
    calls = [e for e in evs if e["type"] == "tool_call"]
    assert len(calls) == 3
    # files written with 0600 inside the workspace
    a = ws / "e2e" / "a.txt"
    b = ws / "e2e" / "b.txt"
    assert a.read_text() == "alpha\n"
    assert b.read_text() == "beta\n"
    assert stat.S_IMODE(os.stat(a).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(b).st_mode) == 0o600
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert trans[-1] == "end_turn"


def test_e2e_check_scope_cli(scope_file, capsys):
    from hypervisor.cli import main as m
    rc = m(["--check-scope", str(scope_file)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "scope_ref: sha256:" in out
    assert "mode=strict" in out
