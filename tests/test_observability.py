"""P4 acceptance — observability wiring regression.

The first real-mode acceptance run on the engagement host (CISAI-0288,
cisai-ultra) exposed that the SLO audit's model plane read ZERO model
calls and ZERO tokens from production journals although every run had
plainly called the model. Root causes, all fixed and pinned here:

1. cli.py built the shared LLMGuard WITHOUT the engagement journal —
   every defense event (llm_call / llm_call_end / llm_retry /
   llm_abandon / llm_breaker) was silently dropped, leaving the SLO
   model plane with no data at all.
2. The query loop never journaled turn_end (a registered event type,
   "one loop invocation finished") — the SLO token plane's designed
   source. The cumulative counters lived only in the [completed] line.
3. The guard journaled llm_call ONCE per call_stream with no attempt
   number while llm_call_end is per-attempt (1-based) — the SLO
   pairing key (purpose, turn, attempt) could never match. The journal
   contract ("attempt started") is per attempt; the guard now emits one
   llm_call per attempt carrying the matching attempt number.
"""
import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from hypervisor.adapters.openai import Chunk, ModelReply, frozen_json
from hypervisor.debug.slo import _load_events, slo_audit
from hypervisor.guard import GuardBounds, LLMGuard
from hypervisor.permissions import (PermissionEngine, ScopeFile,
                                    ScopeManager)
from hypervisor.persist.journal import Journal
from hypervisor.persist.sessions import SessionStore
from hypervisor.query import ProductionDeps, QueryParams, query_loop
from hypervisor.tools.base import ToolContext
from hypervisor.tools.core import build_registry


# ─── shared plane ──────────────────────────────────────────────────────

@pytest.fixture()
def plane(tmp_path):
    scope = {
        "version": 1, "engagement_id": "OBS-TEST", "mode": "strict",
        "targets": [{"target": "10.0.0.0/24"}],
        "roe": {"poc_only": True},
    }
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"signed_sha256": fp}
    d = tmp_path / "scope"
    d.mkdir()
    (d / "scope.json").write_text(json.dumps(scope))
    sm = ScopeManager(ScopeFile.load(d / "scope.json"))
    ws = tmp_path / "ws"
    ws.mkdir()
    j = Journal(tmp_path / "journal")
    reg = build_registry()
    session = SessionStore(ws / ".aegis" / "sessions")
    ctx = ToolContext(workspace=str(ws), registry=reg,
                      permissions=PermissionEngine(sm, journal=j),
                      journal=j, extra={"session": session})
    return ctx, reg, j, session, ws, tmp_path


def reply(text="", tools=(), finish="stop", usage=None):
    blocks = ([{"type": "text", "text": text}] if text else []) + \
        list(tools)
    r = ModelReply(message={"role": "assistant", "content": blocks},
                   tool_uses=list(tools), text=text, usage=usage or {},
                   finish_reason=finish, model="fake")
    r.text_parts = tuple([text] if text else ())
    return r


def tu(name, args, i):
    return {"type": "tool_use", "id": f"call_{i}", "name": name,
            "input": args}


class FakeAdapter:
    """Minimal OpenAICompatClient stand-in: scripted replies with
    usage, driven through the REAL guard via ProductionDeps — the
    exact wiring cli.py installs (guard carries the journal)."""

    model = "fake-model"

    def __init__(self, replies):
        self.replies = list(replies)

    async def stream_chat(self, *, messages=None, tools=None,
                          max_tokens=None):
        r = self.replies.pop(0)
        for t in getattr(r, "text_parts", ()):
            yield Chunk(kind="text", text=t)
        yield Chunk(kind="reply", reply=r)


# ─── 1. the guard journals, per attempt, with pairing ─────────────────

def test_guard_journals_attempt_pairing(plane):
    _, _, j, _, _, _ = plane
    guard = LLMGuard(journal=j)

    async def factory():
        yield Chunk(kind="reply", reply=reply(
            "ok", usage={"prompt_tokens": 7, "completion_tokens": 3}))

    async def drive():
        out = []
        async for c in guard.call_stream(factory, purpose="main",
                                         model="fake-model", turn=1):
            out.append(c)
        return out

    chunks = asyncio.run(drive())
    assert chunks and chunks[-1].kind == "reply"
    events = _load_events(plane[5] / "journal")
    calls = [e for e in events if e["type"] == "llm_call"]
    ends = [e for e in events if e["type"] == "llm_call_end"]
    assert len(calls) == 1 and len(ends) == 1
    # the pairing contract: same attempt number on both sides
    assert calls[0]["data"]["attempt"] == ends[0]["data"]["attempt"]
    assert ends[0]["data"]["outcome"] == "ok"
    assert ends[0]["data"]["usage"]["prompt_tokens"] == 7


def test_guard_journals_one_llm_call_per_attempt(plane):
    """A first failed attempt + successful retry journals TWO llm_call
    events (one per attempt), each pairing with its llm_call_end."""
    _, _, j, _, _, _ = plane
    guard = LLMGuard(bounds=GuardBounds(
        total_timeout_s=2.0, idle_timeout_s=1.0, max_attempts=2,
        backoff_s=0.01, cancel_grace_s=0.2, breaker_threshold=3),
        journal=j)

    state = {"n": 0}

    async def factory():
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("connection reset")
        yield Chunk(kind="reply", reply=reply("recovered"))

    async def drive():
        out = []
        async for c in guard.call_stream(factory, purpose="main",
                                         model="fake-model", turn=1):
            out.append(c)
        return out

    chunks = asyncio.run(drive())
    assert chunks and chunks[-1].kind == "reply"
    events = _load_events(plane[5] / "journal")
    calls = [e["data"]["attempt"] for e in events
             if e["type"] == "llm_call"]
    ends = [(e["data"]["attempt"], e["data"]["outcome"])
            for e in events if e["type"] == "llm_call_end"]
    assert calls == [1, 2]                      # per attempt
    assert (1, "error") in ends and (2, "ok") in ends


# ─── 2. the loop journals turn_end with cumulative tokens ─────────────

def test_loop_journals_turn_end_and_llm_events(plane):
    ctx, reg, j, _, ws, tmp_path = plane
    replies = [
        reply("Probing.", tools=[
            tu("run_command", {"command": "echo hello 10.0.0.5"}, 1)],
            usage={"prompt_tokens": 100, "completion_tokens": 20}),
        reply("Done: hello",
              usage={"prompt_tokens": 150, "completion_tokens": 30}),
    ]
    deps = ProductionDeps(adapter=FakeAdapter(replies),
                          guard=LLMGuard(journal=j))

    async def drain():
        out = []
        async for ev in query_loop(QueryParams(
                system_prompt="You are AEGIS.", tools=list(reg),
                initial_messages=[
                    {"role": "user", "content": "say hi"}], ctx=ctx),
                deps):
            out.append(ev)
        return out

    events = asyncio.run(drain())
    assert events[-1].kind == "completed"
    assert events[-1].reason == "end_turn"

    jev = _load_events(tmp_path / "journal")
    types = [e["type"] for e in jev]
    # the guard's defense events flowed into the engagement journal
    assert types.count("llm_call") == 2
    assert types.count("llm_call_end") == 2
    # one turn_end per assembled reply, cumulative counters
    tds = [e for e in jev if e["type"] == "turn_end"]
    assert len(tds) == 2
    assert tds[0]["data"]["prompt_tokens"] == 100
    assert tds[0]["data"]["completion_tokens"] == 20
    assert tds[1]["data"]["prompt_tokens"] == 250   # cumulative
    assert tds[1]["data"]["completion_tokens"] == 50


# ─── 3. the SLO model plane reads a production-shaped journal ─────────

def test_slo_model_plane_reads_production_journal(plane):
    ctx, reg, j, _, ws, tmp_path = plane
    replies = [
        reply("Probing.", tools=[
            tu("run_command", {"command": "echo hello 10.0.0.5"}, 1)],
            usage={"prompt_tokens": 100, "completion_tokens": 20}),
        reply("Done: hello",
              usage={"prompt_tokens": 150, "completion_tokens": 30}),
    ]
    deps = ProductionDeps(adapter=FakeAdapter(replies),
                          guard=LLMGuard(journal=j))

    async def drain():
        out = []
        async for ev in query_loop(QueryParams(
                system_prompt="You are AEGIS.", tools=list(reg),
                initial_messages=[
                    {"role": "user", "content": "say hi"}], ctx=ctx),
                deps):
            out.append(ev)
        return out

    asyncio.run(drain())
    rep = slo_audit(_load_events(tmp_path / "journal"))
    p = rep["profile"]
    m = p["model_calls"]
    # the plane the first real acceptance run showed as 0/0/n-a
    assert m["count"] == 2 and m["ok"] == 2 and m["errors"] == 0
    assert m["p50_ms"] is not None and m["max_ms"] is not None
    assert p["tokens"] == {"prompt": 250, "completion": 50}
    assert rep["overall"] == "pass"


# ─── 4. the cli glue: run_engagement routes the journal-wired guard ──

def test_run_engagement_routes_guard_journal(plane, capsys):
    """The engagement glue the acceptance run actually executes: the
    journal-wired guard must reach the MAIN loop (production_deps),
    not just the subagent runtime — the original bug was exactly
    here (run_engagement built a fresh journal-less guard)."""
    from hypervisor.cli import run_engagement
    ctx, reg, j, _, ws, tmp_path = plane
    replies = [
        reply("Probing.", tools=[
            tu("run_command", {"command": "echo hello 10.0.0.5"}, 1)],
            usage={"prompt_tokens": 100, "completion_tokens": 20}),
        reply("Done: hello",
              usage={"prompt_tokens": 150, "completion_tokens": 30}),
    ]
    params = QueryParams(
        system_prompt="You are AEGIS.", tools=list(reg),
        initial_messages=[{"role": "user", "content": "say hi"}],
        ctx=ctx)
    rc = run_engagement(params, FakeAdapter(replies),
                        guard=LLMGuard(journal=j))
    assert rc == 0
    jev = _load_events(tmp_path / "journal")
    types = [e["type"] for e in jev]
    assert types.count("llm_call") == 2          # main loop, journaled
    assert types.count("llm_call_end") == 2
    assert types.count("turn_end") == 2
    rep = slo_audit(jev)
    assert rep["profile"]["model_calls"]["count"] == 2
    assert rep["profile"]["tokens"] == {"prompt": 250, "completion": 50}
