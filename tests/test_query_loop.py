"""P1 acceptance tests — query.py (Skeleton 9-1: THE loop).

Covers the load-bearing behaviors with fake deps: the happy path,
tool_use as the sole exit signal (stop_reason distrusted), max_turns
ceiling, the output ladder (escalate then resume-mid-thought), the
blocking gate, permission denials flowing back as tool_results (the
loop always continues), and the journal/session audit surfaces."""
import asyncio
import json
from pathlib import Path

import pytest

from hypervisor.adapters.openai import Chunk, ModelReply, frozen_json
from hypervisor.persist.journal import Journal
from hypervisor.persist.sessions import SessionStore
from hypervisor.permissions import (PermissionEngine, ScopeFile,
                                    ScopeManager)
from hypervisor.query import (LoopDeps, LoopState, QueryParams,
                              assemble_prompt, query_loop)
from hypervisor.tools.base import ToolContext
from hypervisor.tools.core import build_registry

import hashlib


@pytest.fixture()
def plane(tmp_path):
    scope = {
        "version": 1, "engagement_id": "T", "mode": "strict",
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
    return ctx, reg, j, session, ws


class Scripted(LoopDeps):
    """Fake model plane: pops scripted replies, records every prompt."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen_prompts = []

    async def call_model(self, messages, tools, max_tokens, turn):
        self.seen_prompts.append(([dict(m) for m in messages],
                                  max_tokens))
        r = self.replies.pop(0)
        for t in getattr(r, "text_parts", ()):
            yield Chunk(kind="text", text=t)
        yield Chunk(kind="reply", reply=r)


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


def params(plane, objective="go", **kw):
    ctx, reg, _, _, _ = plane
    return QueryParams(system_prompt="You are AEGIS.",
                       tools=list(reg),
                       initial_messages=[
                           {"role": "user", "content": objective}],
                       ctx=ctx, **kw)


def collect(p, deps):
    return [e for e in asyncio.run(
        _drain(p, deps))]


async def _drain(p, deps):
    out = []
    async for ev in query_loop(p, deps):
        out.append(ev)
    return out


# ─── happy path ────────────────────────────────────────────────────────


def test_happy_path_two_turns(plane):
    fake = Scripted([
        reply("Checking.", tools=[
            tu("run_command", {"command": "echo hello 10.0.0.5"}, 1)]),
        reply("Done: hello",
              usage={"prompt_tokens": 10, "completion_tokens": 5}),
    ])
    events = collect(params(plane, "say hi"), fake)
    kinds = [e.kind for e in events]
    assert kinds == ["text_delta", "tool_result", "transition",
                     "text_delta", "completed"]
    final = events[-1]
    assert final.reason == "end_turn"
    assert final.detail == {"turns": 2, "tool_calls": 1,
                            "prompt_tokens": 10,
                            "completion_tokens": 5}
    tr = events[1]
    assert "hello" in tr.tool_results[0]["content"]
    assert not tr.tool_results[0]["is_error"]
    # assembly: system first; turn-2 prompt carries the full history
    pr = fake.seen_prompts[1][0]
    assert pr[0]["role"] == "system"
    assert pr[0]["content"] == "You are AEGIS."
    assert [m["role"] for m in pr[1:]] == ["user", "assistant", "user"]
    assert pr[-1]["content"][0]["type"] == "tool_result"


# ─── tool_use is the SOLE exit signal ──────────────────────────────────


def test_tool_use_sole_exit_signal(plane):
    """finish_reason says stop, but tool_uses arrived: the loop
    continues (stop_reason is unreliable and must not be trusted —
    query.ts:553-556)."""
    fake = Scripted([
        reply("one", tools=[
            tu("run_command", {"command": "echo a 10.0.0.5"}, 1)]),
        reply("two", tools=[
            tu("run_command", {"command": "echo b 10.0.0.5"}, 2)]),
        reply("finished"),
    ])
    events = collect(params(plane), fake)
    final = events[-1]
    assert final.kind == "completed" and final.reason == "end_turn"
    assert final.detail["turns"] == 3


def test_no_tools_finish_reason_length_runs_later_not_exit(plane):
    fake = Scripted([
        reply("cut", finish="length"),
        reply("done"),
    ])
    events = collect(params(plane), fake)
    # first turn: ladder escalate; second: complete
    trans = [e.transition for e in events if e.kind == "transition"]
    assert trans == ["max_output_tokens_escalate"]
    assert events[-1].reason == "end_turn"


# ─── ceilings ──────────────────────────────────────────────────────────


def test_max_turns_ceiling(plane):
    fake = Scripted([
        reply("again", tools=[
            tu("run_command", {"command": f"echo {i} 10.0.0.5"}, i)])
        for i in range(10)])
    events = collect(params(plane, max_turns=3), fake)
    final = events[-1]
    assert final.kind == "completed" and final.reason == "max_turns"
    assert final.detail["turns"] == 3


def test_blocking_gate_prompt_too_long(plane):
    class Huge(LoopDeps):
        async def call_model(self, *a, **k):
            yield Chunk(kind="reply", reply=reply("x"))

        def estimate_tokens(self, messages):
            return 10 ** 9

    events = collect(params(plane), Huge())
    assert events[-1].kind == "prompt_too_long"


# ─── output ladder ─────────────────────────────────────────────────────


def test_output_ladder_escalate_then_recoveries(plane):
    fake = Scripted([
        reply("cut mid", finish="length"),
        reply("still cut", finish="length"),
        reply("still cut 2", finish="length"),
        reply("finally done"),
    ])
    events = collect(params(plane), fake)
    trans = [e.transition for e in events if e.kind == "transition"]
    assert trans == ["max_output_tokens_escalate",
                     "max_output_tokens_recovery",
                     "max_output_tokens_recovery"]
    final = events[-1]
    assert final.reason == "end_turn" and final.detail["turns"] == 4
    # one clean escalation to the ceiling
    assert fake.seen_prompts[0][1] == 8192
    assert fake.seen_prompts[1][1] == 65536
    # resume-mid-thought isMeta nudge present
    pr3 = fake.seen_prompts[2][0]
    assert pr3[-1].get("isMeta") is True
    assert "Continue your response" in pr3[-1]["content"][0]["text"]


def test_output_ladder_exhaustion_surfaces_error(plane):
    fake = Scripted([
        reply("cut", finish="length"),
        reply("cut", finish="length"),
        reply("cut", finish="length"),
        reply("cut", finish="length"),
        reply("cut", finish="length"),
    ])
    events = collect(params(plane), fake)
    err = events[-1]
    assert err.kind == "error" and "output ladder exhausted" in \
        err.reason


# ─── scoped full-auto: denials flow back, loop continues ───────────────


def test_permission_denial_continues_the_engagement(plane):
    fake = Scripted([
        reply("trying", tools=[
            tu("run_command", {"command": "nmap 192.168.1.1"}, 1)]),
        reply("denied, stopping"),
    ])
    events = collect(params(plane), fake)
    tr = events[1]
    assert tr.tool_results[0]["is_error"]
    assert "PERMISSION DENIED" in tr.tool_results[0]["content"]
    final = events[-1]
    assert final.reason == "end_turn" and final.detail["turns"] == 2


def test_abort_event_ends_the_loop(plane):
    ctx, reg, _, _, _ = plane
    ctx.abort.set()
    fake = Scripted([reply("never")])
    events = collect(params(plane), fake)
    assert events[-1].kind == "completed"
    assert events[-1].reason == "aborted"


# ─── audit surfaces ────────────────────────────────────────────────────


def test_journal_records_the_transition_table(plane):
    fake = Scripted([
        reply("checking", tools=[
            tu("run_command", {"command": "echo x 10.0.0.5"}, 1)]),
        reply("done"),
    ])
    collect(params(plane), fake)
    _, _, j, _, _ = plane
    evs = list(j.events())      # events() is a generator — materialize
    types = {e["type"] for e in evs}
    assert {"loop_transition", "permission_decision", "tool_call",
            "tool_result", "agent_message"} <= types
    trans = [e["data"]["transition"] for e in evs
             if e["type"] == "loop_transition"]
    assert trans[0] == "init"
    assert "next_turn" in trans and "end_turn" in trans
    perm = [e for e in evs if e["type"] == "permission_decision"]
    assert perm and perm[0]["data"]["allowed"] is True
    assert perm[0]["data"]["scope_ref"].startswith("sha256:")


def test_session_records_the_transcript_chain(plane):
    fake = Scripted([
        reply("checking", tools=[
            tu("run_command", {"command": "echo x 10.0.0.5"}, 1)]),
        reply("done"),
    ])
    collect(params(plane), fake)
    _, _, _, session, _ = plane
    rep = session.verify_chain()
    assert rep["records"] >= 5 and rep["orphans"] == []
    types = [r["type"] for r in session.read_all()]
    assert "user" in types and "assistant" in types
    assert "tool_result" in types and "meta" in types


def test_loop_state_next_and_assembly():
    st = LoopState(messages=[{"role": "user", "content": "x"}])
    st2 = st.next(messages=[{"role": "user", "content": "xy"}],
                  transition="next_turn")
    assert st2.turn_count == 1 and st2.transition == "next_turn"
    assert st2.output_recovery == 0
    st3 = st2.next(messages=[], output_recovery=1)
    assert st3.turn_count == 2 and st3.output_recovery == 1
    p = assemble_prompt("SYS", [{"role": "user", "content": "x"}])
    assert p[0] == {"role": "system", "content": "SYS"}
    assert assemble_prompt("", [{"role": "user", "content": "x"}]) == \
        [{"role": "user", "content": "x"}]
