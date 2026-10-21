"""P4 acceptance — the stop-hook surface (hypervisor/hooks.py + the
query_loop seam + the SubagentStop re-entry).

CC contract anchors (claude-code reference): StopHookInputSchema
({hook_event_name: 'Stop', stop_hook_active, last_assistant_message}),
exit-2 blocking error semantics, {decision: approve|block, reason}
stdout JSON, the stop_hook_active recursion guard.

Acceptance:
  * approve / block / exit-2 / non-blocking-error / timeout decisions;
  * a block feeds the reason back and the loop CONTINUES;
  * stop_hook_active prevents recursion (second block completes);
  * hook failure never wedges the loop (audited allow);
  * the payload shape matches CC's Stop input;
  * journal stop_hook events land and replay counts them;
  * the SubagentStop seam re-drives a blocked child once.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.adapters.openai import Chunk, ModelReply, frozen_json  # noqa: E402
from hypervisor.hooks import (HookDecision, StopHookConfig,  # noqa: E402
                              block_feedback_message,
                              run_stop_hook, stop_hook_from_env,
                              stop_payload)
from hypervisor.persist.journal import Journal  # noqa: E402
from hypervisor.query import LoopDeps, QueryParams, query_loop  # noqa: E402
from hypervisor.tools.base import ToolContext  # noqa: E402
from hypervisor.tools.core import build_registry  # noqa: E402

import hashlib  # noqa: E402


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
    from hypervisor.permissions import (PermissionEngine, ScopeFile,
                                        ScopeManager)
    sm = ScopeManager(ScopeFile.load(d / "scope.json"))
    ws = tmp_path / "ws"
    ws.mkdir()
    j = Journal(tmp_path / "journal")
    reg = build_registry()
    ctx = ToolContext(workspace=str(ws), registry=reg,
                      permissions=PermissionEngine(sm, journal=j),
                      journal=j)
    return ctx, j, ws


class Scripted(LoopDeps):
    def __init__(self, replies):
        self.replies = list(replies)
        self.seen_prompts = []

    async def call_model(self, messages, tools, max_tokens, turn):
        self.seen_prompts.append([dict(m) for m in messages])
        r = self.replies.pop(0)
        for t in getattr(r, "text_parts", ()):
            yield Chunk(kind="text", text=t)
        yield Chunk(kind="reply", reply=r)


def reply(text="", finish="stop"):
    blocks = [{"type": "text", "text": text}] if text else []
    r = ModelReply(message={"role": "assistant", "content": blocks},
                   tool_uses=[], text=text, usage={},
                   finish_reason=finish, model="fake")
    r.text_parts = tuple([text] if text else ())
    return r


def run(params, deps):
    out = []

    async def _go():
        async for ev in query_loop(params, deps):
            out.append(ev)
    asyncio.run(_go())
    return out


def hook_script(tmp_path, body, name="hook.sh"):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return str(p)


# ─── decision parsing (CC semantics) ────────────────────────────────────

def test_payload_shape_matches_cc_stop_input():
    p = stop_payload(last_assistant_message="done",
                     stop_hook_active=False, turn=3)
    assert p["hook_event_name"] == "Stop"
    assert p["stop_hook_active"] is False
    assert p["last_assistant_message"] == "done"
    assert p["turn"] == 3


def test_approve_via_json_stdout(tmp_path):
    cmd = hook_script(tmp_path,
                      'echo \'{"decision": "approve"}\'')
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.decision == "approve" and not d.blocks


def test_block_via_json_stdout(tmp_path):
    cmd = hook_script(
        tmp_path,
        "echo '{\"decision\": \"block\", "
        "\"reason\": \"findings summary missing\"}'")
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.blocks
    assert d.reason == "findings summary missing"


def test_block_via_exit_code_2_with_stderr(tmp_path):
    cmd = hook_script(tmp_path,
                      'echo "engagement incomplete" >&2\nexit 2')
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.blocks
    assert "engagement incomplete" in d.reason


def test_nonzero_exit_is_audited_allow_not_block(tmp_path):
    cmd = hook_script(tmp_path, 'echo "boom" >&2\nexit 1')
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.decision == "error" and not d.blocks


def test_exit_0_no_json_is_approve(tmp_path):
    cmd = hook_script(tmp_path, 'exit 0')
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.decision == "approve"


def test_hook_timeout_is_audited_allow(tmp_path):
    cmd = hook_script(tmp_path, 'sleep 30')
    d = asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd, timeout_s=1.0),
        stop_payload(last_assistant_message="x",
                     stop_hook_active=False, turn=1)))
    assert d.timed_out
    assert d.decision == "error" and not d.blocks


def test_hook_receives_payload_on_stdin(tmp_path):
    cmd = hook_script(
        tmp_path,
        'read -r LINE\necho "$LINE" > "' +
        str(tmp_path / "payload.json") + '"\nexit 0')
    asyncio.run(run_stop_hook(
        StopHookConfig(command=cmd), stop_payload(
            last_assistant_message="hello hook",
            stop_hook_active=True, turn=7)))
    got = json.loads((tmp_path / "payload.json").read_text())
    assert got["hook_event_name"] == "Stop"
    assert got["stop_hook_active"] is True
    assert got["last_assistant_message"] == "hello hook"


def test_callable_hook_sync_and_async(tmp_path):
    calls = []

    def sync_hook(payload):
        calls.append(payload)
        return {"decision": "block", "reason": "not done"}

    d = asyncio.run(run_stop_hook(
        StopHookConfig(callable=sync_hook), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.blocks and len(calls) == 1

    async def async_hook(payload):
        return None                       # None = approve

    d = asyncio.run(run_stop_hook(
        StopHookConfig(callable=async_hook), stop_payload(
            last_assistant_message="x", stop_hook_active=False,
            turn=1)))
    assert d.decision == "approve"


def test_env_config_roundtrip(monkeypatch):
    monkeypatch.setenv("AEGIS_STOP_HOOK", "/usr/local/bin/gate.sh")
    monkeypatch.setenv("AEGIS_SUBAGENT_STOP_HOOK", "/x/y.sh")
    monkeypatch.setenv("AEGIS_STOP_HOOK_TIMEOUT_S", "45")
    cfg = stop_hook_from_env()
    assert cfg.command == "/usr/local/bin/gate.sh"
    assert cfg.subagent_command == "/x/y.sh"
    assert cfg.timeout_s == 45.0
    assert cfg.active() and cfg.subagent_active()


# ─── the loop seam ──────────────────────────────────────────────────────

def test_block_continues_the_loop_then_completes(plane, tmp_path):
    ctx, j, ws = plane
    # blocks the first stop, approves the second
    marker = tmp_path / "marker"
    cmd = hook_script(
        tmp_path,
        f'if [ ! -f "{marker}" ]; then\n'
        f'  touch "{marker}"\n'
        f'  echo "name the lab scope first" >&2\n'
        f'  exit 2\n'
        f'fi\n'
        f'echo \'{{"decision": "approve"}}\'\n', name="loop-hook.sh")
    deps = Scripted([reply("first attempt"),
                     reply("final: 10.0.0.0/24 lab done")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig(command=cmd))
    events = run(params, deps)
    completes = [e for e in events if e.kind == "completed"]
    assert len(completes) == 1
    assert completes[0].reason == "end_turn"
    assert completes[0].detail["turns"] == 2
    # the block feedback message reached the model's second prompt
    second = deps.seen_prompts[1]
    feedback = [m for m in second if m.get("isMeta")]
    assert feedback, "the block reason must ride the channel"
    assert "name the lab scope first" in \
        json.dumps(second, default=str)
    # the journal audited both consultations + the blocked transition
    types = [e["type"] for e in j.events()]
    assert types.count("stop_hook") == 2
    stops = [e for e in j.events() if e["type"] == "stop_hook"]
    assert [e["data"]["decision"] for e in stops] == ["block", "approve"]
    transitions = [e["data"].get("transition") for e in j.events()
                   if e["type"] == "loop_transition"]
    assert "stop_hook_blocked" in transitions
    assert "end_turn" in transitions


def test_recursion_guard_second_block_completes(plane, tmp_path):
    ctx, j, ws = plane
    cmd = hook_script(
        tmp_path, 'echo "always block" >&2\nexit 2',
        name="always-block.sh")
    deps = Scripted([reply("one"), reply("two"), reply("three")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig(command=cmd))
    events = run(params, deps)
    completes = [e for e in events if e.kind == "completed"]
    assert len(completes) == 1 and completes[0].reason == "end_turn"
    # exactly ONE re-entry (turn 2), then the guard completes on turn 2
    assert completes[0].detail["turns"] == 2
    transitions = [e["data"].get("transition") for e in j.events()
                   if e["type"] == "loop_transition"]
    assert "stop_hook_recursion_guard" in transitions


def test_hook_error_never_wedges_the_loop(plane, tmp_path):
    ctx, j, ws = plane
    cmd = hook_script(tmp_path, 'exit 1', name="failing.sh")
    deps = Scripted([reply("done")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig(command=cmd))
    events = run(params, deps)
    completes = [e for e in events if e.kind == "completed"]
    assert len(completes) == 1 and completes[0].reason == "end_turn"
    assert completes[0].detail["turns"] == 1


def test_no_hook_configured_is_inert(plane):
    ctx, j, ws = plane
    deps = Scripted([reply("done")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig())
    events = run(params, deps)
    assert [e.kind for e in events].count("completed") == 1
    types = [e["type"] for e in j.events()]
    assert "stop_hook" not in types


def test_feedback_message_shape():
    m = block_feedback_message("the reason given")
    assert m["role"] == "user"
    assert m["isMeta"] is True
    text = json.dumps(m)
    assert "the reason given" in text
    assert "Continue working" in text


# ─── journal + replay integration ───────────────────────────────────────

def test_replay_counts_stop_hook_events(plane, tmp_path):
    ctx, j, ws = plane
    cmd = hook_script(
        tmp_path, 'echo \'{"decision": "approve"}\'',
        name="approve.sh")
    deps = Scripted([reply("done")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig(command=cmd))
    run(params, deps)
    from hypervisor.persist.replay import JournalReplay
    r = JournalReplay(Path(j.file).parent)
    chain = r.revision_chain()
    assert chain["stop_hook_runs"] == 1
    assert chain["stop_hook_blocks"] == 0
    report = r.full_report()
    assert report["ok"], report["renders"]["issues"]


def test_replay_clean_after_block_and_continue(plane, tmp_path):
    """The P4-harness bug class: the block feedback message must be a
    journaled channel member or Zone W reconstruction fails."""
    ctx, j, ws = plane
    marker = tmp_path / "m2"
    cmd = hook_script(
        tmp_path,
        f'if [ ! -f "{marker}" ]; then touch "{marker}"; '
        f'echo "keep going" >&2; exit 2; fi\n'
        f'echo \'{{"decision": "approve"}}\'\n', name="bc.sh")
    deps = Scripted([reply("attempt"),
                     reply("done properly")])
    params = QueryParams(
        system_prompt="s", tools=[], initial_messages=[
            {"role": "user", "content": "objective"}],
        ctx=ctx, stop_hook=StopHookConfig(command=cmd))
    run(params, deps)
    from hypervisor.persist.replay import JournalReplay
    r = JournalReplay(Path(j.file).parent)
    report = r.full_report(verify_renders=True)
    assert report["ok"], report["renders"]["issues"]
    chain = r.revision_chain()
    assert chain["stop_hook_runs"] == 2
    assert chain["stop_hook_blocks"] == 1
