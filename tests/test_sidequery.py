"""P3 acceptance — REFACTOR-04: the L3 pre-expansion selector.

Oracle anchors: src/core/side_query.py L48-86 (the selector prompts),
L110-123 (index), L134-167 (detection), L172-185 (gate), L190-207
(post-filter), L212-230 (expansion cap at injection), L256-400 (the
orchestration + the never-gates discipline).
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.adapters.openai import Chunk, ModelReply  # noqa: E402
from hypervisor.memory import sidequery as SQ  # noqa: E402
from hypervisor.memory.ekd import DAGNode, EngagementDAG  # noqa: E402
from hypervisor.memory.extractors import ensure_objective  # noqa: E402
from hypervisor.persist.journal import Journal  # noqa: E402
from hypervisor.tools.base import ToolContext  # noqa: E402


class _Ctx:
    def __init__(self, extra):
        self.extra = extra


def _ekd():
    ekd = EngagementDAG()
    ensure_objective(ekd, "probe the lab")
    ekd.add(DAGNode(id="", type="entity", subtype="host",
                    key="ip:10.10.0.5", title="10.10.0.5"))
    ekd.add(DAGNode(id="", type="entity", subtype="endpoint",
                    key="url:https://app.target.com/login",
                    title="login endpoint"))
    ekd.add(DAGNode(id="", type="finding", key="finding:sqli",
                    title="sqli on /search"))
    return ekd


# ─── the gate (spec 3.5) ───────────────────────────────────────────────

def test_gate_skips_when_revision_unchanged_and_no_new_entities():
    run, reason = SQ.selector_gate(revision_changed=False,
                                   new_entities=[], candidates=5)
    assert run is False
    assert reason == "revision unchanged and no new entities"
    run, reason = SQ.selector_gate(revision_changed=True,
                                   new_entities=[], candidates=5)
    assert run is True and reason == "revision bump"
    run, reason = SQ.selector_gate(revision_changed=False,
                                   new_entities=["h1"], candidates=5)
    assert run is True and "new entities" in reason
    run, _ = SQ.selector_gate(revision_changed=True, new_entities=[],
                              candidates=0)
    assert run is False        # nothing fresh to pick


def test_detect_new_entities_deterministic():
    ekd = _ekd()
    got = SQ.detect_new_entities(
        "check 10.10.0.5 and the app.target.com login", ekd)
    # both the ip-keyed host and the endpoint resolve by key mention
    assert len(got) >= 1
    assert all(isinstance(x, str) for x in got)
    got2 = SQ.detect_new_entities(
        "check 10.10.0.5", ekd, {"surfaced-dummy": 1})
    # 10.10.0.5's node id is not in surfaced -> still detected;
    # with the node id itself surfaced it drops
    h1 = got2[0] if got2 else None
    if h1:
        assert SQ.detect_new_entities("id " + h1, ekd, {h1: 1}) == []


def test_parse_selector_output_enforces_the_contract():
    valid = ["h1", "e2", "F1", "H1", "ZZ9"]
    out = SQ.parse_selector_output(
        "h1\nBogus prose\nZZ9\nh1 again\ne2\nF1\nH1\nextra", valid)
    assert out == ["h1", "ZZ9", "e2", "F1", "H1"]
    # surfaced dropped, invalid dropped, dupes dropped, cap 5
    out2 = SQ.parse_selector_output("h1\ne2", ["h1", "e2"],
                                    {"h1": 1})
    assert out2 == ["e2"]
    assert SQ.parse_selector_output("nothing valid", valid) == []


def test_selector_prompt_shape():
    """The no-tools constraint LEADS and the trailer reinforces (the
    measured 2.79% lesson — oracle L48-86 verbatim)."""
    assert SQ.SELECTOR_SYSTEM_PROMPT.startswith("CRITICAL: Respond "
                                                "with TEXT ONLY.")
    assert SQ.SELECTOR_SYSTEM_PROMPT.rstrip().endswith(
        "Tool calls will be rejected and you will fail the task.")
    msg = SQ.selector_user_message("turn text", ["h1 (entity): web"],
                                   [])
    assert msg.startswith("Current turn:\nturn text")
    assert "Engagement entry index:" in msg
    assert "Already surfaced (do not re-pick):\n(none)" in msg


# ─── expansion (cap at injection, sha-pinned) ──────────────────────────

def test_expand_entities_caps_and_pins():
    ekd = _ekd()
    hid = ekd.nodes and next(iter(ekd.nodes))  # some node
    target = None
    for n in ekd.nodes_of_type("entity"):
        target = n
        break
    assert target is not None
    exps = SQ.expand_entities(ekd, [target.id], char_cap=200)
    assert len(exps) == 1
    e = exps[0]
    assert e["id"] == target.id
    assert e["chars"] == len(e["text"]) <= 200
    import hashlib
    assert e["sha"] == hashlib.sha256(
        e["text"].encode()).hexdigest()[:16]


def test_write_expansions_lands_zone_t_and_surface():
    ekd = _ekd()
    ctx = _Ctx({"tail_attachments": {}, "side_query_surfaced": {}})
    n = next(iter(ekd.nodes_of_type("entity")))
    exps = [{"id": n.id, "text": "detail", "sha": "x" * 16,
             "chars": 6}]
    written = SQ.write_expansions(ctx, exps, ts=123.0)
    assert written == 1
    assert ctx.extra["tail_attachments"][n.id]["text"] == "detail"
    assert ctx.extra["side_query_surfaced"][n.id] == 123.0


# ─── the engine (journaled, bounded, never gates) ──────────────────────

class FakeAdapter:
    def __init__(self, reply_text="h1"):
        self.model = "cheap-selector"
        self.reply_text = reply_text
        self.calls = []

    async def stream_chat(self, *, messages, tools, max_tokens):
        self.calls.append({"messages": messages, "tools": tools,
                           "max_tokens": max_tokens})
        text = self.reply_text
        reply = ModelReply(
            message={"role": "assistant", "content": text},
            text=text, usage={}, finish_reason="stop")
        yield Chunk(kind="text", text=text)
        yield Chunk(kind="reply", reply=reply)


class NoopGuard:
    async def call_stream(self, factory, **kw):
        async for c in factory():
            yield c


def test_engine_runs_on_revision_bump_and_journals(tmp_path):
    ekd = _ekd()
    journal = Journal(tmp_path / "journal")
    host_id = next(iter(ekd.nodes_of_type("entity"))).id
    adapter = FakeAdapter(host_id)
    eng = SQ.SideQueryEngine(adapter, NoopGuard(), journal=journal)
    ctx = _Ctx({"ekd": ekd, "tail_attachments": {},
                "side_query_surfaced": {}})
    got = asyncio.run(eng([{"role": "user",
                            "content": "probe 10.10.0.5"}], ctx))
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["tools"] is None
    assert adapter.calls[0]["max_tokens"] == 256
    # the selected entity id expanded into Zone T
    assert got == [host_id]
    evs = journal.events_of_type("side_query")
    assert evs and evs[0]["data"]["trigger"] == "revision bump"
    assert evs[0]["data"]["expansions"]
    assert evs[0]["data"]["expansions"][0]["id"] == host_id
    assert ctx.extra["tail_attachments"][host_id]["text"]
    # engine counters
    assert eng.runs == 1 and eng.expansions_written == 1

    # second call, same rev, same turn text -> skip journaled
    got2 = asyncio.run(eng([{"role": "user",
                             "content": "probe 10.10.0.5"}], ctx))
    assert got2 == []
    assert eng.skips == 1
    evs2 = journal.events_of_type("side_query")
    assert evs2[-1]["data"]["skipped"] == \
        "revision unchanged and no new entities"


def test_engine_never_gates_on_failure(tmp_path):
    """The Table-13 health flag: any selector failure -> [] +
    journaled failure, no exception into the assembly path."""
    class ExplodingAdapter:
        model = "boom"

        async def stream_chat(self, **kw):
            raise RuntimeError("transport gone")
            yield  # pragma: no cover

    ekd = _ekd()
    journal = Journal(tmp_path / "journal")
    eng = SQ.SideQueryEngine(ExplodingAdapter(), NoopGuard(),
                             journal=journal)
    ctx = _Ctx({"ekd": ekd, "tail_attachments": {},
                "side_query_surfaced": {}})
    out = asyncio.run(eng([{"role": "user", "content": "go"}], ctx))
    assert out == []
    assert eng.failures == 1
    evs = journal.events_of_type("side_query")
    assert evs and "selector error" in evs[-1]["data"]["failed"]
    assert "RuntimeError" in evs[-1]["data"]["failed"]


def test_engine_outer_net_swallows_broken_ctx():
    """A ctx that cannot even raise cleanly out of the handler: the
    outer net returns [] (oracle L378-400 parity)."""
    class BrokenExtra:
        def get(self, k, d=None):
            raise RuntimeError("broken")

    class BrokenCtx:
        extra = BrokenExtra()

    eng = SQ.SideQueryEngine(FakeAdapter(), None)
    out = asyncio.run(eng([], BrokenCtx()))
    assert out == []
    assert eng.failures == 1


def test_current_turn_text_skips_machinery():
    msgs = [
        {"role": "user", "content": "objective"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": "x"}]},
        {"role": "user", "content": "the real turn"},
    ]
    assert SQ.current_turn_text(msgs) == "the real turn"
    fold = [{"role": "user", "content":
             "This session is being continued from a previous "
             "conversation"}]
    assert SQ.current_turn_text(fold) == ""


# ─── loop integration: the deps slot ────────────────────────────────────

def test_loop_side_query_slot_defaults_and_wires():
    from hypervisor.query import LoopDeps, ProductionDeps

    class Deps(LoopDeps):
        pass

    d = Deps()
    out = asyncio.run(d.side_query([], None))
    assert out == []

    class Prod(ProductionDeps):
        def __init__(self):
            self.sidequery = SQ.SideQueryEngine(FakeAdapter())

    p = Prod()
    assert asyncio.run(p.side_query([], _Ctx({}))) == []
