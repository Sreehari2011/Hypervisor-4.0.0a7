"""Acceptance tests for the debug kit port (PORT-08).

The kit's env knobs are read at import time (same as 3.x), so these
tests control the environment before (re)importing the config module —
importlib.reload re-executes in place, so held module references stay
valid (the same property the 3.x kit relied on for its own tests).
"""
import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))  # run from checkout without install


@pytest.fixture()
def kit(tmp_path, monkeypatch):
    """Fresh kit pointed at a temp dir, fully installed."""
    monkeypatch.setenv("AEGIS_DEBUG", "1")
    monkeypatch.setenv("AEGIS_DEBUG_DIR", str(tmp_path / "debug"))
    monkeypatch.setenv("AEGIS_DEBUG_QUIET", "1")
    import hypervisor.debug as dbg
    import hypervisor.debug.config as cfg
    importlib.reload(cfg)
    dbg.reset_for_tests()
    dbg.install()
    yield dbg
    dbg.reset_for_tests()


def _timeline_events(dbg):
    path = Path(dbg.timeline.path())
    if not path.exists():
        return []
    return [json.loads(x) for x in
            path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ── 1. install creates the run dir + meta ─────────────────────────

def test_install_creates_run_dir(kit, tmp_path):
    root = tmp_path / "debug"
    runs = list(root.glob("run_*"))
    assert len(runs) == 1
    meta = json.loads((runs[0] / "kit_meta.json").read_text())
    assert meta["kit"].startswith("aegis-debug 2.0")
    for sub in ("wire", "prompts", "stalls"):
        assert (runs[0] / sub).is_dir()
    # idempotent
    kit.install()
    assert len(list(root.glob("run_*"))) == 1


# ── 2. timeline event shape ────────────────────────────────────────

def test_timeline_event_shape(kit):
    kit.timeline.emit("meta", "unit_probe", dur_ms=1.25, id="x1", k="v")
    evs = _timeline_events(kit)
    probe = [e for e in evs if e["ev"] == "unit_probe"][0]
    assert probe["cat"] == "meta" and probe["dur_ms"] == 1.25
    assert probe["id"] == "x1" and probe["data"]["k"] == "v"
    assert "ts" in probe and "t" in probe
    t0 = kit.timeline.last_event_time()
    kit.timeline.emit("meta", "again")
    assert kit.timeline.last_event_time() >= t0


# ── 3. journal tap mirrors appends ────────────────────────────────

def test_journal_tap_mirrors_events(kit, tmp_path):
    from hypervisor.persist.journal import Journal
    j = Journal(tmp_path / "jtap")
    j.append("boot", {"mode": "scoped-full-auto"})
    evs = _timeline_events(kit)
    mirrored = [e for e in evs if e["cat"] == "journal"
                and e["ev"] == "boot"]
    assert mirrored, "journal boot event must mirror into the timeline"
    m = mirrored[-1]
    assert m["data"]["seq"] == 1
    assert m["data"]["data"]["mode"] == "scoped-full-auto"


def test_journal_tap_never_breaks_journal(kit, tmp_path, monkeypatch):
    from hypervisor.persist.journal import Journal
    j = Journal(tmp_path / "jtap2")
    # sabotage the timeline emitter the tap calls
    def boom(*a, **kw):
        raise RuntimeError("tap explosion")
    monkeypatch.setattr(kit.timeline, "emit", boom)
    ev = j.append("boot", {"still": "fine"})
    assert ev is not None and ev["seq"] == 1
    assert j.verify_integrity()["ok"]


# ── 4. wire tap on a fake httpx module ────────────────────────────

def _fresh_fake_module():
    """A fresh fake httpx-flavored module per call. Classes are defined
    INSIDE so each test patches a never-patched class — a module-level
    class would accumulate taps across tests (module-global state in
    wire_tap keys the original `send` at patch time)."""

    class FakeRequest:
        def __init__(self, url, body=b""):
            self.url = url
            self.method = "POST"
            self.content = body
            self.headers = {"Authorization": "Bearer sekrit", "X-Ok": "1"}

    class FakeResponse:
        status_code = 200
        content = b'{"usage": {"prompt_tokens": 10}}'
        headers = {"Content-Type": "application/json"}

        def iter_bytes(self):
            yield b'data: {"usage": {"total_tokens": 42}}\n'
            yield b"\n"

    class FakeClient:
        def send(self, request, *a, stream=False, **kw):
            return FakeResponse()

    return types.SimpleNamespace(Client=FakeClient, AsyncClient=FakeClient), \
        FakeRequest


def test_wire_tap_sync_nonstream(kit):
    mod, FakeRequest = _fresh_fake_module()
    assert kit.wire_tap._install_httpx_module(mod, "fakehttpx")
    client = mod.Client()
    req = FakeRequest(
        "http://cisai-ultra.local/v1/chat/completions",
        b'{"model": "cisai", "messages": [{"content": "hi"}]}')
    resp = client.send(req)
    assert resp.status_code == 200
    evs = _timeline_events(kit)
    req_ev = [e for e in evs if e["cat"] == "wire" and e["ev"] == "request"][-1]
    assert req_ev["data"]["transport"] == "fakehttpx"
    assert req_ev["data"]["model"] == "cisai"
    assert req_ev["data"]["n_messages"] == 1
    wire_dir = Path(kit.config.run_dir()) / "wire"
    reqs = sorted(wire_dir.glob("req_*.json"))
    resps = sorted(wire_dir.glob("resp_*.json"))
    assert reqs and resps
    saved_req = json.loads(reqs[-1].read_text())
    assert saved_req["headers"]["Authorization"] == "***REDACTED***"
    assert saved_req["headers"]["X-Ok"] == "1"


def test_wire_tap_streaming_tee_counts_chunks(kit):
    mod, FakeRequest = _fresh_fake_module()
    kit.wire_tap._install_httpx_module(mod, "fakehttpx")
    resp = mod.Client().send(FakeRequest("http://x/api"), stream=True)
    chunks = list(resp.iter_bytes())
    assert len(chunks) == 2
    evs = _timeline_events(kit)
    end = [e for e in evs if e["ev"] == "stream_end"][-1]
    assert end["data"]["chunks"] == 2 and end["data"]["status"] == 200
    # second consumer path is a silent passthrough: chunks are delivered,
    # but NOT double-counted — still exactly one stream_end at 2 chunks
    assert list(resp.iter_bytes()) == chunks
    ends = [e for e in _timeline_events(kit) if e["ev"] == "stream_end"]
    assert len(ends) == 1 and ends[0]["data"]["chunks"] == 2


# ── 5. LoopObserver spans ─────────────────────────────────────────

def test_loop_observer_llm_tool_perm_spans(kit):
    from hypervisor.debug.loop_events import LoopObserver
    obs = LoopObserver()
    obs.on_loop_start(turn=1)
    obs.on_llm_start("span1", model="cisai", turn=1,
                     messages=[{"role": "user", "content": "go"}],
                     system_prompt="SYS")
    obs.on_llm_first_token("span1")
    obs.on_llm_end("span1", usage={"prompt_tokens": 5,
                                   "completion_tokens": 7,
                                   "total_tokens": 12},
                   finish="tool_calls", output="calling")
    obs.on_tool_start("span2", tool="nmap_scan", turn=1, args="-sV target")
    obs.on_tool_end("span2", output="open ports found")
    obs.on_permission_decision(tool="nmap_scan", allowed=True,
                               rule="cidr:10.0.0.0/24", turn=1)
    obs.on_transition("tool_result", to="next_turn", turn=1)
    obs.on_loop_end(turn=1, reason="objective complete")
    evs = _timeline_events(kit)
    cats = [(e["cat"], e["ev"]) for e in evs]
    assert ("loop", "start") in cats and ("loop", "end") in cats
    assert ("llm", "start") in cats and ("llm", "first_token") in cats
    assert ("llm", "end") in cats and ("tool", "start") in cats
    assert ("tool", "end") in cats and ("perm", "decision") in cats
    assert ("loop", "transition") in cats
    end = [e for e in evs if e["cat"] == "llm" and e["ev"] == "end"][0]
    assert end["data"]["total_tokens"] == 12
    prompt_files = list((Path(kit.config.run_dir()) / "prompts")
                        .glob("prompt_*.txt"))
    assert prompt_files and "── system · 3 chars" in prompt_files[-1].read_text()


# ── 6. empty loop smoke — the P0 exit criterion ───────────────────

@pytest.mark.anyio
async def test_empty_loop_smoke(kit):
    import asyncio
    res = await asyncio.get_event_loop().run_in_executor(
        None, lambda: None)  # loop exists; smoke is executor-safe anyway
    from hypervisor.query import empty_loop_smoke
    out = await empty_loop_smoke()
    assert out["observer"] == "main"
    evs = _timeline_events(kit)
    kinds = [e["ev"] for e in evs if e["cat"] == "loop"]
    assert "start" in kinds and "end" in kinds and "transition" in kinds


# ── 7. fail-silence under a broken sink ───────────────────────────

def test_emit_never_raises_on_broken_dir(kit, monkeypatch):
    monkeypatch.setattr(kit.config, "run_dir",
                        lambda: "/proc/definitely/not/writable")
    kit.timeline.close()
    kit.timeline.emit("meta", "into_the_void")   # must not raise
