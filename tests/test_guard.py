"""P1 acceptance tests — guard.py (PORT-07: the four defenses).

Port-card acceptance list, mapped:
  2. breaker: N consecutive failures -> open; recovery resets
  3. sanitizer: degenerate delta fixture -> treated as failure
  4. green path: no false trips across a full run
The oracle-defect repro (item 1: the 24-minute hang bounded by the
caller-side total) is covered by test_total_bound_replaces_the_hang;
the full repro_hang.py replay against a mock gateway is a P4
fault-matrix exercise on the real stack (E2E variant lives in
test_e2e.py)."""
import asyncio
import time

import pytest

from hypervisor.adapters.openai import Chunk
from hypervisor.guard import (Breaker, GuardBounds, LLMCallTimeoutError,
                              LLMBreakerOpenError, LLMDegenerateStreamError,
                              LLMGuard, _DegenerateWatch)


def fast_bounds(**kw):
    b = dict(total_timeout_s=0.5, idle_timeout_s=0.3, max_attempts=1,
             backoff_s=0.01, cancel_grace_s=0.2, breaker_threshold=3)
    b.update(kw)
    return GuardBounds(**b)


async def _ok_stream():
    for t in ("Hello", " world"):
        await asyncio.sleep(0.005)
        yield Chunk(kind="text", text=t)
    yield Chunk(kind="reply", reply=None)


def run(coro):
    return asyncio.run(coro)


def test_green_path_no_false_trips():
    async def go():
        g = LLMGuard(bounds=fast_bounds())
        out = [c.text async for c in g.call_stream(
            _ok_stream, purpose="ok") if c.kind == "text"]
        assert out == ["Hello", " world"]
        assert not g.breaker.is_open("ok")
    run(go())


def test_total_bound_replaces_the_hang():
    """The 2026-10-06 defect class: a call that never produces a chunk
    must be bounded caller-side, well below any observation window."""
    async def hang():
        await asyncio.sleep(30)
        yield Chunk(kind="text", text="never")

    async def go():
        g = LLMGuard(bounds=fast_bounds(total_timeout_s=0.3,
                                        idle_timeout_s=0.2))
        t0 = time.monotonic()
        with pytest.raises(LLMCallTimeoutError):
            async for _ in g.call_stream(hang, purpose="hang"):
                pass
        assert time.monotonic() - t0 < 2.0
    run(go())


def test_idle_bound_catches_keepalive_only_streams():
    """A stream that produces a parsed chunk only every few seconds
    (keepalive comment lines between them) parks interval-based
    watchdogs forever; the parsed-chunk idle bound must fire BETWEEN
    chunks, well before the total bound."""

    async def trickle():
        for _ in range(50):
            await asyncio.sleep(0.3)
            yield Chunk(kind="text", text="x")
        yield Chunk(kind="reply", reply=None)

    async def go():
        g = LLMGuard(bounds=fast_bounds(total_timeout_s=30.0,
                                        idle_timeout_s=0.15))
        with pytest.raises(LLMCallTimeoutError) as ei:
            async for _ in g.call_stream(trickle, purpose="trickle"):
                pass
        assert ei.value.reason == "idle"
    run(go())


def test_sanitizer_catches_content_free_streams():
    async def degenerate():
        for _ in range(300):
            yield Chunk(kind="text", text="")
        yield Chunk(kind="reply", reply=None)

    async def go():
        g = LLMGuard(bounds=fast_bounds(
            degenerate_min_chunks=200, degenerate_max_chars=10))
        with pytest.raises(LLMDegenerateStreamError):
            async for _ in g.call_stream(degenerate, purpose="deg"):
                pass
    run(go())


def test_sanitizer_catches_looping_deltas():
    """The live regression: `|>think<|sep|>` repeated hundreds of
    times — content exists but nothing new."""
    async def loop():
        for _ in range(120):
            yield Chunk(kind="text", text="|>think<|sep|>")
        yield Chunk(kind="reply", reply=None)

    async def go():
        g = LLMGuard(bounds=fast_bounds(
            degenerate_min_chunks=10_000,   # force the loop rule to fire
            degenerate_repeat_streak=100))
        with pytest.raises(LLMDegenerateStreamError) as ei:
            async for _ in g.call_stream(loop, purpose="loop"):
                pass
        assert "looping" in str(ei.value)
    run(go())


def test_sanitizer_watch_unit():
    w = _DegenerateWatch(GuardBounds(degenerate_min_chunks=5,
                                     degenerate_max_chars=3,
                                     degenerate_repeat_streak=3))
    for _ in range(4):
        assert w.observe(Chunk(kind="text", text="")) is None
    assert w.observe(Chunk(kind="text", text="")) is not None

    w2 = _DegenerateWatch(GuardBounds(degenerate_min_chunks=10_000,
                                      degenerate_max_chars=1,
                                      degenerate_repeat_streak=3))
    assert w2.observe(Chunk(kind="text", text="abc")) is None
    assert w2.observe(Chunk(kind="text", text="abc")) is None
    assert w2.observe(Chunk(kind="text", text="abc")) is None
    assert w2.observe(Chunk(kind="text", text="abc")) is not None


def test_breaker_opens_and_resets():
    async def fail():
        raise RuntimeError("boom")
        yield

    async def go():
        g = LLMGuard(bounds=fast_bounds())
        for _ in range(3):
            with pytest.raises(RuntimeError):
                async for _ in g.call_stream(fail, purpose="b"):
                    pass
        assert g.breaker.is_open("b")
        with pytest.raises(LLMBreakerOpenError):
            async for _ in g.call_stream(_ok_stream, purpose="b"):
                pass
        # recovery: a success resets the circuit
        g.breaker.record("b", True)
        assert not g.breaker.is_open("b")
        out = [c.text async for c in g.call_stream(
            _ok_stream, purpose="b") if c.kind == "text"]
        assert out == ["Hello", " world"]
        # purposes are independent
        assert not g.breaker.is_open("other")
    run(go())


def test_guard_journals_the_full_event_family(tmp_path):
    from hypervisor.persist.journal import Journal
    j = Journal(tmp_path / "j")

    async def fail():
        raise RuntimeError("boom")
        yield

    async def go():
        g = LLMGuard(bounds=fast_bounds(max_attempts=2, backoff_s=0.01),
                     journal=j)
        with pytest.raises(RuntimeError):
            async for _ in g.call_stream(fail, purpose="j"):
                pass
    run(go())
    events = list(j.events())
    types = [e["type"] for e in events]
    assert "llm_call" in types
    assert "llm_call_end" in types
    assert "llm_retry" in types
    assert "llm_breaker" in types
    end = [e for e in events if e["type"] == "llm_call_end"][0]
    assert end["data"]["outcome"] == "error"
    brk = [e for e in events if e["type"] == "llm_breaker"][0]
    assert brk["data"]["consecutive_failures"] == 1


def test_breaker_unit_semantics():
    b = Breaker(3)
    assert b.record("k", False) == 1
    assert b.record("k", False) == 2
    assert b.record("k", False) == 3
    assert b.is_open("k")
    b.check("k") if not b.is_open("k") else None
    with pytest.raises(LLMBreakerOpenError):
        b.check("k")
    assert b.record("k", True) == 0
    assert not b.is_open("k")
