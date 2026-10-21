"""hypervisor.guard — LLM call bounds, breaker, sanitizer (P1).

Port card: PORT-07 (3.7.3 core/llm_guard.py — the four defenses born from
the 24-minute-hang post-mortem, ported as LOOP INVARIANTS).

THE POST-MORTEM (run_20261006_085653_pid36): one main-loop model call
parked the agent for 24+ minutes because (1) no call site set a total
duration bound — httpx timeouts were DISABLED (timeout=None), (2) every
watchdog was gap-based (inter-byte / inter-chunk), defeated by gateway
keepalives and degenerate trickle deltas, and (3) the one bounded call
wasted in-flight requests on cancellation races. The four defense lines:

  1. Per-attempt transport bounds — connect/first-byte/inter-chunk live
     in the ADAPTER's httpx.Timeout (see adapters/openai.py); the guard
     adds the parsed-chunk IDLE bound here (defense against
     keepalive-only streams, which inter-byte timeouts cannot catch).
  2. Total wall-clock bound per call, enforced CALLER-SIDE via a child
     pump task: even if the child's cancellation cannot complete (the
     observed container pathology), the caller returns at the deadline.
     Abandoned children are cancelled best-effort, journaled
     (llm_abandon) and left to the transport timeouts to reclaim.
  3. Consecutive-failure breaker — counted per purpose; at threshold the
     circuit opens, fails fast and pages the operator (llm_breaker
     events, mirroring compaction_breaker semantics).
  4. Degenerate-delta sanitizer — content-free chunk streams (the
     `|>think<|sep|>` regression the live model produced) are treated as
     FAILURES, not progress.

Every defense writes its journal events (llm_call, llm_call_end,
llm_retry, llm_abandon, llm_breaker) — the guard NEVER silently
swallows. Bounds are engagement-configurable, never unbounded.

4.0 deltas vs 3.7.3 (port card):
  * operates on async STREAMS (the adapter's chunk generator), not
    llm.ainvoke — no LangChain anywhere;
  * the idle watchdog is enforced at the queue pump level, so a
    keepalive-only SSE stream trips even while bytes keep arriving;
  * the turn watchdog (query.py) wraps whole iterations ABOVE these
    per-call bounds; the debug kit's reaper supplies the external view.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, Optional

from .adapters.openai import Chunk


class LLMCallTimeoutError(RuntimeError):
    """Total wall-clock bound exceeded (caller-side, always enforced)."""

    def __init__(self, purpose: str, timeout_s: float, attempt: int,
                 reason: str = "total"):
        self.purpose = purpose
        self.timeout_s = timeout_s
        self.attempt = attempt
        self.reason = reason          # "total" | "idle"
        super().__init__(
            f"LLM call '{purpose}' exceeded its "
            f"{'total' if reason == 'total' else 'idle'} bound of "
            f"{timeout_s:.0f}s on attempt {attempt} (stream stalled or "
            f"degenerate — see llm_abandon/llm_call_end journal events)")


class LLMBreakerOpenError(RuntimeError):
    """Circuit open: N consecutive failed LLM calls for this purpose."""

    def __init__(self, purpose: str, failures: int, threshold: int):
        self.purpose = purpose
        self.failures = failures
        self.threshold = threshold
        super().__init__(
            f"LLM breaker OPEN for '{purpose}': {failures} consecutive "
            f"failures (threshold {threshold}) — auto-retry disabled; "
            f"operator attention required (see journal breaker events)")


class LLMDegenerateStreamError(RuntimeError):
    """Sanitizer: the chunk stream is content-free or looping."""

    def __init__(self, purpose: str, chunks: int, chars: int, detail: str):
        self.purpose = purpose
        self.chunks = chunks
        self.chars = chars
        super().__init__(
            f"LLM stream for '{purpose}' degenerate after {chunks} chunks "
            f"({chars} content chars): {detail}")


@dataclass(frozen=True)
class GuardBounds:
    """The four defense lines' knobs. Engagement-configurable via env,
    never unbounded (PORT-07 contract)."""
    total_timeout_s: float = 600.0     # AEGIS_LLM_TOTAL_TIMEOUT_S
    idle_timeout_s: float = 90.0       # AEGIS_LLM_IDLE_TIMEOUT_S (parsed-chunk gap)
    max_attempts: int = 2              # AEGIS_LLM_MAX_ATTEMPTS (logical)
    backoff_s: float = 2.0             # AEGIS_LLM_RETRY_BACKOFF_S
    cancel_grace_s: float = 3.0
    breaker_threshold: int = 3         # AEGIS_LLM_BREAKER_THRESHOLD
    # Sanitizer line 4: a stream that produced at least this many chunks
    # but less than this many content characters is degenerate; a delta
    # byte-identical to the previous one this many times in a row is
    # looping. Both numbers derived from the live regression (hundreds of
    # `|>think<|sep|>` fragments, zero usable content).
    degenerate_min_chunks: int = 200
    degenerate_max_chars: int = 64
    degenerate_repeat_streak: int = 100

    @classmethod
    def from_env(cls) -> "GuardBounds":
        def _f(name: str, default: float) -> float:
            try:
                return float(os.environ.get(name, "") or default)
            except (TypeError, ValueError):
                return default

        def _i(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, "") or default)
            except (TypeError, ValueError):
                return default

        return cls(
            total_timeout_s=max(1.0, _f("AEGIS_LLM_TOTAL_TIMEOUT_S", 600.0)),
            idle_timeout_s=max(1.0, _f("AEGIS_LLM_IDLE_TIMEOUT_S", 90.0)),
            max_attempts=max(1, _i("AEGIS_LLM_MAX_ATTEMPTS", 2)),
            backoff_s=max(0.0, _f("AEGIS_LLM_RETRY_BACKOFF_S", 2.0)),
            cancel_grace_s=max(0.5, _f("AEGIS_LLM_CANCEL_GRACE_S", 3.0)),
            breaker_threshold=max(1, _i("AEGIS_LLM_BREAKER_THRESHOLD", 3)),
            degenerate_min_chunks=max(
                10, _i("AEGIS_SANITIZER_MIN_CHUNKS", 200)),
            degenerate_max_chars=max(
                0, _i("AEGIS_SANITIZER_MAX_CHARS", 64)),
            degenerate_repeat_streak=max(
                2, _i("AEGIS_SANITIZER_REPEAT_STREAK", 100)),
        )


class Breaker:
    """Per-purpose consecutive-failure counters (mirrors the compaction
    breaker's semantics: counted -> open -> fail fast; success resets)."""

    def __init__(self, threshold: int = 3):
        self.threshold = max(1, int(threshold))
        self._failures: Dict[str, int] = {}

    def failures(self, key: str) -> int:
        return self._failures.get(key, 0)

    def is_open(self, key: str) -> bool:
        return self.failures(key) >= self.threshold

    def check(self, key: str) -> None:
        if self.is_open(key):
            raise LLMBreakerOpenError(key, self.failures(key), self.threshold)

    def record(self, key: str, ok: bool) -> int:
        if ok:
            self._failures[key] = 0
        else:
            self._failures[key] = self._failures.get(key, 0) + 1
        return self._failures[key]

    def state(self) -> Dict[str, int]:
        return dict(self._failures)


class _DegenerateWatch:
    """Line 4: content-free / looping delta detection."""

    def __init__(self, bounds: GuardBounds):
        self.b = bounds
        self.chunks = 0
        self.chars = 0
        self._last_text = ""
        self._streak = 0

    def observe(self, chunk: Chunk) -> Optional[str]:
        """Returns a human detail string when the stream is degenerate."""
        self.chunks += 1
        text = getattr(chunk, "text", "") or ""
        self.chars += len(text)
        if self.chunks >= self.b.degenerate_min_chunks and \
                self.chars < self.b.degenerate_max_chars:
            return (f"content-free stream: {self.chunks} chunks, "
                    f"{self.chars} content chars")
        if text and text == self._last_text:
            self._streak += 1
            if self._streak >= self.b.degenerate_repeat_streak:
                return (f"looping delta x{self._streak}: "
                        f"{text[:40]!r}")
        else:
            self._streak = 0
        self._last_text = text
        return None


async def _pump(factory: Callable[[], AsyncIterator[Chunk]], q: asyncio.Queue):
    """Child task: drains the underlying stream into an unbounded queue.
    put() never blocks (unbounded), so the pump only ever parks on the
    stream itself — exactly what the bounds watch."""
    try:
        async for c in factory():
            await q.put(("chunk", c))
        await q.put(("done", None))
    except BaseException as exc:  # noqa: BLE001 — pumped, not raised here
        await q.put(("error", exc))


class LLMGuard:
    """The loop invariant every model call goes through (no call site may
    bypass it — main loop, subagents, side queries alike)."""

    def __init__(self, *, bounds: Optional[GuardBounds] = None,
                 journal: Any = None, observer: Any = None):
        self.bounds = bounds or GuardBounds.from_env()
        self.breaker = Breaker(self.bounds.breaker_threshold)
        self.journal = journal
        self.observer = observer

    # ------------------------------------------------------- journaling

    def _j(self, kind: str, data: Dict[str, Any]) -> None:
        if self.journal is None:
            return
        try:
            self.journal.append(kind, data)
        except Exception:
            try:
                self.journal.append("error", {
                    "extractor": "llm_guard",
                    "reason": f"journal write failed for {kind}"})
            except Exception:
                pass

    # ---------------------------------------------------- bounded stream

    async def call_stream(self, factory: Callable[[], AsyncIterator[Chunk]],
                          *, purpose: str = "llm", model: str = "",
                          turn: int = 0, messages=None,
                          span_id: Optional[str] = None
                          ) -> AsyncIterator[Chunk]:
        """Consume factory() under all four defense lines, re-yielding
        its chunks. Retries (logical attempts) with backoff; raises the
        underlying error after the final failed attempt, or
        LLMCallTimeoutError / LLMDegenerateStreamError /
        LLMBreakerOpenError per the contracts above."""
        b = self.bounds
        span = span_id or uuid.uuid4().hex[:12]
        self.breaker.check(purpose)          # line 3: fail fast when open

        n_msgs = 0
        try:
            n_msgs = len(list(messages)) if messages is not None else 0
        except Exception:
            pass
        if self.observer is not None:
            try:
                self.observer.on_llm_start(span, model=str(model or "?"),
                                           turn=turn, messages=messages)
            except Exception:
                pass

        backoff = b.backoff_s
        last_exc: Optional[BaseException] = None
        first_token_seen = False

        for attempt in range(1, b.max_attempts + 1):
            t0 = time.monotonic()
            # llm_call is PER ATTEMPT (the journal contract: "attempt
            # started") and carries the same attempt number its
            # llm_call_end pair carries — the SLO latency plane pairs
            # on (purpose, turn, attempt)
            self._j("llm_call", {"purpose": purpose, "attempt": attempt,
                                 "attempts": b.max_attempts,
                                 "total_timeout_s": b.total_timeout_s,
                                 "idle_timeout_s": b.idle_timeout_s,
                                 "n_messages": n_msgs,
                                 "model": str(model)})
            watch = _DegenerateWatch(b)
            reply_chunk: Optional[Chunk] = None
            try:
                async for kind, payload in self._bounded_attempt(
                        factory, attempt=attempt, t0=t0, watch=watch,
                        purpose=purpose):
                    if kind == "chunk":
                        chunk: Chunk = payload
                        if not first_token_seen and chunk.text:
                            first_token_seen = True
                            if self.observer is not None:
                                try:
                                    self.observer.on_llm_first_token(
                                        span, chunk=chunk.text[:80])
                                except Exception:
                                    pass
                        if chunk.kind == "reply":
                            reply_chunk = chunk
                        yield chunk
                # attempt completed without a bound trip
                if reply_chunk is not None and reply_chunk.reply is not None:
                    r = reply_chunk.reply
                    self._on_attempt_ok(purpose, attempt, t0, span, r)
                else:
                    self._j("llm_call_end", {
                        "purpose": purpose, "attempt": attempt,
                        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                        "outcome": "error",
                        "error": "stream ended without an assembled reply"})
                self.breaker.record(purpose, True)
                return

            except (asyncio.CancelledError, GeneratorExit):
                raise
            except BaseException as exc:      # noqa: BLE001 — retried below
                last_exc = exc
                self._j("llm_call_end", {
                    "purpose": purpose, "attempt": attempt,
                    "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                    "outcome": "error",
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                if self.observer is not None:
                    try:
                        self.observer.on_llm_error(span, exc)
                    except Exception:
                        pass

            if attempt < b.max_attempts:
                self._j("llm_retry", {"purpose": purpose,
                                      "next_attempt": attempt + 1,
                                      "backoff_s": backoff})
                if self.observer is not None:
                    try:
                        self.observer.on_llm_retry(span, attempt=attempt,
                                                   error=last_exc,
                                                   backoff_s=backoff)
                    except Exception:
                        pass
                await asyncio.sleep(backoff)
                backoff *= 2.0

        # exhausted: breaker accounting (line 3), then re-raise
        failures = self.breaker.record(purpose, False)
        self._j("llm_breaker", {"purpose": purpose,
                                "consecutive_failures": failures,
                                "threshold": self.breaker.threshold,
                                "open": failures >= self.breaker.threshold})
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"llm guard exhausted attempts for {purpose!r} "
                           f"without an error")  # unreachable in practice

    # ------------------------------------------------- one bounded attempt

    async def _bounded_attempt(self, factory, *, attempt: int, t0: float,
                               watch: _DegenerateWatch, purpose: str
                               ) -> AsyncIterator[tuple]:
        b = self.bounds
        q: asyncio.Queue = asyncio.Queue()
        task = asyncio.ensure_future(_pump(factory, q))

        def _el() -> float:
            return round((time.monotonic() - t0) * 1000, 1)

        try:
            while True:
                now = time.monotonic()
                remaining_total = (t0 + b.total_timeout_s) - now
                if remaining_total <= 0:
                    raise LLMCallTimeoutError(purpose, b.total_timeout_s,
                                              attempt, reason="total")
                wait_s = min(remaining_total, b.idle_timeout_s)
                getter = asyncio.ensure_future(q.get())
                done, _ = await asyncio.wait({getter}, timeout=wait_s)
                if not done:
                    getter.cancel()
                    if (time.monotonic() - t0) >= b.total_timeout_s:
                        raise LLMCallTimeoutError(purpose,
                                                  b.total_timeout_s,
                                                  attempt, reason="total")
                    raise LLMCallTimeoutError(purpose, b.idle_timeout_s,
                                              attempt, reason="idle")

                kind, payload = getter.result()
                if kind == "done":
                    return
                if kind == "error":
                    raise payload
                # kind == "chunk" — line 4: degenerate detection
                deg = watch.observe(payload)
                if deg is not None:
                    exc = LLMDegenerateStreamError(purpose, watch.chunks,
                                                   watch.chars, deg)
                    self._j("llm_call_end", {
                        "purpose": purpose, "attempt": attempt,
                        "elapsed_ms": _el(), "outcome": "degenerate",
                        "error": deg, "chunks": watch.chunks,
                        "content_chars": watch.chars})
                    raise exc
                yield ("chunk", payload)
        except (LLMCallTimeoutError, LLMDegenerateStreamError) as trip:
            # line 2: caller-side guarantee — cancel the child, verify the
            # cancellation completed, journal the abandon when it did not
            self._j("llm_call_end", {
                "purpose": purpose, "attempt": attempt,
                "elapsed_ms": _el(), "outcome": "timeout",
                "error": f"{type(trip).__name__}({trip.reason if isinstance(trip, LLMCallTimeoutError) else 'degenerate'})"})
            task.cancel()
            try:
                await asyncio.wait({task}, timeout=b.cancel_grace_s)
            except Exception:
                pass
            if not task.done() or task.cancelled():
                self._j("llm_abandon", {
                    "purpose": purpose, "attempt": attempt,
                    "elapsed_ms": _el(),
                    "note": ("child task abandoned (cancellation did not "
                             "complete within grace); transport timeouts "
                             "will reclaim it")})
            else:
                exc = task.exception()
                if exc is not None:
                    self._j("llm_call_end", {
                        "purpose": purpose, "attempt": attempt,
                        "elapsed_ms": _el(),
                        "outcome": "late_error_after_cancel",
                        "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            raise
        except (asyncio.CancelledError, GeneratorExit):
            task.cancel()
            raise
        finally:
            if not task.done():
                task.cancel()

    # ------------------------------------------------------------ helpers

    def _on_attempt_ok(self, purpose: str, attempt: int, t0: float,
                       span: str, reply: Any) -> None:
        self._j("llm_call_end", {
            "purpose": purpose, "attempt": attempt,
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
            "outcome": "ok",
            "model": str(getattr(reply, "model", "") or ""),
            "usage": dict(getattr(reply, "usage", {}) or {}),
            "finish_reason": str(getattr(reply, "finish_reason", "") or ""),
            "n_tool_uses": len(getattr(reply, "tool_uses", []) or [])})
        if self.observer is not None:
            try:
                self.observer.on_llm_end(
                    span,
                    usage=dict(getattr(reply, "usage", {}) or {}),
                    finish=str(getattr(reply, "finish_reason", "") or ""),
                    output=str(getattr(reply, "text", "") or ""))
            except Exception:
                pass


async def call_llm_bounded(factory, *, purpose: str = "llm",
                           bounds: Optional[GuardBounds] = None,
                           journal: Any = None, observer: Any = None,
                           model: str = "", turn: int = 0,
                           messages=None) -> AsyncIterator[Chunk]:
    """Convenience one-shot: build a guard and stream through it (the
    3.7.3 call_llm_bounded analog, stream-shaped)."""
    guard = LLMGuard(bounds=bounds, journal=journal, observer=observer)
    async for c in guard.call_stream(factory, purpose=purpose, model=model,
                                     turn=turn, messages=messages):
        yield c
