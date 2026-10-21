"""hypervisor.query — THE loop (P1).

Skeleton 9-1 of the ratified blueprint; the new control plane (the grid
it replaces is DELETE-01). One async generator owns every decision to
continue — nothing else in the system decides control flow (principle
1). Modeled on the reference queryLoop (query.ts:241-1729):

  * single mutable state object; every continue path rewrites state and
    falls through the `while True` — never recursion
  * the 7-step pre-flight pipeline runs EVERY iteration before the
    model is called (principle 6): compact boundary -> tool-result
    budget -> microcompact -> autocompact -> blocking gate -> assembly
    (P1 ships the pipeline SHAPE; the fold/microcompact engines land in
    P2 as injected dependencies — the loop never changes when they do)
  * tool_use is the SOLE exit signal: a comment at query.ts:553-556
    states stop_reason is unreliable and must not be trusted; the loop
    ends when the model stops calling tools, not when it says it stopped
  * the output ladder: one clean escalation to the 64K ceiling, then 3
    resume-mid-thought continuations (isMeta user message) before
    surfacing the error (query.ts:1188-1256). The recovery counter
    resets on natural next_turn and is DELIBERATELY preserved across
    the ladder's own continues
  * the turn watchdog bounds each iteration (asyncio.timeout hard bound
    + phase-boundary activity notes driving the debug kit's stall
    detector) — no organ can park the system silently; every trip
    writes a turn_watchdog journal event
  * the L3 side query (P3, REFACTOR-04) rides the same injection
    pattern: deps.side_query runs between the blocking gate and zone
    assembly, is journaled, and NEVER gates assembly (J4 — failures
    degrade to 'brief alone')
  * dependencies are injected (production_deps()); the same loop serves
    the CLI, the headless runner and (P3) every subagent

Transition vocabulary (journal loop_transition / timeline mirrors):
  next_turn - max_output_tokens_escalate - max_output_tokens_recovery -
  autocompact (P2) - reactive_compact_retry (P2, reserved) -
  stop_hook_blocking (P4, reserved) - token_budget_continuation (P4,
  reserved). Terminal reasons: end_turn - max_turns - prompt_too_long -
  turn_watchdog - model_error - aborted.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Sequence

from .adapters.openai import Chunk, ModelReply, OpenAICompatClient
from .context.assemble import (after_compact_boundary, assemble_prompt,
                                journal_channel_message)
from .guard import LLMGuard

# ─── env-tuned loop knobs (boot-once resolution; no mid-session reads) ─


def _env_f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


def _env_i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


TURN_BUDGET_S = max(30.0, _env_f("AEGIS_TURN_BUDGET_S", 1800.0))
CONTEXT_WINDOW = max(4096, _env_i("AEGIS_CONTEXT_WINDOW", 131072))
MAX_OUTPUT_TOKENS = max(256, _env_i("AEGIS_MAX_OUTPUT_TOKENS", 8192))
MAX_OUTPUT_TOKENS_CEILING = max(
    MAX_OUTPUT_TOKENS, _env_i("AEGIS_MAX_OUTPUT_TOKENS_CEILING", 65536))
RECOVERY_CONTINUATIONS = max(
    0, _env_i("AEGIS_RECOVERY_CONTINUATIONS", 3))
BLOCKING_RATIO = min(0.999, max(0.5, _env_f("AEGIS_BLOCKING_RATIO", 0.985)))


# ─── events ────────────────────────────────────────────────────────────

@dataclass
class LoopEvent:
    """Everything the loop yields. Consumers (CLI renderer, subagent
    wrappers, test fakes) see the stream through these."""
    kind: str                        # text_delta | transition | tool_result
                                     # | completed | error | prompt_too_long
                                     # | watchdog | usage
    text: str = ""
    transition: str = ""
    turn: int = 0
    reason: str = ""
    tool_results: Optional[List[Dict[str, Any]]] = None
    reply: Optional[ModelReply] = None
    detail: Optional[Dict[str, Any]] = None


# ─── state ─────────────────────────────────────────────────────────────

@dataclass
class CompactTracking:
    """Compaction bookkeeping the loop carries across turns (the P2 fold
    engines update it through deps; the shape ships in P1)."""
    folds: int = 0
    trims: int = 0
    last_boundary_seq: Optional[int] = None


@dataclass
class LoopState:
    """The single mutable state object. Every continue path calls
    .next() with the new messages and the canonical transition name."""
    messages: List[Dict[str, Any]]
    turn_count: int = 0
    compact: CompactTracking = field(default_factory=CompactTracking)
    output_recovery: int = 0        # max_output_tokens ladder counter
    stop_hook_active: bool = False  # P4: CC recursion guard (set when a
                                    # stop-hook block re-enters the loop)
    transition: str = "init"

    def next(self, *, messages: List[Dict[str, Any]],
             transition: str = "next_turn",
             output_recovery: Optional[int] = None) -> "LoopState":
        return LoopState(
            messages=messages,
            turn_count=self.turn_count + 1,
            compact=self.compact,
            output_recovery=(self.output_recovery
                             if output_recovery is None
                             else output_recovery),
            stop_hook_active=self.stop_hook_active,
            transition=transition)


@dataclass
class QueryParams:
    """Everything the loop needs. The stop_hook (P4) is operator
    configuration — never model-reachable — consulted at the end_turn
    decision before a natural stop is accepted."""
    system_prompt: str
    tools: Sequence[Any]
    initial_messages: List[Dict[str, Any]]
    ctx: Any                          # ToolContext
    max_turns: Optional[int] = None   # None = no ceiling (main loop)
    purpose: str = "main"
    max_output_tokens: int = MAX_OUTPUT_TOKENS
    stop_hook: Any = None             # P4: StopHookConfig (operator-side)


# ─── injected dependencies ─────────────────────────────────────────────

class LoopDeps:
    """The loop's injectable boundary (productionDeps() analog). Tests
    substitute fakes; P2's context engine (budget + compaction) and
    zone assembly ride the SAME slots without touching the loop."""

    async def call_model(self, messages: List[Dict[str, Any]],
                         tools: Sequence[Any], max_tokens: int,
                         turn: int) -> AsyncIterator[Chunk]:
        raise NotImplementedError

    def apply_tool_result_budget(self, messages: List[Dict[str, Any]]
                                ) -> List[Dict[str, Any]]:
        return messages              # P2: per-tool caps cascade

    async def microcompact(self, messages: List[Dict[str, Any]], ctx: Any
                           ) -> List[Dict[str, Any]]:
        return messages              # P2: content-clear old tool results

    async def autocompact(self, messages: List[Dict[str, Any]], ctx: Any
                          ) -> tuple[List[Dict[str, Any]], bool]:
        return messages, False       # P2: window-relative fold + breaker

    async def side_query(self, messages: List[Dict[str, Any]], ctx: Any
                         ) -> List[str]:
        return []                    # P3: L3 pre-expansion (never gates)

    def estimate_tokens(self, messages: List[Dict[str, Any]]) -> int:
        """P1 heuristic fallback; the budget manager (P2) replaces
        this without touching the loop."""
        total = 0
        for m in messages:
            c = m.get("content")
            if isinstance(c, str):
                total += len(c) // 4
            elif isinstance(c, list):
                for b in c:
                    total += (len(str(b.get("text", b.get("content", ""))))
                              // 4) + 8
            total += 4
        return total

    def blocking_limit(self) -> int:
        """The hard prompt-size stop (checked after the fold ladder).
        The budget manager derives this from the model's resolved
        window; the P1 fallback uses the env knob."""
        return int(CONTEXT_WINDOW * BLOCKING_RATIO)

    def new_id(self) -> str:
        return _uuid.uuid4().hex[:12]


class ProductionDeps(LoopDeps):
    """Model calls through the guard (no call site may bypass it) on
    the OpenAI-compatible adapter; the P2 context engine rides the
    same slots (budget + compaction ladder)."""

    def __init__(self, *, adapter: OpenAICompatClient,
                 guard: Optional[LLMGuard] = None,
                 budget: Any = None, engine: Any = None,
                 sidequery: Any = None):
        self.adapter = adapter
        self.guard = guard or LLMGuard()
        self.budget = budget
        self.engine = engine
        self.sidequery = sidequery

    async def call_model(self, messages, tools, max_tokens, turn):
        async def _factory():
            async for c in self.adapter.stream_chat(
                    messages=messages, tools=tools,
                    max_tokens=max_tokens):
                yield c
        async for c in self.guard.call_stream(
                _factory, purpose="main", model=self.adapter.model,
                turn=turn, messages=messages):
            yield c

    def apply_tool_result_budget(self, messages):
        if self.engine is None:
            return messages
        return self.engine.apply_tool_result_budget(messages)

    async def microcompact(self, messages, ctx):
        if self.engine is None:
            return messages
        return await self.engine.microcompact(messages, ctx)

    async def autocompact(self, messages, ctx):
        if self.engine is None:
            return messages, False
        return await self.engine.autocompact(messages, ctx)

    async def side_query(self, messages, ctx):
        if self.sidequery is None:
            return []
        return await self.sidequery(messages, ctx)

    def estimate_tokens(self, messages):
        if self.budget is not None:
            return int(self.budget.counter(messages))
        return super().estimate_tokens(messages)

    def blocking_limit(self) -> int:
        if self.budget is not None:
            return int(self.budget.blocking_at)
        return super().blocking_limit()


def production_deps(adapter: Optional[OpenAICompatClient] = None,
                    guard: Optional[LLMGuard] = None,
                    budget: Any = None, engine: Any = None,
                    sidequery: Any = None
                    ) -> ProductionDeps:
    return ProductionDeps(adapter=adapter or OpenAICompatClient.from_env(),
                          guard=guard, budget=budget, engine=engine,
                          sidequery=sidequery)


# ─── assembly (P2: zone assembly lives in context/assemble.py; the
#    top-of-module re-export keeps the P1 import surface stable) ──


class _TurnWatchdog(Exception):
    """Internal: the turn's wall-clock budget was exceeded."""

    def __init__(self, elapsed_s: float):
        self.elapsed_s = float(elapsed_s)
        super().__init__(f"turn exceeded {TURN_BUDGET_S:.0f}s "
                         f"after {elapsed_s:.1f}s")


def _note_activity(turn: int, phase: str) -> None:
    """Feed the debug kit's stall detector (fail-silent when the kit
    is not installed)."""
    try:
        from .debug import loop_monitor
        loop_monitor.note_turn_activity(turn, phase)
    except Exception:
        pass


# ─── THE loop ──────────────────────────────────────────────────────────

async def query_loop(p: QueryParams,
                     deps: LoopDeps) -> AsyncIterator[LoopEvent]:
    """The only control plane. Yields LoopEvents as they happen; every
    continue path journals its canonical transition."""
    ctx = p.ctx
    obs = getattr(ctx, "observer", None)
    journal = getattr(ctx, "journal", None)
    session = (ctx.extra or {}).get("session") if ctx.extra else None
    stats = {"turns": 0, "tool_calls": 0,
             "prompt_tokens": 0, "completion_tokens": 0}

    def _transition(name: str, *, trigger: str = "", **detail):
        """Journal + timeline + outward event for one state-machine
        move (the CC transition-table equivalent)."""
        if journal is not None:
            try:
                journal.record_loop_transition(
                    name, trigger=trigger, turn=stats["turns"],
                    detail=detail or None)
            except Exception:
                pass
        if obs is not None:
            try:
                obs.on_transition(name, turn=stats["turns"], **detail)
            except Exception:
                pass

    if obs is not None:
        obs.on_loop_start(turn=0)
    if session is not None:
        # the transcript chain starts with the objective(s) the caller
        # handed the loop — the session is the loop's to own
        for m in p.initial_messages:
            session.append({"type": str(m.get("role", "user")),
                            "message": m})
        session.record_meta("boot", {"purpose": p.purpose,
                                     "tools": len(p.tools or [])})
    if journal is not None:
        # PORT-06: the message events Zone W reconstruction replays
        # (channel members in landing order — objective first)
        for m in p.initial_messages:
            journal_channel_message(journal, m, source="user")
    _transition("init", to="idle")

    state = LoopState(messages=list(p.initial_messages))
    current_max_tokens = p.max_output_tokens

    try:
        while True:
            # ── ceilings and abort ─────────────────────────────────
            if ctx.abort.is_set():
                _transition("aborted", trigger="operator")
                yield LoopEvent("completed", reason="aborted",
                                turn=stats["turns"])
                return
            if p.max_turns is not None and state.turn_count >= p.max_turns:
                _transition("max_turns", trigger="ceiling")
                yield LoopEvent("completed", reason="max_turns",
                                turn=stats["turns"], detail=dict(stats))
                return

            stats["turns"] = state.turn_count + 1
            ctx.turn = stats["turns"]
            turn_t0 = time.monotonic()
            turn_deadline = turn_t0 + TURN_BUDGET_S
            _note_activity(stats["turns"], "preflight")

            # ── the turn watchdog: no organ can park the system
            # silently. The model call is total-bounded by the guard
            # (PORT-07); tool dispatch is hard-bounded by the turn's
            # remaining budget below; the deadline is re-checked at
            # every phase boundary and any overshoot is journaled
            # (never silent) before the loop terminates.
            try:
                # ── 7-step pre-flight pipeline (exact order) ────
                msgs = after_compact_boundary(state.messages)
                msgs = deps.apply_tool_result_budget(msgs)
                msgs = await deps.microcompact(msgs, ctx)
                msgs, folded = await deps.autocompact(msgs, ctx)
                if folded:
                    state.compact.folds += 1
                    _transition("autocompact", trigger="threshold")
                if deps.estimate_tokens(msgs) >= deps.blocking_limit():
                    _transition("prompt_too_long",
                                trigger="blocking_limit")
                    yield LoopEvent("prompt_too_long",
                                    turn=stats["turns"])
                    return
                # ── the L3 pre-expansion step (P3, REFACTOR-04): a
                # journaled, guard-bounded side call that may write
                # Zone T drilldown attachments. Strictly optional —
                # never gates assembly (J4 discipline in-engine).
                await deps.side_query(msgs, ctx)
                prompt = assemble_prompt(p.system_prompt, msgs, ctx=ctx)

                # ── model call (guard-bounded, streaming) ──────
                _note_activity(stats["turns"], "model")
                reply: Optional[ModelReply] = None
                async for chunk in deps.call_model(
                        prompt, p.tools, current_max_tokens,
                        stats["turns"]):
                    if chunk.kind == "text" and chunk.text:
                        yield LoopEvent("text_delta", text=chunk.text,
                                        turn=stats["turns"])
                    elif chunk.kind == "reply" and chunk.reply is not None:
                        reply = chunk.reply
                if reply is None:
                    _transition("model_error", trigger="no_reply")
                    yield LoopEvent("error",
                                    reason="model_error: stream "
                                           "ended without a reply",
                                    turn=stats["turns"])
                    return
                u = reply.usage or {}
                stats["prompt_tokens"] += int(u.get("prompt_tokens", 0))
                stats["completion_tokens"] += int(
                    u.get("completion_tokens", 0))
                if session is not None:
                    session.record_assistant(reply.message)
                if journal is not None:
                    journal_channel_message(journal, reply.message,
                                            source="assistant")
                    try:
                        journal.append("agent_message", {
                            "purpose": p.purpose,
                            "text": (reply.text or "")[:400],
                            "n_tool_uses": len(reply.tool_uses),
                            "finish_reason": reply.finish_reason},
                            actor="loop")
                    except Exception:
                        pass
                    # the SLO token plane (journal contract: "one loop
                    # invocation finished"): one turn_end per assembled
                    # reply carrying the CUMULATIVE counters — the final
                    # event holds the engagement totals (the audit takes
                    # max() over these)
                    try:
                        journal.append("turn_end", {
                            "prompt_tokens": stats["prompt_tokens"],
                            "completion_tokens":
                                stats["completion_tokens"],
                            "tool_calls": stats["tool_calls"],
                            "finish_reason": reply.finish_reason},
                            actor="loop", turn=stats["turns"])
                    except Exception:
                        pass

                # ── the output ladder (query.ts:1188-1256) ─────
                if reply.finish_reason == "length" and \
                        not reply.tool_uses:
                    if state.output_recovery == 0 and \
                            current_max_tokens < MAX_OUTPUT_TOKENS_CEILING:
                        current_max_tokens = MAX_OUTPUT_TOKENS_CEILING
                        state = state.next(
                            messages=[*msgs, reply.message],
                            transition="max_output_tokens_escalate",
                            output_recovery=1)
                        _transition("max_output_tokens_escalate",
                                    trigger="finish_reason=length",
                                    max_tokens=current_max_tokens)
                        yield LoopEvent(
                            "transition",
                            transition="max_output_tokens_escalate",
                            turn=stats["turns"])
                        continue
                    if state.output_recovery <= RECOVERY_CONTINUATIONS:
                        n = state.output_recovery
                        state = state.next(
                            messages=[*msgs, reply.message, {
                                "role": "user",
                                "content": [{"type": "text", "text":
                                             "Continue your response "
                                             "exactly where it was cut "
                                             "off. Do not repeat prior "
                                             "output."}],
                                "isMeta": True}],
                            transition="max_output_tokens_recovery",
                            output_recovery=n + 1)
                        _transition(
                            "max_output_tokens_recovery",
                            trigger="finish_reason=length",
                            continuation=n + 1)
                        yield LoopEvent(
                            "transition",
                            transition="max_output_tokens_recovery",
                            turn=stats["turns"])
                        continue
                    _transition("model_error",
                                trigger="output_ladder_exhausted")
                    yield LoopEvent(
                        "error",
                        reason="model_error: output ladder exhausted "
                               "(1 escalation + "
                               f"{RECOVERY_CONTINUATIONS} continuations)",
                        turn=stats["turns"])
                    return

                # ── tool_use is the SOLE exit signal ───────────
                if not reply.tool_uses:
                    # ── the stop-hook seam (P4, CC parity): the
                    # operator's last-chance veto before a natural
                    # stop is accepted. A block feeds the reason back
                    # and continues; stop_hook_active enforces the
                    # single re-entry recursion guard; every outcome
                    # is journaled and hook failure never wedges the
                    # loop (error/timeouts are audited allows).
                    stop_cfg = getattr(p, "stop_hook", None)
                    if stop_cfg is not None and \
                            getattr(stop_cfg, "active", lambda: False)():
                        from .hooks import (block_feedback_message,
                                            journal_hook_run,
                                            run_stop_hook, stop_payload)
                        last_text = (reply.text or "")[:8000]
                        active = state.stop_hook_active
                        payload = stop_payload(
                            last_assistant_message=last_text,
                            stop_hook_active=active,
                            turn=stats["turns"],
                            purpose=p.purpose)
                        decision = await run_stop_hook(stop_cfg, payload)
                        journal_hook_run(journal, decision, payload)
                        _transition("stop_hook", trigger="end_turn",
                                    decision=decision.decision,
                                    reason=(decision.reason or "")[:200])
                        if decision.blocks and not active:
                            feedback = block_feedback_message(
                                decision.reason)
                            # the block feedback IS a channel member:
                            # journal it or Zone W reconstruction loses
                            # it (PORT-06 discipline — the P4 harness
                            # caught exactly this)
                            journal_channel_message(
                                journal, feedback, source="stop_hook")
                            state = state.next(
                                messages=[*msgs, reply.message,
                                          feedback],
                                transition="stop_hook_blocked")
                            state.stop_hook_active = True
                            _transition("stop_hook_blocked",
                                        trigger="hook_block",
                                        reason=(decision.reason or
                                                "")[:200])
                            yield LoopEvent(
                                "transition",
                                transition="stop_hook_blocked",
                                turn=stats["turns"])
                            continue
                        if decision.blocks and active:
                            # recursion guard: a second block while
                            # active completes anyway (journaled)
                            _transition("stop_hook_recursion_guard",
                                        trigger="block_while_active")
                    # recovery counter resets on natural completion
                    _transition("end_turn", trigger="no_tool_uses")
                    yield LoopEvent("completed", reason="end_turn",
                                    turn=stats["turns"], reply=reply,
                                    detail=dict(stats))
                    return

                # ── phase-boundary deadline check (the guard
                # bounded the call itself; overshoot is journaled
                # and terminates the loop — never silent)
                if time.monotonic() >= turn_deadline:
                    raise _TurnWatchdog(time.monotonic() - turn_t0)

                # ── tool execution as children of the loop ─────
                _note_activity(stats["turns"], "tools")
                from .tools.base import dispatch_tools
                remaining = max(1.0, turn_deadline - time.monotonic())
                try:
                    results = await asyncio.wait_for(
                        dispatch_tools(reply.tool_uses, ctx),
                        timeout=remaining)
                except asyncio.TimeoutError:
                    raise _TurnWatchdog(time.monotonic() - turn_t0)
                stats["tool_calls"] += len(results)
                for r in results:
                    yield LoopEvent("tool_result", turn=stats["turns"],
                                    tool_results=[r])
                if session is not None:
                    session.record_tool_results(results)
                if journal is not None:
                    # the channel member is ONE tool-result carrier
                    # message (the state rewrite appends it whole)
                    journal_channel_message(
                        journal, {"role": "user", "content": results},
                        source="tool_results")
                if ctx.abort.is_set():
                    _transition("aborted", trigger="operator")
                    yield LoopEvent("completed", reason="aborted",
                                    turn=stats["turns"])
                    return
                if time.monotonic() >= turn_deadline:
                    raise _TurnWatchdog(time.monotonic() - turn_t0)

                # ── state rewrite and fall through ─────────────
                state = state.next(
                    messages=[*msgs, reply.message,
                              {"role": "user", "content": results}],
                    transition="next_turn")
                _transition("next_turn",
                            trigger="tool_results",
                            tool_calls=len(results))
                yield LoopEvent("transition", transition="next_turn",
                                turn=stats["turns"])

            except _TurnWatchdog as trip:
                if journal is not None:
                    try:
                        journal.record_turn_watchdog(
                            turn=stats["turns"], bound_s=TURN_BUDGET_S,
                            elapsed_s=trip.elapsed_s, action="tripped",
                            detail="iteration exceeded turn budget")
                    except Exception:
                        pass
                _transition("turn_watchdog", trigger="budget",
                            elapsed_s=round(trip.elapsed_s, 1))
                yield LoopEvent("watchdog", turn=stats["turns"],
                                reason="turn budget exceeded",
                                detail={"elapsed_s": round(trip.elapsed_s, 1),
                                        "bound_s": TURN_BUDGET_S})
                return
            except (asyncio.CancelledError, GeneratorExit):
                raise
            except Exception as exc:
                # harness-level failure: auditable, then terminal — the
                # loop never silently swallows (principle 7)
                if journal is not None:
                    try:
                        journal.append("error", {
                            "where": "query_loop",
                            "error": f"{type(exc).__name__}: "
                                     f"{str(exc)[:300]}"},
                            actor="loop")
                    except Exception:
                        pass
                _transition("model_error", trigger="exception")
                yield LoopEvent("error",
                                reason=f"{type(exc).__name__}: {exc}",
                                turn=stats["turns"])
                return
    finally:
        if obs is not None:
            obs.on_loop_end(turn=stats["turns"], reason=state.transition)
        if session is not None:
            session.record_meta("note", {
                "loop_end": state.transition, "turns": stats["turns"],
                "tool_calls": stats["tool_calls"]})


# ─── P0 exit-criterion helper (kept: the empty-loop demo) ──────────────

async def empty_loop_smoke(on_event=None) -> dict:
    """P0 exit-criterion helper: run zero turns through the observability
    stack — kit install, one loop start, one transition, one end — and
    confirm the timeline + journal captured all of it."""
    from .debug import loop_events, loop_monitor
    obs = loop_events.LoopObserver()
    loop_monitor.ensure_started()
    obs.on_loop_start(turn=0)
    obs.on_transition("init", to="idle", turn=0, note="p0 smoke")
    from .persist.journal import Journal
    j = Journal(on_event=on_event) if on_event is not None else None
    if j is not None:
        j.record_loop_transition("init", to="idle", turn=0,
                                 detail={"smoke": True})
    obs.on_loop_end(turn=0, reason="p0 smoke complete")
    return {"observer": obs.label, "depth": obs.depth}
