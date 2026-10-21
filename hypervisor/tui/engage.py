"""hypervisor.tui.engage — the engine bridge (UX-01).

Mirrors hypervisor.cli.main's engagement chain module-call for
module-call (kit install -> scope -> journal boot -> registry ->
gate -> session -> EKD -> brief renderer -> fingerprint monitor ->
adapter -> budget -> guard -> side query -> stop hook -> query_loop)
so a TUI engagement IS a CLI engagement: same journal events, same
permission decisions, same session records, same EKD deltas.

Zero display-data loss, by construction: the LoopEvent stream the
headless line renderer consumes is consumed here unchanged — plus
three things the line renderer cannot show, all sourced from the
journal's on_event tap (no engine changes):

  * scope-gate DENIALS rendered live (the CLI shows tool results
    only after execution; the TUI shows the gate refusing first)
  * tool NAMES paired onto results (journal tool_call events carry
    the name the LoopEvent's result dict does not)
  * the live EKD revision in the status line

Follow-up turns: the loop is stateless outside (messages, ctx); a
follow-up rebuilds QueryParams over the session-reconstructed
channel + the new user message, reusing the same ctx (EKD, briefs,
budget, guard) — the CC continuation shape.

Aborts: soft (ctx.abort.set() — the engine's own operator-abort
contract, journaled reason=aborted, honored at tool boundaries) and
hard (stop consuming; the loop's GeneratorExit path is designed for
it). Adapter close + EKD persist always run in the worker's finally.
"""
from __future__ import annotations

import asyncio
import os
import re
import threading
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from . import render as R

_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ANSI_ESC_RE = re.compile(r"\x1b[@-Z\\-_]")
_C1_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_stream(text: str) -> str:
    """Model output is untrusted: strip ANSI/C1/control chars so the
    stream can never drive the terminal. Newlines and tabs survive."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_CSI_RE.sub("", text)
    text = _ANSI_ESC_RE.sub("", text)
    return _C1_RE.sub("", text)


class Engagement:
    """One armed engagement context; survives across follow-up turns."""

    def __init__(self, app) -> None:
        self.app = app
        self.started = False          # chain booted at least once
        self.running = False
        self.turn = 0
        self.total_tokens = 0
        self.autocompacts = 0
        self.rev = 0
        self.abort_soft = threading.Event()
        self.abort_hard = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.ctx: Any = None
        self.adapter: Any = None
        self.ekd: Any = None
        self.journal: Any = None
        self.session: Any = None
        self._deps: Any = None
        self._names: Deque[str] = deque()

    # ── public: start / follow-up / abort ─────────────────────────────

    def start(self, objective: str) -> None:
        """First run: boot the chain, then the loop."""
        if self.running:
            self.app.hint("an engagement is already running — Ctrl-C "
                          "aborts it first")
            return
        try:
            self._boot(objective)
        except Exception as exc:
            self.app.err(f"engagement boot failed: "
                         f"{type(exc).__name__}: {exc}")
            return
        self._spawn([{"role": "user", "content": objective}])

    def follow_up(self, text: str) -> None:
        """Continuation turn over the live context."""
        if self.running:
            self.app.hint("the agent is mid-turn — Ctrl-C aborts first")
            return
        messages = list(self.app.messages) + \
            [{"role": "user", "content": text}]
        self._spawn(messages)

    def abort(self, hard: bool = False) -> None:
        self.abort_soft.set()
        if hard:
            self.abort_hard.set()
        if self.ctx is not None and self.abort_soft.is_set():
            try:
                self.ctx.abort.set()   # engine contract: is_set() polls
            except Exception:
                pass

    # ── the chain (cli.main mirror) ───────────────────────────────────

    def _boot(self, objective: str) -> None:
        app, sf = self.app, self.app.sf
        assert sf is not None, "scope must be armed before _boot"

        # 1. observability before behavior
        if not os.environ.get("AEGIS_NO_DEBUG"):
            try:
                from ..debug import install as install_kit
                install_kit()
            except Exception:
                pass

        workspace = Path(app.workspace).resolve()
        workspace.mkdir(parents=True, exist_ok=True)

        from ..persist.journal import Journal
        from ..permissions import (PermissionEngine, ScopeManager)

        # journal with the live tap (thread-safe: append happens on
        # the worker's single thread; we only queue render ops)
        self.journal = Journal(workspace / ".aegis" / "journal",
                               on_event=self._on_journal_event)
        scope_mgr = ScopeManager(sf, journal=self.journal)

        brief_total = _env_i("AEGIS_BRIEF_TOTAL", 700)
        brief_ceiling = max(brief_total, _env_i("AEGIS_BRIEF_CEILING", 800))
        brief_topn = _env_i("AEGIS_BRIEF_TOPN", 12)
        self.journal.append("boot", {
            "engagement_id": sf.engagement_id,
            "scope_ref": sf.scope_ref(),
            "mode": sf.mode,
            "rules": len(sf.rules),
            "excludes": len(sf.excludes),
            "workspace": str(workspace),
            "render_params": {
                "brief_token_budget": brief_total,
                "brief_ceiling": brief_ceiling,
                "render_topn_entities": brief_topn,
                "scope_mode": sf.mode,
            },
        }, actor="cli")

        from ..tools.core import build_registry
        from ..tools.base import ToolContext
        registry = build_registry(include_vapt=True, include_task=True)
        registry.freeze()
        engine = PermissionEngine(scope_mgr, journal=self.journal)

        from ..persist.sessions import SessionStore
        if getattr(app, "session_id", None):
            self.session = SessionStore(workspace / ".aegis" / "sessions",
                                        session_id=app.session_id)
        else:
            self.session = SessionStore(workspace / ".aegis" / "sessions")
            app.session_id = self.session.session_id

        self.ctx = ToolContext(workspace=str(workspace), registry=registry,
                               permissions=engine, journal=self.journal,
                               extra={"session": self.session})

        from ..memory import ekd as ekd_mod
        from ..memory.brief import BriefRenderer
        from ..memory.extractors import ensure_objective
        ekd_state = ekd_mod.state_path_for(str(workspace))
        self.ekd, repaired = ekd_mod.recover(self.journal, str(workspace))

        with ekd_mod.EkdBatch(self.ekd, self.ctx, extractor="tier_a",
                              reason="objective_commit"):
            objective_id = ensure_objective(self.ekd, objective)
        try:
            self.journal.record_objective(objective)
        except Exception:
            pass

        renderer = BriefRenderer(
            journal=self.journal, token_budget=brief_total,
            hard_ceiling=brief_ceiling, topn_entities=brief_topn)

        from ..context.fingerprint import FingerprintMonitor
        self.ctx.extra["ekd"] = self.ekd
        self.ctx.extra["ekd_state_path"] = ekd_state
        self.ctx.extra["renderer"] = renderer
        self.ctx.extra["objective_id"] = objective_id
        self.ctx.extra["extractor_failures"] = \
            ekd_mod.new_extractor_failures()
        self.ctx.extra["tail_attachments"] = {}
        self.ctx.extra["episodic_residual"] = ""
        self.ctx.extra["fingerprint_monitor"] = FingerprintMonitor(
            self.journal)

        from ..adapters.openai import OpenAICompatClient
        from ..context.budget import (BudgetManager,
                                      resolve_context_window)
        from ..guard import LLMGuard
        from ..query import production_deps
        self.adapter = OpenAICompatClient.from_env()
        window = resolve_context_window(self.adapter.model)
        budget = BudgetManager(window)
        self.ctx.extra["model"] = str(self.adapter.model)
        self.ctx.extra["tool_names"] = [t.name for t in registry]

        guard = LLMGuard(journal=self.journal)
        from ..context.compact import CompactEngine, make_summarizer
        summarizer = make_summarizer(self.adapter, guard)
        self.ctx.extra["agent_runtime"] = {
            "adapter": self.adapter, "guard": guard, "budget": budget,
            "summarizer": summarizer}
        self.ctx.extra["side_query_surfaced"] = {}
        sidequery = None
        if os.environ.get("AEGIS_SIDEQUERY", "1").strip().lower() \
                in ("1", "true", "yes", "on"):
            from ..memory.sidequery import SideQueryEngine
            sidequery = SideQueryEngine(self.adapter, guard,
                                        journal=self.journal)

        from ..hooks import stop_hook_from_env
        stop_hook_cfg = stop_hook_from_env()
        if stop_hook_cfg.active():
            self.ctx.extra["subagent_stop_hook"] = stop_hook_cfg

        engine_c = CompactEngine(budget, summarizer=summarizer)
        self._deps = production_deps(adapter=self.adapter, guard=guard,
                                     budget=budget, engine=engine_c,
                                     sidequery=sidequery)
        self.started = True

        # the engagement card (the data the CLI's stderr banners carry)
        self.app.push_op(("lines", R.card([
            R.label_value("scope_ref:", sf.scope_ref()),
            R.label_value("mode:", f"{sf.mode} · {len(sf.rules)} rules "
                                   f"· {len(sf.excludes)} excludes"),
            R.label_value("context:", budget.describe()),
            R.label_value("session:", self.session.session_id),
            R.label_value("hooks:", "stop-hook armed"
                          if stop_hook_cfg.active() else "none"),
        ])))

    # ── worker ────────────────────────────────────────────────────────

    def _spawn(self, messages: List[Dict[str, Any]]) -> None:
        from ..cli import SYSTEM_PROMPT
        from ..query import QueryParams
        params = QueryParams(
            system_prompt=SYSTEM_PROMPT,
            tools=[t for t in self.ctx.registry],
            initial_messages=messages, ctx=self.ctx, max_turns=None,
            purpose="main",
            stop_hook=self.ctx.extra.get("subagent_stop_hook"))
        self.abort_soft.clear()
        self.abort_hard.clear()
        self.running = True
        self._thread = threading.Thread(target=self._worker,
                                        args=(params,), daemon=True)
        self._thread.start()

    def _worker(self, params) -> None:
        from ..query import query_loop
        push = self.app.push_op
        push(("state", "engaging"))

        async def _consume():
            async for ev in query_loop(params, self._deps):
                if self.abort_hard.is_set():
                    break
                self._on_event(ev)

        rc_reason = "aborted"
        try:
            asyncio.run(_consume())
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            push(("line", R.error_line(
                f"engagement crashed: {type(exc).__name__}: {exc}")))
        finally:
            try:
                if self.ekd is not None:
                    from ..memory import ekd as ekd_mod
                    ekd_mod.save_state(self.ekd, str(self.app.workspace))
            except Exception:
                pass
            try:
                asyncio.run(self.adapter.aclose())
            except Exception:
                pass
            self.running = False
            self._sync_messages()
            push(("state", "idle"))
            push(("completed_note",))

    def _on_event(self, ev) -> None:
        push = self.app.push_op
        kind = ev.kind
        if kind == "text_delta" and ev.text:
            push(("stream", sanitize_stream(ev.text)))
        elif kind == "tool_result":
            results = ev.tool_results or [{}]
            r = results[0]
            okay = not bool(r.get("is_error"))
            name = self._names.popleft() if self._names else "tool"
            head = str(r.get("content", ""))[:120].replace("\n", " ")
            push(("stream_flush",))
            push(("line", R.tool_line(okay, name, head)))
        elif kind == "transition":
            self.turn = ev.turn
            push(("stream_flush",))
            if ev.transition == "autocompact":
                self.autocompacts += 1
                push(("line", R.system_line("autocompact boundary")))
            else:
                push(("line", R.transition_line(ev.transition, ev.turn)))
            push(("turn", ev.turn))
        elif kind == "completed":
            self.turn = ev.turn
            d = ev.detail or {}
            self.total_tokens += int(d.get("prompt_tokens", 0)) + \
                int(d.get("completion_tokens", 0))
            push(("stream_flush",))
            push(("line", R.system_line(
                f"completed · reason={ev.reason} "
                f"turns={d.get('turns')} tool_calls={d.get('tool_calls')} "
                f"tokens={d.get('prompt_tokens')}/"
                f"{d.get('completion_tokens')}")))
        elif kind == "prompt_too_long":
            push(("line", R.error_line(
                "PROMPT TOO LONG: blocking limit reached")))
        elif kind == "watchdog":
            push(("line", R.error_line(
                f"TURN WATCHDOG: {ev.reason} ({ev.detail})")))
        elif kind == "error":
            push(("line", R.error_line(f"MODEL ERROR: {ev.reason}")))

    # journal tap: denials live + tool names + EKD rev ─────────────────

    def _on_journal_event(self, event: Dict[str, Any]) -> None:
        t = event.get("type")
        d = event.get("data") or {}
        if t == "permission_decision":
            if not d.get("allowed"):
                self.app.push_op(("deny", str(d.get("tool") or "?"),
                                  str(d.get("reason", ""))[:100]))
        elif t == "tool_call":
            self._names.append(str(d.get("tool") or "?"))
        elif t == "ekd_mutation":
            rev = d.get("rev_after")
            if isinstance(rev, int):
                self.rev = rev
                self.app.push_op(("rev", rev))

    # ── helpers ───────────────────────────────────────────────────────

    def _sync_messages(self) -> None:
        """The session store is the authoritative channel; refresh the
        app's message list from it after every run (follow-ups and
        /resume share this path)."""
        try:
            messages = []
            for rec in self.session.read_all():
                msg = rec.get("message")
                if rec.get("type") in ("user", "assistant", "tool_result") \
                        and isinstance(msg, dict) and msg.get("role"):
                    messages.append(msg)
            self.app.messages = messages
        except Exception:
            pass


def _env_i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default
