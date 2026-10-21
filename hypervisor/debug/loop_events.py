"""AEGIS Debug Kit — loop observer (4.0 replacement for the 3.x
LangChain callback handler).

Port card: PORT-08. In 3.7.3, callbacks.py injected a
BaseCallbackHandler into every LangChain callback manager to observe the
mesh. In 4.0 there is no LangChain: the query loop (P1) calls this
observer directly at its defined phase boundaries — same spans, same
timeline shapes, zero injection machinery. The prompt-dump logic is
carried over verbatim (the EXACT assembled prompt lands in
prompts/<seq>.txt with role + char counts).

The observer observes everything and touches nothing: every method is
guarded, none may raise into the loop, and the emitted events are the
4.0 control-plane timeline vocabulary:

  cat=loop  ev=start/end/transition/turn_activity
  cat=llm   ev=start/prompt/first_token/end/error/retry
  cat=tool  ev=start/end/error
  cat=perm  ev=decision

(P1 wiring: LoopDeps will hold an observer instance; the loop calls it
exactly where the CC reference emits its transitions — after model
response, after each tool result, at every continue path.)
"""
import time

from . import config, timeline

_MAX_TRACKED = 4096        # span maps are bounded; engagements are long

_STARTS = {}               # span id -> (monotonic t0, kind, name)
_FIRST_TOKEN = {}          # span id -> first-token monotonic


def _now():
    return time.monotonic()


def _track(span_id, kind, name):
    if len(_STARTS) > _MAX_TRACKED:
        _STARTS.clear()   # crude but safe: stale entries only cost dur=None
    _STARTS[span_id] = (_now(), kind, name)


def _close(span_id):
    ent = _STARTS.pop(span_id, None)
    if not ent:
        return None, None, None
    t0, kind, name = ent
    return round((_now() - t0) * 1000, 1), kind, name


def _prev(obj, limit=300):
    try:
        return str(obj)[:limit] if obj is not None else None
    except Exception:
        return None


def dump_prompt(messages, span_id, system_prompt=None):
    """Write the EXACT assembled prompt to prompts/<seq>.txt. Carried
    verbatim from the 3.7.3 callback handler (role, char counts, total),
    extended with the optional system prompt block the 4.0 assembly
    passes separately. Never raises."""
    seq = timeline.seq_next()
    try:
        parts, total = [], 0
        if system_prompt:
            sp = str(system_prompt)
            total += len(sp)
            parts.append(f"── system · {len(sp)} chars {'═' * 40}\n{sp}\n")
        if messages and isinstance(messages[0], (list, tuple)):
            messages = [m for group in messages for m in group]
        for m in messages or []:
            if isinstance(m, dict):
                content = m.get("content", "")
                role = m.get("role", "msg")
            else:
                content = getattr(m, "content", m if isinstance(m, str) else "")
                role = getattr(m, "type", "msg")
            n = len(str(content))
            total += n
            parts.append(f"── {role} · {n} chars {'═' * 40}\n{content}\n")
        with open(f"{config.run_dir()}/prompts/prompt_{seq:04d}.txt",
                  "w", encoding="utf-8") as f:
            f.write(f"span_id={span_id} total_chars={total}\n\n"
                    + "".join(parts))
        timeline.emit("llm", "prompt", id=str(span_id), seq=seq,
                      n_messages=len(messages or []),
                      chars=total,
                      est_tokens=total // 4)
    except Exception:
        pass


class LoopObserver:
    """Observes everything; touches nothing. One instance lives in the
    loop's deps; subagents (P3) get their own instance with a depth
    marker so nested spans stay distinguishable in the timeline."""

    def __init__(self, *, depth: int = 0, label: str = "main"):
        self.depth = depth
        self.label = label

    # ── loop lifecycle ──────────────────────────────────────────────

    def on_loop_start(self, *, turn: int = 0):
        timeline.emit("loop", "start", depth=self.depth, label=self.label,
                      turn=turn)

    def on_loop_end(self, *, turn: int = 0, reason: str = ""):
        timeline.emit("loop", "end", depth=self.depth, label=self.label,
                      turn=turn, reason=reason or None)

    def on_transition(self, transition: str, *, frm: str = "", to: str = "",
                      turn: int = 0, **detail):
        """The 4.0 transition table surface (CC-equivalent). Every
        continue path through the loop calls this with the canonical
        transition name."""
        timeline.emit("loop", "transition", id=str(turn),
                      transition=transition, frm=frm or None, to=to or None,
                      depth=self.depth, label=self.label,
                      **{k: v for k, v in detail.items() if v is not None})

    # ── LLM calls ───────────────────────────────────────────────────

    def on_llm_start(self, span_id, *, model: str = "", turn: int = 0,
                     messages=None, system_prompt=None):
        _track(span_id, "llm", model or "chat")
        timeline.emit("llm", "start", id=str(span_id), model=model or "?",
                      turn=turn, depth=self.depth, label=self.label)
        if messages is not None:
            dump_prompt(messages, span_id, system_prompt=system_prompt)

    def on_llm_first_token(self, span_id, *, chunk: str = ""):
        if span_id not in _FIRST_TOKEN:
            if len(_FIRST_TOKEN) > _MAX_TRACKED:
                _FIRST_TOKEN.clear()
            _FIRST_TOKEN[span_id] = _now()
            ent = _STARTS.get(span_id)
            ttft = round((_FIRST_TOKEN[span_id] - ent[0]) * 1000, 1) if ent else None
            timeline.emit("llm", "first_token", id=str(span_id), ttft_ms=ttft)

    def on_llm_end(self, span_id, *, usage=None, finish: str = "",
                   output: str = ""):
        dur, _kind, _name = _close(span_id)
        _FIRST_TOKEN.pop(span_id, None)
        u = usage or {}
        timeline.emit("llm", "end", dur_ms=dur, id=str(span_id),
                      out=_prev(output, 200),
                      finish=finish or None,
                      prompt_tokens=u.get("prompt_tokens"),
                      completion_tokens=u.get("completion_tokens"),
                      total_tokens=u.get("total_tokens"))

    def on_llm_error(self, span_id, error):
        dur, _kind, _name = _close(span_id)
        timeline.emit("llm", "error", dur_ms=dur, id=str(span_id),
                      exc=f"{type(error).__name__}: {error}")

    def on_llm_retry(self, span_id, *, attempt: int = 0, error=None,
                     backoff_s: float = 0.0):
        timeline.emit("llm", "retry", id=str(span_id), attempt=attempt,
                      backoff_s=backoff_s or None,
                      exc=(f"{type(error).__name__}: {error}"
                           if error is not None else None))

    # ── tools ───────────────────────────────────────────────────────

    def on_tool_start(self, span_id, *, tool: str = "", turn: int = 0,
                      args=None):
        _track(span_id, "tool", tool)
        timeline.emit("tool", "start", id=str(span_id), tool=tool or None,
                      turn=turn, depth=self.depth, label=self.label,
                      input=_prev(args))

    def on_tool_end(self, span_id, *, output=None):
        dur, _kind, name = _close(span_id)
        out = ""
        try:
            out = str(getattr(output, "content", output))
        except Exception:
            pass
        timeline.emit("tool", "end", dur_ms=dur, id=str(span_id),
                      tool=name or None, output=_prev(out))

    def on_tool_error(self, span_id, error):
        dur, _kind, name = _close(span_id)
        timeline.emit("tool", "error", dur_ms=dur, id=str(span_id),
                      tool=name or None,
                      exc=f"{type(error).__name__}: {error}")

    # ── permission gate ─────────────────────────────────────────────

    def on_permission_decision(self, *, tool: str, allowed: bool,
                               rule: str = "", turn: int = 0):
        """Mirrors the journal's permission_decision event into the
        timeline (SLO-1 surface: zero scope violations)."""
        timeline.emit("perm", "decision", tool=tool,
                      allowed=bool(allowed), rule=rule or None,
                      turn=turn, depth=self.depth, label=self.label)
