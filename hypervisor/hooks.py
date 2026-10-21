"""hypervisor.hooks — the stop-hook surface (P4, blueprint Ch.14).

The last control-plane seam from the Claude Code architecture: a hook
consulted at the moment the main loop is about to accept a natural
stop (a final reply with no tool uses). CC's contract (query.ts:1267 /
stopHooks.ts / utils/hooks.ts, exit-code + JSON decision semantics):

  input  → stdin JSON  {"hook_event_name": "Stop",
                        "stop_hook_active": <bool>,
                        "last_assistant_message": <str>,
                        "session_path": <str>, "turn": <int>}
  output → exit 0 + stdout JSON {"decision": "approve"|"block",
                                 "reason": <str>}
           exit 0 without JSON        → approve
           exit 2                     → blocking error (stderr or stdout
                                        becomes the block reason)
           any other exit             → non-blocking error: journaled,
                                        DOES NOT gate the stop

A block feeds the reason back into the conversation as an isMeta user
message and the loop continues — with stop_hook_active=True so a hook
that blocks its own continuation cannot recurse forever (the CC
recursion guard, enforced in-engine as a hard single re-entry).

SubagentStop rides the same module (CC parity: agent_id / agent_type
fields) and is consulted by the agent runtime after a child loop ends;
it can veto a subagent's report the same way.

4.0 discipline: the hook command runs under the SAME bounded-subprocess
contract as every tool (process group, wall-clock bound, captured
output); every run journals a stop_hook event (decision, duration,
exit code); hook failure NEVER wedges the loop — a non-2 failure is an
audited allow, a timeout is an audited allow. The hook command is
operator configuration: --stop-hook CLI flag or AEGIS_STOP_HOOK env —
never model-reachable.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_HOOK_TIMEOUT_S = 30.0
MAX_HOOK_TIMEOUT_S = 120.0


# ─── the decision ───────────────────────────────────────────────────────

@dataclass
class HookDecision:
    """Outcome of one stop-hook consultation."""
    decision: str = "approve"          # approve | block | error
    reason: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    timed_out: bool = False
    raw_stdout: str = ""
    source: str = "command"            # command | callable

    @property
    def blocks(self) -> bool:
        return self.decision == "block"


# ─── configuration ──────────────────────────────────────────────────────

@dataclass
class StopHookConfig:
    """Operator configuration for the stop-hook seam. Either a shell
    command (CC parity: subprocess, stdin JSON, exit-code semantics)
    or an in-engine callable(payload_dict) -> HookDecision | dict |
    None (tests + programmatic policy)."""
    command: Optional[str] = None
    callable: Optional[Any] = None
    timeout_s: float = DEFAULT_HOOK_TIMEOUT_S
    subagent_command: Optional[str] = None   # SubagentStop (same shape)
    max_reentry: int = 1                     # the CC recursion guard

    def active(self) -> bool:
        return bool(self.command or self.callable)

    def subagent_active(self) -> bool:
        return bool(self.subagent_command or self.callable)


def stop_hook_from_env() -> StopHookConfig:
    """AEGIS_STOP_HOOK / AEGIS_SUBAGENT_STOP_HOOK / AEGIS_STOP_HOOK_TIMEOUT_S."""
    cfg = StopHookConfig()
    cfg.command = os.environ.get("AEGIS_STOP_HOOK", "").strip() or None
    cfg.subagent_command = (
        os.environ.get("AEGIS_SUBAGENT_STOP_HOOK", "").strip() or None)
    try:
        cfg.timeout_s = min(
            float(os.environ.get("AEGIS_STOP_HOOK_TIMEOUT_S", "")
                  or DEFAULT_HOOK_TIMEOUT_S), MAX_HOOK_TIMEOUT_S)
    except (TypeError, ValueError):
        pass
    return cfg


# ─── payload construction (the CC Stop input shape) ─────────────────────

def stop_payload(*, last_assistant_message: str,
                 stop_hook_active: bool, turn: int,
                 session_path: str = "",
                 purpose: str = "main") -> Dict[str, Any]:
    return {
        "hook_event_name": "Stop",
        "stop_hook_active": bool(stop_hook_active),
        "last_assistant_message": str(last_assistant_message)[:8000],
        "session_path": str(session_path),
        "turn": int(turn),
        "purpose": str(purpose),
    }


def subagent_stop_payload(*, agent_type: str, agent_id: str,
                          last_assistant_message: str,
                          stop_hook_active: bool, turn: int = 0,
                          session_path: str = "") -> Dict[str, Any]:
    return {
        "hook_event_name": "SubagentStop",
        "stop_hook_active": bool(stop_hook_active),
        "agent_id": str(agent_id),
        "agent_type": str(agent_type),
        "last_assistant_message": str(last_assistant_message)[:8000],
        "session_path": str(session_path),
        "turn": int(turn),
    }


# ─── execution ──────────────────────────────────────────────────────────

def _parse_decision(stdout: str) -> Optional[Dict[str, Any]]:
    """CC semantics: stdout may carry a JSON object with decision/reason.
    Tolerates leading/trailing noise; returns None when no JSON object."""
    text = (stdout or "").strip()
    if not text:
        return None
    # direct parse first
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # then scan for the first {...} block (hooks that log then print)
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        start = -1
    return None


async def _run_command_hook(command: str, payload: Dict[str, Any],
                            timeout_s: float) -> HookDecision:
    """Run one hook command under the bounded-subprocess contract."""
    argv = shlex.split(command)
    if not argv:
        return HookDecision(decision="error",
                            reason="empty hook command")
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid)
    except OSError as exc:
        return HookDecision(decision="error",
                            reason=f"hook spawn failed: {exc}",
                            duration_s=time.monotonic() - t0)
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(
                input=json.dumps(payload).encode("utf-8")),
            timeout=max(1.0, timeout_s))
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        return HookDecision(decision="error",
                            reason=f"hook exceeded {timeout_s:.0f}s",
                            timed_out=True,
                            duration_s=time.monotonic() - t0)
    stdout = (out or b"").decode("utf-8", "replace")
    stderr = (err or b"").decode("utf-8", "replace")
    rc = proc.returncode or 0
    dur = time.monotonic() - t0

    if rc == 2:                        # blocking error (CC contract)
        reason = (stderr.strip() or stdout.strip()
                  or "Blocked by hook")
        return HookDecision(decision="block", reason=reason,
                            exit_code=rc, duration_s=dur,
                            raw_stdout=stdout)
    if rc != 0:                        # non-blocking error
        return HookDecision(decision="error",
                            reason=f"hook exit {rc}: "
                                   f"{(stderr or stdout).strip()[:300]}",
                            exit_code=rc, duration_s=dur,
                            raw_stdout=stdout)
    obj = _parse_decision(stdout)
    if obj is None:
        return HookDecision(decision="approve", exit_code=rc,
                            duration_s=dur, raw_stdout=stdout)
    decision = str(obj.get("decision", "approve")).strip().lower()
    reason = str(obj.get("reason", ""))
    if decision == "block":
        return HookDecision(decision="block",
                            reason=reason or "Blocked by hook",
                            exit_code=rc, duration_s=dur,
                            raw_stdout=stdout)
    if decision not in ("approve", "allow", "ok", ""):
        return HookDecision(decision="error",
                            reason=f"unknown hook decision {decision!r}",
                            exit_code=rc, duration_s=dur,
                            raw_stdout=stdout)
    return HookDecision(decision="approve", reason=reason,
                        exit_code=rc, duration_s=dur,
                        raw_stdout=stdout)


async def run_stop_hook(config: StopHookConfig,
                        payload: Dict[str, Any]) -> HookDecision:
    """Consult the configured stop hook. Errors never gate the stop
    (audited allow); a block carries the reason back to the loop."""
    if not config.active():
        return HookDecision(decision="approve", reason="no hook configured",
                            source="noop")
    if config.callable is not None:
        t0 = time.monotonic()
        try:
            out = config.callable(payload)
            if asyncio.iscoroutine(out):
                out = await out
            dur = time.monotonic() - t0
        except Exception as exc:
            return HookDecision(decision="error",
                                reason=f"hook callable raised: {exc}",
                                duration_s=time.monotonic() - t0,
                                source="callable")
        if out is None:
            return HookDecision(decision="approve",
                                duration_s=dur, source="callable")
        if isinstance(out, HookDecision):
            out.source = "callable"
            return out
        if isinstance(out, dict):
            decision = str(out.get("decision", "approve")).lower()
            return HookDecision(
                decision="block" if decision == "block" else "approve",
                reason=str(out.get("reason", "")),
                duration_s=dur, source="callable")
        return HookDecision(decision="error",
                            reason=f"hook callable returned "
                                   f"{type(out).__name__}",
                            duration_s=dur, source="callable")
    return await _run_command_hook(config.command or "", payload,
                                   config.timeout_s)


async def run_subagent_stop_hook(config: StopHookConfig,
                                 payload: Dict[str, Any]) -> HookDecision:
    """SubagentStop consultation (same contract, subagent command)."""
    sub = StopHookConfig(command=config.subagent_command,
                         callable=None if config.subagent_command
                         else config.callable,
                         timeout_s=config.timeout_s)
    if not sub.active():
        return HookDecision(decision="approve",
                            reason="no subagent hook configured",
                            source="noop")
    return await run_stop_hook(sub, payload)


# ─── journaling ─────────────────────────────────────────────────────────

def journal_hook_run(journal: Any, decision: HookDecision,
                     payload: Dict[str, Any], *,
                     event: str = "stop_hook") -> None:
    """Every consultation is auditable: decision, duration, exit code,
    the block reason. Failures of the journal itself never propagate."""
    if journal is None:
        return
    try:
        journal.append(event, {
            "decision": decision.decision,
            "reason": (decision.reason or "")[:400],
            "duration_ms": round(decision.duration_s * 1000, 1),
            "exit_code": decision.exit_code,
            "timed_out": decision.timed_out,
            "hook_event_name": payload.get("hook_event_name", "Stop"),
            "stop_hook_active": payload.get("stop_hook_active", False),
            "turn": payload.get("turn", 0),
            "source": decision.source,
        }, actor="hooks")
    except Exception:
        pass


# ─── the block feedback message (CC's createUserMessage shape) ──────────

def block_feedback_message(reason: str) -> Dict[str, Any]:
    """The isMeta user message a block injects — the reason the hook
    gave, framed so the model continues the engagement instead of
    stopping. stop_hook_active rides the payload (not the message); the
    loop tracks re-entry."""
    return {
        "role": "user",
        "content": [{"type": "text", "text":
                     "The stop-hook blocked this stop: "
                     f"{reason}\nContinue working the objective; address "
                     "the hook's reason and finish properly."}],
        "isMeta": True,
    }
