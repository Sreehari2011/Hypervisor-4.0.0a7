"""AEGIS Debug Kit — event-loop health + stall forensics.

Ported from 3.7.3 (mechanism verbatim), with the 4.0 addition of a
turn-activity signal (blueprint 9.10): the P1 turn watchdog will call
note_turn_activity() once per loop-iteration phase, so a turn that is
progressing (LLM streaming, tools running) never trips the stall
detector, while a turn parked on one call still dumps stacks.

Two sentinels answer the "environment or agent?" question directly:

  * Loop lag probe: a thread schedules a no-op coroutine onto the running
    loop once a second and measures scheduling delay. If the loop is
    blocked (a sync call inside async code), lag spikes — recorded as
    loop_lag events. asyncio debug mode additionally makes asyncio
    itself log slow callbacks, which logtap captures.
  * Stall detector: when NOTHING has hit the timeline for STALL_SECONDS
    (default 30s), faulthandler dumps EVERY thread's stack to
    stalls/stall_<n>_<ts>.txt and repeats while the stall persists. A
    45-minute hang leaves a stack-by-stack record of exactly where the
    process sat — socket read, sqlite write, subprocess wait, lock.

Also surfaces wire requests that never completed (open_requests) inside
each stall dump header, so an endpoint hang is distinguishable from a
local block at a glance.
"""
import asyncio
import faulthandler
import os
import threading
import time

from . import config, timeline

_STATE = {"loop": None, "thread": None, "last_dump": 0.0, "dump_n": 0,
          "turn": None}          # 4.0: turn-activity surface
_LOCK = threading.Lock()


def note_turn_activity(turn: int, phase: str = ""):
    """4.0 turn-watchdog signal: the loop calls this at each iteration
    phase boundary. Emits a loop turn_activity event (keeps the stall
    detector fed) and records the current turn for stall headers. Cheap
    by design — one buffered JSONL line."""
    with _LOCK:
        _STATE["turn"] = turn
    timeline.emit("loop", "turn_activity", id=str(turn), phase=phase or None)


def current_turn():
    with _LOCK:
        return _STATE.get("turn")


def _stall_check():
    last = timeline.last_event_time()
    if last == 0.0:
        return
    silent = time.monotonic() - last
    if silent < config.STALL_SECONDS:
        return
    if time.monotonic() - _STATE["last_dump"] < config.STALL_REPEAT_SECONDS:
        return
    _STATE["last_dump"] = time.monotonic()
    _STATE["dump_n"] += 1
    n = _STATE["dump_n"]
    stamp = time.strftime("%H%M%S", time.gmtime())
    path = os.path.join(config.run_dir(), "stalls", f"stall_{n:03d}_{stamp}.txt")
    from . import wire_tap
    header = [
        f"STALL #{n}: {silent:.1f}s with zero timeline events",
        f"wall: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"turn: {_STATE.get('turn')}",
        f"open wire requests: {wire_tap.open_requests_snapshot()}",
        "-" * 60,
    ]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(header) + "\n")
            faulthandler.dump_traceback(file=f)
        timeline.emit("stall", "stack_dump", silent_s=round(silent, 1),
                      dump=path)
    except Exception as exc:
        timeline.emit("stall", "dump_failed", exc=repr(exc))


async def _ping():
    return time.monotonic()


def _monitor_loop():
    while True:
        loop = _STATE["loop"]
        if loop is not None and not loop.is_closed():
            try:
                t_sched = time.monotonic()
                fut = asyncio.run_coroutine_threadsafe(_ping(), loop)
                done = fut.result(timeout=15)
                lag = done - t_sched
                if lag > config.LOOP_LAG_WARN:
                    timeline.emit("loop", "lag", lag_ms=round(lag * 1000, 1))
            except Exception:
                pass
        _stall_check()
        time.sleep(1.0)


def running_loop():
    """The event loop registered by ensure_started (None before the first
    async send, or when the kit runs in a purely sync process). The
    dead-stream reaper uses this to close stuck async responses ON the
    loop that owns them (never from a foreign thread directly)."""
    with _LOCK:
        return _STATE.get("loop")


def ensure_started():
    """Bootstrap from any async context; idempotent; never raises."""
    try:
        with _LOCK:
            if _STATE["thread"] is not None and _STATE["thread"].is_alive():
                return
            loop = asyncio.get_running_loop()
            if config.LOOP_DEBUG:
                try:
                    loop.set_debug(True)
                    loop.slow_callback_duration = 0.1
                except Exception:
                    pass
            _STATE["loop"] = loop
            _STATE["thread"] = threading.Thread(
                target=_monitor_loop, name="aegis-debug-monitor", daemon=True)
            _STATE["thread"].start()
            timeline.emit("meta", "loop_monitor_started",
                          loop_debug=config.LOOP_DEBUG)
    except RuntimeError:
        pass  # no running loop in this thread — called from sync context
    except Exception:
        pass
