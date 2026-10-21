"""AEGIS Debug Kit — the timeline: one append-only JSONL of every event.

Ported from 3.7.3, mechanism verbatim. Every line:

    {"t": <monotonic s>, "ts": <wall iso>, "cat": <category>,
     "ev": <event>, "dur_ms": <float|null>, "id": <correlation id>,
     "data": {...}}

Categories: meta | wire | llm | loop | tool | perm | journal | memory |
stall | log. (3.7.3's 'chain'/'saver'/'dag' categories retired with the
grid; 'loop'/'perm'/'memory' are the 4.0 control-plane surfaces.)

The sink is deliberately crash-forensic: every event is flushed on write,
so a hard hang (the exact failure class this kit was built for) still
leaves the timeline complete up to the last observed event.
"""
import json
import os
import sys
import threading
import time

from . import config

_LOCK = threading.Lock()
_FH = None
_LAST_EVENT = 0.0          # monotonic of last accepted event (stall detector)
_SEQ = 0
_T0 = time.monotonic()


def _handle():
    global _FH
    if _FH is None:
        path = os.path.join(config.run_dir(), "timeline.jsonl")
        _FH = open(path, "a", encoding="utf-8", buffering=1)  # line buffered
    return _FH


def emit(cat: str, ev: str, dur_ms=None, id=None, **data):
    """Append one event. Never raises — the kit must not break the agent."""
    global _SEQ, _LAST_EVENT
    try:
        now = time.time()
        rec = {
            "t": round(time.monotonic(), 6),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
                  + (".%03dZ" % (int(now * 1000) % 1000)),
            "cat": cat, "ev": ev, "dur_ms": dur_ms, "id": id,
        }
        if data:
            rec["data"] = {k: v for k, v in data.items() if v is not None}
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with _LOCK:
            _FH_ = _handle()
            _FH_.write(line + "\n")
            _SEQ += 1
            _LAST_EVENT = rec["t"]
    except Exception as exc:  # pragma: no cover — forensic silence
        try:
            sys.stderr.write(f"[aegis-debug] timeline emit failed: {exc!r}\n")
        except Exception:
            pass


def last_event_time():
    """Monotonic timestamp of the last accepted event (0 if none yet)."""
    with _LOCK:
        return _LAST_EVENT


def seq_next():
    global _SEQ
    with _LOCK:
        _SEQ += 1
        return _SEQ


def elapsed() -> float:
    return time.monotonic() - _T0


def path() -> str:
    return os.path.join(config.run_dir(), "timeline.jsonl")


def close():
    """Flush and close the sink (test hook; the next emit reopens)."""
    global _FH
    with _LOCK:
        if _FH is not None:
            try:
                _FH.flush()
                _FH.close()
            except Exception:
                pass
            _FH = None
