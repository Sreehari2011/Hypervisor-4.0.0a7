"""AEGIS Debug Kit — 4.0 port (P0, ported first per blueprint 9.10).

Port card: docs/port-cards/PORT-08-aegis-debug.md.

Zero-intrusion instrumentation for Hypervisor-4.0, ported from the 3.7.3
aegis_debug kit (which the operator designated to keep, whole). Captures:

  * RAW LLM wire traffic (requests + responses, streaming chunks, SSE
    data-line silence tracking, dead-stream reaper)
  * loop events: transitions, LLM calls (prompt dumps, TTFT, usage),
    tool spans, permission decisions — via the loop observer
    (loop_events.py), the 4.0 replacement for the LangChain callback
    handler
  * every journal append (mirrored into the unified timeline)
  * the future EKD/sessions attachment points (armed as no-op taps until
    P2/P1 land their modules — same guarded pattern as 3.7.3)
  * event-loop lag, full-process stall forensics with stack dumps
  * the entire application log tree

WITHOUT editing a single hypervisor source file beyond install(). The kit
must NEVER take the agent down: every path is guarded and fail-silent.

4.0 deltas from 3.7.3 (blueprint 9.10):
  * callbacks.py (LangChain BaseCallbackHandler) -> loop_events.py —
    the observer binds to explicit loop calls instead of injected
    callback managers; prompt-dump logic carried over verbatim.
  * wire tap unchanged in mechanism — the OpenAI-compatible client
    (adapters/openai.py, P1) rides httpx, which the tap already
    patches; httpx2 handling retained for the 3.x-era stack.
  * timeline categories add 'perm' (permission decisions).
  * the stall detector exposes a turn-activity signal the P1 turn
    watchdog will drive (loop_monitor.note_turn_activity).
  * saver/DAG taps re-aimed: journal tap targets
    hypervisor.persist.journal; EKD tap arms for hypervisor.memory.ekd
    (P2) via the same deterministic import hook; the LangGraph sqlite
    saver tap is deleted with the grid (its 4.0 successor is the
    sessions tap, P1).
"""
import os
import sys
import traceback

from . import config, timeline

_INSTALLED = False


def install():
    """Idempotent, fail-safe installation. Never raises."""
    global _INSTALLED
    if _INSTALLED or not config.ENABLED:
        return
    _INSTALLED = True
    try:
        timeline.emit("meta", "kit_start",
                      python=sys.version.split()[0],
                      pid=os.getpid(),
                      out=config.OUT_ROOT,
                      note="AEGIS Debug Kit 2.0 — 4.0 port: zero-intrusion "
                           "taps + journal mirror + dead-stream reaper")
        from . import logtap, wire_tap, patcher
        logtap.install()
        wire_tap.install()
        patcher.install_journal_tap()
        patcher.install_ekd_tap()       # no-op until memory/ekd lands (P2)
        patcher.install_sessions_tap()  # no-op until persist/sessions (P1)
        timeline.emit("meta", "kit_ready",
                      note="wire + loop_events + journal + ekd/sessions "
                           "watchers + loop monitor + reaper live")
        if not config.QUIET:
            sys.stderr.write(
                "[aegis-debug] KIT LIVE (2.0, 4.0 port) — events -> "
                f"{os.path.abspath(config.OUT_ROOT)}\n")
    except Exception:
        # The kit must NEVER take the agent down. Record and go silent.
        try:
            sys.stderr.write("[aegis-debug] install failed (agent unaffected):\n"
                             + traceback.format_exc())
        except Exception:
            pass


def reset_for_tests():
    """Test hook: allow a clean reinstall into a fresh run directory."""
    global _INSTALLED
    _INSTALLED = False
    timeline.close()
