"""hypervisor.tui.app — the TUI composition (UX-01).

One select-tick main loop owns the screen; everything else talks to
it through a thread-safe op queue:

  worker threads (engagement pump, /test, /doctor)  ──ops──▶  main loop
  stdin keys ──KeyParser──▶ LineEditor ──actions──▶ commands.dispatch

Frame budget: one select() with a 100 ms timeout per iteration —
drain all pending ops, apply keys, animate the spinner, repaint the
footer. The transcript itself is written incrementally (emit at the
scroll-region bottom), never full-screen redrawn, so long tool
output streams at the speed the engine produces it.

Ctrl-C semantics (Claude Code shape): aborts a running job, then a
running engagement (soft: the engine's own ctx.abort contract, hard
on the second press), then clears the input, then quits. Esc aborts
an engagement or clears the input. Everything restores the terminal
in a finally.
"""
from __future__ import annotations

import os
import queue
import select
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import commands as CMDS
from . import render as R
from .editor import KeyParser, LineEditor
from .engage import Engagement
from .term import CLEAR_SCREEN, Screen, Terminal, clip_styled, len_plain

TICK_S = 0.100


class TuiApp:
    """The operator surface commands talk to (see commands.py's module
    docstring for the contract): say/say_lines/err/hint/run_job/
    start_engagement/clear_view/quit + the state fields."""

    def __init__(self, *, workspace: Optional[str] = None,
                 stdin=None, stdout=None) -> None:
        self.sf: Any = None
        self.scope_path: Optional[str] = None
        self.workspace = Path(workspace or os.environ.get(
            "AEGIS_WORKSPACE") or "engagement").resolve()
        self.messages: List[Dict[str, Any]] = []
        self.session_id: Optional[str] = None
        self.engagement: Optional[Engagement] = None
        self._quit = False
        self._ops: "queue.Queue[tuple]" = queue.Queue()
        self._job: Optional[Dict[str, Any]] = None
        self._frame = 0
        self._last_cc = 0.0
        self._eng_t0 = 0.0
        self._stream_buf = ""
        self._last_footer_sig = None
        self._model = os.environ.get("AEGIS_MODEL", "adapter default")
        self.term = Terminal(stdin, stdout)
        self.screen = Screen(self.term)
        self.editor = LineEditor()
        self.parser = KeyParser()

    @property
    def cols(self) -> int:
        """Current terminal width — commands read this for wrapping."""
        return self.screen.cols

    # ─── op surface (thread-safe) ─────────────────────────────────────

    def push_op(self, op: tuple) -> None:
        self._ops.put(op)

    def say(self, line: str) -> None:
        self._ops.put(("line", line))

    def say_lines(self, lines: List[str]) -> None:
        self._ops.put(("lines", lines))

    def err(self, text: str) -> None:
        self._ops.put(("line", R.error_line(text)))

    def hint(self, text: str) -> None:
        self._ops.put(("line", R.hint_line(text)))

    def quit(self) -> None:
        self._quit = True

    # ─── jobs (/test, /doctor, ...) ───────────────────────────────────

    def run_job(self, title: str, fn: Callable) -> None:
        """fn(push, abort_event) runs on a worker thread; push(line)
        streams styled or plain lines into the transcript."""
        if self._job is not None and self._job["thread"].is_alive():
            self.hint(f"a job is already running ({self._job['title']}) "
                      f"— Ctrl-C aborts it")
            return
        abort = threading.Event()

        def push(line: str) -> None:
            self._ops.put(("line", line))

        def worker():
            try:
                fn(push, abort)
            except Exception as exc:
                push(R.error_line(
                    f"job failed: {type(exc).__name__}: {exc}"))
            finally:
                self._ops.put(("job_done",))

        t = threading.Thread(target=worker, daemon=True)
        self._job = {"title": title, "abort": abort, "thread": t}
        t.start()

    # ─── engagement entry ─────────────────────────────────────────────

    def start_engagement(self, text: str) -> None:
        if self.engagement is None:
            self.engagement = Engagement(self)
        if not self.engagement.started:
            self._eng_t0 = time.monotonic()
            self.engagement.start(text)
        else:
            self._eng_t0 = time.monotonic()
            self.engagement.follow_up(text)

    # ─── view ─────────────────────────────────────────────────────────

    def clear_view(self) -> None:
        self._ops.put(("clear",))

    def _print_header(self) -> None:
        from .. import __version__
        scope = self.sf.scope_ref() + f" · {self.sf.mode}" if self.sf \
            else "not armed"
        rows = R.header_card(__version__, self._model,
                             str(self.workspace), scope)
        self.screen.emit_many(rows)
        self.screen.emit("")

    def _print_tip(self) -> None:
        self.screen.emit_many(R.tip_card([
            "/help lists every command · /scope <file> arms the "
            "engagement",
            "then just type — free text talks to the agent · Tab "
            "completes · Ctrl-C aborts, twice quits",
        ]))
        self.screen.emit("")

    # ─── the main loop ────────────────────────────────────────────────

    def run(self) -> int:
        term, screen, editor, parser = \
            self.term, self.screen, self.editor, self.parser
        with term:
            try:
                term.write("\x1b]0;AEGIS Hypervisor — operator TUI\x07")
                screen.relayout()
                self._print_header()
                self._print_tip()
                fd = term.stdin.fileno()
                while not self._quit:
                    if term.resized:
                        screen.relayout()
                    self._drain_ops()
                    if self._quit:
                        break
                    # keys (with tick timeout; abort-friendly)
                    try:
                        ready, _, _ = select.select([fd], [], [], TICK_S)
                    except (OSError, ValueError):
                        break
                    if ready:
                        try:
                            data = os.read(fd, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        for ev in parser.feed(data) + parser.flush_idle():
                            self._on_key(ev)
                            if self._quit:
                                break
                    else:
                        for ev in parser.flush_idle():
                            self._on_key(ev)
                    self._frame += 1
                    self._paint_footer()
            finally:
                if self.engagement is not None and \
                        self.engagement.running:
                    self.engagement.abort(hard=True)
                    if self.engagement._thread is not None:
                        self.engagement._thread.join(timeout=5.0)
        return 0

    # ─── keys ─────────────────────────────────────────────────────────

    def _on_key(self, ev) -> None:
        action, payload = self.editor.update(ev)
        if action == "none":
            return
        if action == "changed":
            self.editor.refresh_palette(CMDS.completions())
            self._sync_palette()
            return
        if action == "submit":
            line = payload
            self.screen.emit_many(R.user_echo(line))
            self.editor.refresh_palette(CMDS.completions())
            self._sync_palette()
            if line.strip():
                CMDS.dispatch(self, line)
            return
        if action == "interrupt":
            self._on_ctrl_c()
            return
        if action == "eof":
            self._quit = True
            return
        if action == "esc":
            eng = self.engagement
            if eng is not None and eng.running:
                self._abort_engagement()
            elif self.editor.text():
                self.editor._set("")
            return
        if action == "redraw":
            self.clear_view()
            return
        # 'complete' (Tab without palette): no-op for now

    def _on_ctrl_c(self) -> None:
        now = time.monotonic()
        job = self._job
        if job is not None and job["thread"].is_alive():
            job["abort"].set()
            self.hint("aborting job…")
            return
        eng = self.engagement
        if eng is not None and eng.running:
            self._abort_engagement()
            return
        if self.editor.text():
            self.editor._set("")
            self.editor.refresh_palette(CMDS.completions())
            self._sync_palette()
            self.hint("input cleared — Ctrl-C again to quit")
            self._last_cc = now
            return
        if now - self._last_cc < 2.5:
            self._quit = True
            return
        self._last_cc = now
        self.hint("Ctrl-C again to quit")

    def _abort_engagement(self) -> None:
        eng = self.engagement
        assert eng is not None
        if not eng.abort_soft.is_set():
            eng.abort(hard=False)
            self.hint("aborting — takes effect at the next tool "
                      "boundary; Ctrl-C again to force")
        else:
            eng.abort(hard=True)
            self.hint("forcing abort…")

    # ─── ops ──────────────────────────────────────────────────────────

    def _drain_ops(self) -> None:
        while True:
            try:
                op = self._ops.get_nowait()
            except queue.Empty:
                return
            kind = op[0]
            if kind == "line":
                self._stream_flush_buf()
                self.screen.emit(op[1])
            elif kind == "lines":
                self._stream_flush_buf()
                self.screen.emit_many(op[1])
            elif kind == "stream":
                self._feed_stream(op[1])
            elif kind == "stream_flush":
                self._stream_flush_buf()
            elif kind == "deny":
                _, tool, reason = op
                self._stream_flush_buf()
                self.screen.emit(R.error_line(
                    f"gate denied {tool} — {reason}"))
            elif kind == "state":
                if op[1] == "idle":
                    self._stream_flush_buf()
            elif kind == "rev":
                pass                    # status line reads eng.rev live
            elif kind == "turn":
                pass
            elif kind == "completed_note":
                pass
            elif kind == "job_done":
                self._job = None
            elif kind == "clear":
                self._stream_flush_buf()
                self.term.write(CLEAR_SCREEN)
                self.screen.relayout()
                self._print_header()
                self.screen.emit(R.system_line(
                    "view cleared — your terminal's scrollback still "
                    "has the full history"))
                self.screen.emit("")

    # ─── streaming render ─────────────────────────────────────────────

    def _feed_stream(self, text: str) -> None:
        self._stream_buf += text
        while "\n" in self._stream_buf:
            line, self._stream_buf = self._stream_buf.split("\n", 1)
            self._emit_wrapped_assistant(line)
        self._render_transient()

    def _stream_flush_buf(self) -> None:
        if self._stream_buf:
            self._emit_wrapped_assistant(self._stream_buf)
            self._stream_buf = ""
        self.screen.clear_transient()

    def _emit_wrapped_assistant(self, text: str) -> None:
        width = max(20, self.screen.cols - 4)
        rows = R.wrap_plain(text.expandtabs(4), width)
        if not rows:
            return
        for i, chunk in enumerate(rows):
            if i == 0:
                self.screen.emit(R.assistant_line(chunk))
            else:
                self.screen.emit("  " + R.text(chunk))

    def _render_transient(self) -> None:
        width = max(20, self.screen.cols - 4)
        rows = R.wrap_plain(self._stream_buf.expandtabs(4), width)
        if rows:
            self.screen.show_transient(R.assistant_line(rows[-1]))

    # ─── footer ───────────────────────────────────────────────────────

    def _sync_palette(self) -> None:
        if self.editor.palette_open:
            rows = R.palette_rows(self.editor.palette_items,
                                  self.editor.palette_sel,
                                  CMDS.palette_hints())
            self.screen.set_palette(rows)
        else:
            self.screen.set_palette([])

    def _paint_footer(self) -> None:
        eng = self.engagement
        job = self._job
        active = (eng is not None and eng.running) or \
                 (job is not None and job["thread"].is_alive())
        if eng is not None and eng.running:
            elapsed = time.monotonic() - self._eng_t0
            status = R.status_running(self._model, eng.turn, 0,
                                      elapsed, self._frame)
        elif job is not None and job["thread"].is_alive():
            spin = R.fg(R.SPINNER[self._frame % len(R.SPINNER)], R.C_BRAND)
            status = spin + R.muted(f" {job['title']} running…")
        else:
            status = R.status_idle(self._model, str(self.workspace),
                                   self.sf is not None)
            if eng is not None and eng.rev:
                status += R.muted(f" · rev {eng.rev}")
        shown = R.input_line(self.editor.text())
        # cursor col: prompt is 2 printable cols ("❯ " / "> ")
        cursor = 2 + self.editor.cursor
        # idle + nothing changed -> skip the repaint (a 100 ms footer
        # loop over a slow link would otherwise flood the terminal)
        sig = (status, shown, cursor, tuple(self.screen.palette_rows),
               self.screen.cols)
        if not active and sig == self._last_footer_sig:
            return
        self._last_footer_sig = sig
        # clip to the terminal width — an over-long status would wrap
        # inside the footer block and smear the input line
        status = clip_styled(status, self.screen.cols)
        shown = clip_styled(shown, self.screen.cols)
        self.screen.render_footer(
            status_text=status, input_text=shown,
            cursor_col=cursor, input_bg_width=self.screen.cols)


def run_tui(argv: Optional[List[str]] = None) -> int:
    """Entry used by cli.py's bare-tty hook. argv is currently unused
    (state arrives via /commands); kept for future --tui flags."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("operator TUI needs an interactive terminal "
              "(stdin/stdout must be ttys)", file=sys.stderr)
        return 1
    app = TuiApp()
    try:
        return app.run()
    except KeyboardInterrupt:                    # raw mode should catch
        return 130                               # this first; belt+braces
