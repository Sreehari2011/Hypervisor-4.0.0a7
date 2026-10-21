"""hypervisor.tui.editor — key parsing + the input line editor (UX-01).

Two layers:

  * KeyParser turns raw stdin bytes into semantic KeyEvents. UTF-8 is
    decoded incrementally (multibyte chars may arrive split across
    reads); CSI escape sequences (arrows, home/end/delete, bracketed
    paste markers) are assembled with a bounded buffer; a lone ESC is
    resolved by a 40 ms quiet period (flush_idle) so "press Esc" stays
    a first-class key without breaking quick arrow chords.
  * LineEditor is a readline-shaped single-line editor: cursor
    movement, history (up/down with draft preservation), word/line
    kills, and a slash-command palette mode — when the buffer starts
    with "/" and has no space, up/down navigate the palette instead of
    history and Tab accepts the highlighted completion.

Everything is pure logic over (bytes in -> actions out); no terminal
I/O happens here, which is what makes the whole layer unit-testable
without a tty.
"""
from __future__ import annotations

import codecs
import time
from typing import List, NamedTuple, Optional, Tuple

ESC_TIMEOUT_S = 0.040        # lone-ESC resolution window
ESC_MAX_LEN = 16             # bounded escape assembly


class KeyEvent(NamedTuple):
    kind: str                # see _SPECIAL below
    text: str = ""


_IGNORE = "ignore"


class KeyParser:
    """Stateful byte-stream -> KeyEvent parser."""

    PASTE_TIMEOUT_S = 0.050     # lost paste-end marker recovery

    def __init__(self) -> None:
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._esc: List[int] = []
        self._esc_ts = 0.0
        self._pasting = False
        self._paste_ts = 0.0

    # -- public ----------------------------------------------------------

    def feed(self, data: bytes) -> List[KeyEvent]:
        events: List[KeyEvent] = []
        self._paste_ts = time.monotonic()
        for byte in data:
            if self._esc:
                for ev in self._feed_esc(byte):
                    if ev.kind == "paste-start":
                        self._pasting = True
                    elif ev.kind == "paste-end":
                        self._pasting = False
                    events.append(ev)
            elif byte == 0x1B:
                self._esc = [byte]
                self._esc_ts = time.monotonic()
            elif self._pasting and byte in (0x0A, 0x0D):
                # inside a bracketed paste, newlines are DATA (the
                # editor softens them to spaces — no accidental submit)
                events.append(KeyEvent("text", "\n"))
            elif byte < 0x20 or byte == 0x7F:
                ev = _control(byte)
                if ev is not None:
                    events.append(ev)
            else:
                ch = self._dec.decode(bytes([byte]))
                if ch:
                    events.append(KeyEvent("text", ch))
        return events

    def flush_idle(self) -> List[KeyEvent]:
        """Resolve a pending lone ESC once input has been quiet."""
        now = time.monotonic()
        if self._pasting and (now - self._paste_ts) >= self.PASTE_TIMEOUT_S:
            self._pasting = False
        if self._esc and (now - self._esc_ts) >= ESC_TIMEOUT_S:
            self._esc = []
            return [KeyEvent("esc")]
        return []

    def pending_esc(self) -> bool:
        return bool(self._esc)

    # -- escape assembly ---------------------------------------------------

    def _feed_esc(self, byte: int) -> List[KeyEvent]:
        self._esc.append(byte)
        seq = bytes(self._esc)
        # final byte of a CSI sequence: @..~ (params already consumed).
        # Bracketed-paste markers are ordinary CSI sequences here:
        # ESC [ 2 0 0 ~ / ESC [ 2 0 1 ~ — the digits accumulate as
        # params and '~' is the final, so _csi() resolves them (no
        # prefix matching, which would mis-eat e.g. ESC[2015~).
        if len(seq) >= 3 and 0x40 <= byte <= 0x7E:
            self._esc = []
            return [_csi(seq)]
        # SS3 (ESC O x) finals
        if len(seq) == 3 and seq[1] == 0x4F and 0x40 <= byte <= 0x7E:
            self._esc = []
            return [_csi(seq)]
        if len(seq) > ESC_MAX_LEN:
            self._esc = []
        return []


def _csi(seq: bytes) -> KeyEvent:
    """Map one assembled escape sequence to its event."""
    tail = seq[-1:]
    if seq[1:2] == b"O":
        key = {b"A": "up", b"B": "down", b"C": "right",
               b"D": "left", b"H": "home", b"F": "end"}.get(tail)
        return KeyEvent(key or _IGNORE)
    params = seq[2:-1]
    if tail == b"~":
        num = params.split(b";")[0]
        key = {b"1": "home", b"2": _IGNORE, b"3": "delete",
               b"4": "end", b"5": _IGNORE, b"6": _IGNORE,
               b"7": "home", b"8": "end",
               b"200": "paste-start", b"201": "paste-end"}.get(num)
        return KeyEvent(key or _IGNORE)
    key = {b"A": "up", b"B": "down", b"C": "right", b"D": "left",
           b"H": "home", b"F": "end", b"Z": "shift-tab"}.get(tail)
    return KeyEvent(key or _IGNORE)


def _control(byte: int) -> Optional[KeyEvent]:
    """C0 controls the editor understands."""
    mapping = {
        0x0D: "enter", 0x0A: "enter", 0x09: "tab", 0x7F: "backspace",
        0x08: "backspace",
        0x01: "ctrl-a", 0x02: "ctrl-b", 0x04: "ctrl-d", 0x03: "ctrl-c",
        0x05: "ctrl-e", 0x06: "ctrl-f", 0x0B: "ctrl-k", 0x0C: "ctrl-l",
        0x15: "ctrl-u", 0x17: "ctrl-w", 0x19: "ctrl-y",
        0x0E: _IGNORE, 0x10: _IGNORE, 0x12: _IGNORE, 0x13: _IGNORE,
        0x14: _IGNORE, 0x16: _IGNORE, 0x18: _IGNORE, 0x1A: _IGNORE,
    }
    ev = mapping.get(byte)
    return KeyEvent(ev) if ev else None


# ─── LineEditor ────────────────────────────────────────────────────────

class LineEditor:
    """Readline-shaped single-line editor with history + palette."""

    def __init__(self, history: Optional[List[str]] = None) -> None:
        self.buffer: List[str] = []
        self.cursor = 0                      # 0..len(buffer)
        self.history: List[str] = list(history or [])
        self.hist_idx: Optional[int] = None  # None = live buffer
        self.draft: str = ""                 # buffer saved on history nav
        self.last_kill: str = ""
        # palette state (driven by the app between keys)
        self.palette_items: List[str] = []   # suggestion names
        self.palette_sel: int = 0
        self.palette_open: bool = False

    # -- buffer helpers ---------------------------------------------------

    def text(self) -> str:
        return "".join(self.buffer)

    def _set(self, text: str, cursor: Optional[int] = None) -> None:
        self.buffer = list(text)
        self.cursor = len(self.buffer) if cursor is None \
            else max(0, min(cursor, len(self.buffer)))
        self.hist_idx = None

    def _in_word_left(self) -> int:
        i = self.cursor
        while i > 0 and self.buffer[i - 1] == " ":
            i -= 1
        while i > 0 and self.buffer[i - 1] != " ":
            i -= 1
        return i

    # -- palette ----------------------------------------------------------

    def refresh_palette(self, completions: List[str]) -> bool:
        """(Re)compute the palette from the buffer. Returns True when
        the palette state changed (the app relayouts the footer)."""
        was_open = self.palette_open
        text = self.text()
        if text.startswith("/") and " " not in text:
            items = [c for c in completions
                     if c.startswith(text[1:].lower())]
            if items:
                self.palette_items = items
                self.palette_sel = min(self.palette_sel, len(items) - 1)
                self.palette_open = True
                return True
        self.palette_items = []
        self.palette_sel = 0
        self.palette_open = False
        return was_open

    def palette_accept(self) -> None:
        """Replace the buffer with the selected suggestion."""
        if self.palette_open and self.palette_items:
            self._set("/" + self.palette_items[self.palette_sel] + " ")
            self.palette_open = False
            self.palette_items = []

    # -- the key switch ---------------------------------------------------

    def update(self, ev: KeyEvent) -> Tuple[str, str]:
        """Apply one event. Returns (action, payload):

            none      — nothing app-level to do
            changed   — buffer/cursor/palette changed (repaint)
            submit    — payload = line to dispatch
            interrupt — ctrl-c (app decides: abort / clear / quit)
            eof       — ctrl-d on empty input
            esc       — lone Esc (abort engagement / clear buffer)
            redraw    — ctrl-l
            complete  — tab with palette open
        """
        k = ev.kind
        if k == "text":
            # single-line editor: pasted newlines soften to spaces
            # (no accidental submit; the operator presses Enter)
            self.buffer.insert(self.cursor, ev.text.replace("\n", " "))
            self.cursor += 1
            self.hist_idx = None
            return ("changed", "")
        if k == "paste-start" or k == "paste-end":
            return ("none", "")          # paste text arrives as 'text'
        if k == "enter":
            line = self.text()
            self._set("")
            if line.strip() and (not self.history
                                 or self.history[-1] != line):
                self.history.append(line)
            return ("submit", line)
        if k == "backspace":
            if self.cursor > 0:
                del self.buffer[self.cursor - 1]
                self.cursor -= 1
                self.hist_idx = None
                return ("changed", "")
            return ("none", "")
        if k == "delete":
            if self.cursor < len(self.buffer):
                del self.buffer[self.cursor]
                self.hist_idx = None
                return ("changed", "")
            return ("none", "")
        if k == "left":
            self.cursor = max(0, self.cursor - 1)
            return ("changed", "")
        if k == "right":
            if self.palette_open:
                self.palette_accept()
                return ("changed", "")
            self.cursor = min(len(self.buffer), self.cursor + 1)
            return ("changed", "")
        if k == "home" or k == "ctrl-a":
            self.cursor = 0
            return ("changed", "")
        if k == "end" or k == "ctrl-e":
            self.cursor = len(self.buffer)
            return ("changed", "")
        if k == "ctrl-b":
            self.cursor = max(0, self.cursor - 1)
            return ("changed", "")
        if k == "ctrl-f":
            self.cursor = min(len(self.buffer), self.cursor + 1)
            return ("changed", "")
        if k == "ctrl-k":
            self.last_kill = "".join(self.buffer[self.cursor:])
            del self.buffer[self.cursor:]
            return ("changed", "")
        if k == "ctrl-u":
            self.last_kill = "".join(self.buffer[:self.cursor])
            del self.buffer[:self.cursor]
            self.cursor = 0
            return ("changed", "")
        if k == "ctrl-w":
            i = self._in_word_left()
            self.last_kill = "".join(self.buffer[i:self.cursor])
            del self.buffer[i:self.cursor]
            self.cursor = i
            return ("changed", "")
        if k == "ctrl-y":
            for ch in self.last_kill:
                self.buffer.insert(self.cursor, ch)
                self.cursor += 1
            return ("changed", "")
        if k == "up":
            if self.palette_open:
                self.palette_sel = max(0, self.palette_sel - 1)
                return ("changed", "")
            if self.history:
                if self.hist_idx is None:
                    self.draft = self.text()
                    self.hist_idx = len(self.history) - 1
                elif self.hist_idx > 0:
                    self.hist_idx -= 1
                self._set_history()
                return ("changed", "")
            return ("none", "")
        if k == "down":
            if self.palette_open:
                self.palette_sel = min(len(self.palette_items) - 1,
                                       self.palette_sel + 1)
                return ("changed", "")
            if self.hist_idx is not None:
                if self.hist_idx < len(self.history) - 1:
                    self.hist_idx += 1
                    self._set_history()
                else:
                    self.hist_idx = None
                    self._set(self.draft)
                return ("changed", "")
            return ("none", "")
        if k == "tab":
            if self.palette_open:
                self.palette_accept()
                return ("changed", "")
            return ("complete", "")
        if k == "ctrl-c":
            return ("interrupt", "")
        if k == "ctrl-d":
            if not self.buffer:
                return ("eof", "")
            if self.cursor < len(self.buffer):
                del self.buffer[self.cursor]
                return ("changed", "")
            return ("none", "")
        if k == "esc":
            return ("esc", "")
        if k == "ctrl-l":
            return ("redraw", "")
        return ("none", "")

    def _set_history(self) -> None:
        text = self.history[self.hist_idx]
        self.buffer = list(text)
        self.cursor = len(self.buffer)
