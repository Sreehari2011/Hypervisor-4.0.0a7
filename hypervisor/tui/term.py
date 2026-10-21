"""hypervisor.tui.term — terminal control layer (UX-01).

The geometry/raw-mode half of the operator TUI. Pure stdlib (termios,
tty, fcntl, signal, select) — the P0 stdlib-only discipline is honored
exactly: the TUI adds ZERO runtime dependencies beyond what the
Dockerfile already ships (Test-4 contract intact).

Rendering model (Claude-Code-shaped, Codex-styled):

  * the header card is printed ONCE before the scroll region is armed,
    so it scrolls up into the terminal's native scrollback like any
    other output — nothing is trapped in an alt-screen;
  * rows [1 .. h-footer] are an ANSI scroll region (DECSTTM): every
    transcript line is written at the region's bottom row and the
    region scrolls itself — lines that leave the screen stay in the
    terminal's scrollback buffer (zero display-data loss);
  * the footer (palette suggestions + status + input block) lives
    BELOW the region and is redrawn in place, never scrolled.

Resize: SIGWINCH sets a flag the app polls; relayout() re-arms the
region, blanks rows that just joined it, and repaints the footer.

Terminal floor: below MIN_ROWS the region degenerates to a single row
and the footer to the input line alone — the app keeps working.
"""
from __future__ import annotations

import fcntl
import os
import signal
import struct
import sys
import termios
import tty
from typing import List, Optional, Tuple

MIN_ROWS = 8
MIN_COLS = 20

# ─── ANSI primitives ────────────────────────────────────────────────────

ESC = "\x1b"
CSI = ESC + "["


def cup(row: int, col: int) -> str:
    """Cursor absolute position (1-based)."""
    return f"{CSI}{row};{col}H"


def el(mode: int = 0) -> str:
    """Erase in line: 0=cursor..end 1=start..cursor 2=whole line."""
    return f"{CSI}{mode}K"


def set_region(top: int, bottom: int) -> str:
    """DECSTTM scroll region (1-based inclusive)."""
    return f"{CSI}{top};{bottom}r"


BRACKETED_PASTE_ON = ESC + "[?2004h"
BRACKETED_PASTE_OFF = ESC + "[?2004l"
HIDE_CURSOR = ESC + "[?25l"
SHOW_CURSOR = ESC + "[?25h"
CLEAR_SCREEN = ESC + "[2J" + cup(1, 1)


def sgr(*codes: int) -> str:
    return f"{CSI}{''.join(f'{c};' for c in codes[:-1])}{codes[-1]}m" \
        if codes else ""


RESET = sgr(0)
BOLD = sgr(1)
DIM = sgr(2)


# ─── Terminal — raw mode + size + signals ──────────────────────────────

class Terminal:
    """Owns the tty: raw mode for the app's lifetime, window size
    queries, and a cooperative SIGWINCH flag (never resizes mid-write
    — the app polls `resized` between frames)."""

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.resized = False
        self._saved: Optional[list] = None
        self._orig_winch = None
        self._active = False

    # -- lifecycle ------------------------------------------------------

    def __enter__(self) -> "Terminal":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        if self._active or not self.stdin.isatty():
            return
        self._active = True
        try:
            self._saved = termios.tcgetattr(self.stdin.fileno())
        except (termios.error, OSError):
            self._saved = None
        try:
            tty.setraw(self.stdin.fileno())
        except (termios.error, OSError):
            pass
        try:
            self._orig_winch = signal.getsignal(signal.SIGWINCH)
            signal.signal(signal.SIGWINCH, self._on_winch)
        except (ValueError, OSError):
            pass
        self.write(BRACKETED_PASTE_ON)
        self.flush()

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        self.write(RESET + BRACKETED_PASTE_OFF + SHOW_CURSOR)
        # park the cursor somewhere sane before handing the tty back
        self.write(f"{CSI}999;1H" + "\n\r")
        self.flush()
        try:
            if self._orig_winch is not None:
                signal.signal(signal.SIGWINCH, self._orig_winch)
        except (ValueError, OSError):
            pass
        if self._saved is not None:
            try:
                termios.tcsetattr(self.stdin.fileno(),
                                  termios.TCSADRAIN, self._saved)
            except (termios.error, OSError):
                pass

    def _on_winch(self, signum, frame) -> None:
        self.resized = True
        # chain to a previously installed handler when it is callable
        h = self._orig_winch
        if callable(h) and h not in (signal.SIG_DFL, signal.SIG_IGN):
            try:
                h(signum, frame)
            except Exception:
                pass

    # -- geometry -------------------------------------------------------

    def size(self) -> Tuple[int, int]:
        """(rows, cols) via TIOCGWINSZ; falls back to the environment,
        then to a conservative 24x80."""
        try:
            data = fcntl.ioctl(self.stdin.fileno(), termios.TIOCGWINSZ,
                               b"\x00" * 8)
            rows, cols = struct.unpack("hhhh", data)[:2]
            if rows > 0 and cols > 0:
                return rows, cols
        except (OSError, struct.error, ValueError):
            pass
        try:
            return (int(os.environ.get("LINES") or 24),
                    int(os.environ.get("COLUMNS") or 80))
        except ValueError:
            return 24, 80

    # -- output ---------------------------------------------------------

    def write(self, text: str) -> None:
        try:
            self.stdout.write(text)
        except (OSError, ValueError):
            pass

    def flush(self) -> None:
        try:
            self.stdout.flush()
        except (OSError, ValueError):
            pass


# ─── Screen — scroll region + pinned footer ────────────────────────────

class Screen:
    """One frame layout:

        rows 1 .. h-F      transcript scroll region
        rows h-F+1 .. h    footer: [palette rows] [status] [input]

    `emit()` appends a transcript line at the region bottom (the
    terminal scrolls the region; scrolled-off lines survive in the
    terminal's own scrollback). `render_footer()` redraws the pinned
    block in place. The input block gets a subtle background fill so
    it reads as the elevated active pane (the Codex reference layout).
    """

    def __init__(self, term: Terminal):
        self.term = term
        self.rows, self.cols = term.size()
        self.palette_rows: List[str] = []      # pre-rendered overlay lines
        self.status_text = ""
        self.input_text = ""
        self.cursor_col = 0                    # 0-based col in input_text
        self.input_bg_width = 0                # shaded block width
        self._region_bottom = 0                # last armed region bottom
        self._footer_frozen = False            # tiny-terminal fallback

    # -- layout ---------------------------------------------------------

    def footer_size(self) -> int:
        """Pinned rows BELOW the scroll region: status + input. The
        palette is an OVERLAY inside the region's bottom rows (the
        Claude-Code floating-popover shape), so opening it never
        re-arms the region and never eats transcript rows beyond the
        ones it visually covers."""
        if self._footer_frozen:
            return 1
        return 2

    def region_bottom(self) -> int:
        return max(1, self.rows - self.footer_size())

    def relayout(self) -> None:
        """Re-measure + re-arm the region + repaint. The region is
        FIXED at rows 1..h-2 (transcript) with the two pinned footer
        rows below; only a resize re-arms it."""
        self.rows, self.cols = self.term.size()
        self.term.resized = False
        if self.rows < MIN_ROWS:
            self._footer_frozen = True
        new_bottom = self.region_bottom()
        self._region_bottom = new_bottom
        if not self._footer_frozen and new_bottom > 0:
            self.term.write(set_region(1, new_bottom))
        self.term.write(cup(new_bottom, 1))
        self.render_footer()

    # -- transcript -----------------------------------------------------

    def emit(self, text: str) -> None:
        """Append one (already-styled) line to the transcript."""
        if self._footer_frozen:
            self.term.write(text + "\r\n")
            self.term.flush()
            return
        b = max(1, self._region_bottom or self.region_bottom())
        self.term.write(cup(b, 1) + text + "\r\n")
        self.render_footer()

    def emit_many(self, lines: List[str]) -> None:
        for line in lines:
            self.emit(line)

    # -- streaming tail --------------------------------------------------

    def show_transient(self, text: str) -> None:
        """Render the in-flight stream tail in place at the region
        bottom (no scroll). The next emit() overwrites it, so the
        transient is purely visual — no data lands only here."""
        if self._footer_frozen:
            return
        b = max(1, self._region_bottom or self.region_bottom())
        self.term.write(cup(b, 1) + el(2) + text)
        self.render_footer()

    def clear_transient(self) -> None:
        if self._footer_frozen:
            return
        b = max(1, self._region_bottom or self.region_bottom())
        self.term.write(cup(b, 1) + el(2))
        self.render_footer()

    # -- footer ---------------------------------------------------------

    def set_palette(self, rows: List[str]) -> None:
        """Swap the floating palette overlay. Rows render INSIDE the
        region's bottom (above the pinned footer); closing blanks the
        covered rows — a small gap that heals as output flows."""
        if rows == self.palette_rows:
            return
        covered = len(self.palette_rows)
        self.palette_rows = rows
        b = self._region_bottom or self.region_bottom()
        for k in range(covered):
            self.term.write(cup(b - 1 - k, 1) + el(2))
        self.render_footer()

    def render_footer(self, status_text: str = None,
                      input_text: str = None,
                      cursor_col: int = None,
                      input_bg_width: int = None) -> None:
        if status_text is not None:
            self.status_text = status_text
        if input_text is not None:
            self.input_text = input_text
        if cursor_col is not None:
            self.cursor_col = cursor_col
        if input_bg_width is not None:
            self.input_bg_width = input_bg_width

        if self._footer_frozen:
            # degenerate layout: input line only, no region games
            self.term.write(cup(self.rows, 1) + el(2)
                            + self.input_text[: max(0, self.cols - 2)]
                            + cup(self.rows,
                                  min(self.cols,
                                      self.cursor_col + 1)))
            self.term.flush()
            return

        h, w = self.rows, self.cols
        b = self._region_bottom or self.region_bottom()
        # palette overlay: the bottom rows of the scroll region, just
        # above the pinned footer (floating popover shape)
        for i, row in enumerate(self.palette_rows):
            self.term.write(cup(b - 1 - i, 1) + el(2)
                            + row[: max(0, w - 1)])
        # status line (the context footer inside the input block)
        self.term.write(cup(h - 1, 1) + el(2))
        pad = " " * max(0, self.input_bg_width
                        - _len_plain(self.status_text))
        self.term.write(bg_fill(self.status_text + pad, 236))
        # input line
        self.term.write(cup(h, 1) + el(2))
        pad = " " * max(0, self.input_bg_width
                        - _len_plain(self.input_text))
        self.term.write(bg_fill(self.input_text + pad, 236))
        # park the cursor inside the input line
        self.term.write(cup(h, min(w, self.cursor_col + 1)))
        self.term.flush()


# ─── style helpers (256-color; safe on any dark terminal) ──────────────

def fg(text: str, color: int, *, bold: bool = False,
       dim: bool = False) -> str:
    pre = (BOLD if bold else "") + (DIM if dim else "") + sgr(38, 5, color)
    return f"{pre}{text}{RESET}"


def bg_fill(text: str, color: int) -> str:
    return f"{sgr(48, 5, color)}{text}{RESET}"


def _len_plain(text: str) -> int:
    """Printable width of a string that may carry SGR sequences."""
    n = 0
    i = 0
    while i < len(text):
        if text[i] == ESC and i + 1 < len(text) and text[i + 1] == "[":
            j = text.find("m", i + 2)
            if j < 0:
                break
            i = j + 1
            continue
        n += 1
        i += 1
    return n


# len_plain is part of the module's tested surface
len_plain = _len_plain


def clip_styled(text: str, width: int) -> str:
    """Truncate a styled (SGR-carrying) string to `width` printable
    columns, cutting only at plain-character boundaries and closing
    with a reset so a cut span can never bleed into what follows."""
    if _len_plain(text) <= width:
        return text
    out = []
    n = 0
    i = 0
    while i < len(text):
        if text[i] == ESC and i + 1 < len(text) and text[i + 1] == "[":
            j = text.find("m", i + 2)
            if j < 0:
                break
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if n >= width:
            break
        out.append(text[i])
        n += 1
        i += 1
    return "".join(out) + RESET
