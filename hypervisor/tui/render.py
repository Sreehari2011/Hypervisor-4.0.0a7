"""hypervisor.tui.render — the TUI's visual language (UX-01).

Every styled string the app paints is built here, so the look lives
in one place. The reference aesthetic is the Codex / Claude Code
terminal family: charcoal-friendly dark palette, muted labels with
bold values, a thin-bordered header card, an elevated input block,
and quiet one-line tool markers — the same +/! marks the headless
line renderer prints (operator muscle memory), plus the tool name.

Palette (xterm-256, chosen to read on #1e1e1e-class backgrounds):
  text 252 · muted 245 · dim 240 · brand 141 · ok 114 · err 203
  info 80 · warn 179 · input-block bg 236 · border 240
"""
from __future__ import annotations

import textwrap
from typing import List, Optional

from .term import BOLD, DIM, RESET, fg, len_plain

# ─── palette ────────────────────────────────────────────────────────────

C_TEXT = 252
C_MUTED = 245
C_DIM = 240
C_BRAND = 141
C_OK = 114
C_ERR = 203
C_INFO = 80
C_WARN = 179
C_BORDER = 240
C_INPUT_BG = 236

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def text(s: str) -> str:
    return fg(s, C_TEXT)


def muted(s: str) -> str:
    return fg(s, C_MUTED)


def dim(s: str) -> str:
    return fg(s, C_DIM)


def brand(s: str, bold: bool = True) -> str:
    return fg(s, C_BRAND, bold=bold)


def ok(s: str) -> str:
    return fg(s, C_OK)


def err(s: str) -> str:
    return fg(s, C_ERR)


def info(s: str) -> str:
    return fg(s, C_INFO)


def warn(s: str) -> str:
    return fg(s, C_WARN)


def label_value(label: str, value: str) -> str:
    """Codex-style 'model: gpt-5.4 low' — muted label, bright value."""
    return muted(label) + " " + fg(value, 15, bold=True)


# ─── box drawing ────────────────────────────────────────────────────────

def card(lines: List[str], width: int = 64) -> List[str]:
    """Rounded single-line box. `lines` are already styled; wrapping is
    the caller's job (plain width must fit)."""
    inner = max((len_plain(l) for l in lines), default=0)
    inner = max(inner, min(width, 72))
    out = [fg("╭" + "─" * (inner + 2) + "╮", C_BORDER)]
    for l in lines:
        pad = inner - len_plain(l)
        out.append(fg("│", C_BORDER) + " " + l + " " * max(0, pad)
                   + " " + fg("│", C_BORDER))
    out.append(fg("╰" + "─" * (inner + 2) + "╯", C_BORDER))
    return out


# ─── transcript blocks ──────────────────────────────────────────────────

def wrap_plain(s: str, width: int) -> List[str]:
    """Wrap plain text; styled callers wrap BEFORE styling."""
    if not s:
        return [""]
    return textwrap.wrap(s, width=max(16, width),
                         break_long_words=True,
                         break_on_hyphens=False)


def user_echo(line: str) -> List[str]:
    """The dim echo of the operator's own input (Claude Code style)."""
    return [fg("❯ ", C_MUTED) + fg(line, C_TEXT, bold=True)]


def assistant_line(s: str) -> str:
    return fg("● ", C_BRAND) + text(s)


def tool_line(okay: bool, name: str, head: str) -> str:
    mark = ok("+") if okay else err("!")
    return (fg("  ⎿ ", C_DIM) + mark + " " + fg(name, C_INFO)
            + muted(" · ") + muted(head))


def transition_line(name: str, turn: int) -> str:
    return dim(f"  ~ {name} (turn {turn})")


def system_line(s: str) -> str:
    return muted("  · ") + muted(s)


def error_line(s: str) -> str:
    return err("  ✗ ") + err(s)


def hint_line(s: str) -> str:
    return warn("  → ") + warn(s)


def section_line(s: str) -> str:
    return fg(f"── {s} ", C_DIM) + fg("─" * 30, C_DIM)


def kv_line(label: str, value: str) -> str:
    return "  " + muted(f"{label:<12}") + " " + fg(value, C_TEXT)


# ─── header card (the Codex config box) ────────────────────────────────

def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def header_card(version: str, model: str, workspace: str,
                scope_line: str, width: int = 64) -> List[str]:
    lines = [
        brand("⚡ AEGIS Hypervisor", bold=True) + muted("  operator TUI"),
        label_value("version:", _trunc(version, 40)),
        label_value("model:", _trunc(model, 40)),
        label_value("workspace:", _trunc(workspace, 46)),
        label_value("scope:", _trunc(scope_line, 46)),
    ]
    return card(lines, width=width)


def tip_card(lines: List[str], width: int = 64) -> List[str]:
    return card([fg("Tip: ", C_TEXT, bold=True) + l for l in lines],
                width=width)


# ─── footer ─────────────────────────────────────────────────────────────

def input_line(buffer: str) -> str:
    """The elevated input block's text row: muted '>' prompt."""
    return fg("> ", C_MUTED) + text(buffer) + fg(" ", C_INPUT_BG)


def status_idle(model: str, workspace: str, scope_armed: bool) -> str:
    scope = ok("scope armed") if scope_armed else warn("no scope")
    return (fg("·", C_DIM) + muted(f" {model} · {workspace} · ")
            + scope)


def status_running(model: str, turn: int, tokens: int,
                   elapsed_s: float, frame: int) -> str:
    spin = fg(SPINNER[frame % len(SPINNER)], C_BRAND)
    tok = f"{tokens / 1000:.1f}k tok" if tokens >= 1000 \
        else f"{tokens} tok"
    return (spin + brand(" engaging", bold=False)
            + muted(f" · turn {max(1, turn)} · {tok} · {elapsed_s:.0f}s"))


def palette_rows(items: List[str], sel: int, hints: dict) -> List[str]:
    rows = []
    for i, name in enumerate(items[:7]):
        hint = hints.get(name, "")
        sel_mark = fg("▸ ", C_BRAND) if i == sel else "  "
        if i == sel:
            rows.append(sel_mark + fg("/" + name, 15, bold=True)
                        + dim(f"  {hint}"))
        else:
            rows.append(sel_mark + fg("/" + name, C_TEXT)
                        + dim(f"  {hint}"))
    return rows


def fmt_tokens(n: int) -> str:
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)
