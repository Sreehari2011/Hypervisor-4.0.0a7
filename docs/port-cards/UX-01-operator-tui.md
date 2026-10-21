# UX-01 — Operator TUI (Codex/Claude-Code-shaped front end)

**Status: ✅ DONE (P4/UX) · Target: `hypervisor/tui/` (+ an 11-line
non-destructive hook in `cli.py`)**

First card in the **UX family** — 4.0-native components with no 3.7.3
source to port (rule 1 covers 3.x behavior; new 4.0 surfaces get UX
cards with the same acceptance-test discipline). This one lands the
REFACTOR-06 deferral: "The interactive REPL with slash commands is
later polish on this same chain."

## What landed

A single-command interactive front end: bare `hypervisor` on a tty
boots a Codex/Claude-Code-style chat — header config card (version /
model / workspace / scope), streaming transcript, slash-command
palette with Tab completion, elevated input block with a live status
footer (spinner · turn · elapsed · EKD rev).

| module | role |
|---|---|
| `tui/term.py` | raw mode, TIOCGWINSZ + SIGWINCH, ANSI scroll region + pinned footer, 256-color styles |
| `tui/editor.py` | byte-stream key parser (UTF-8 incremental, CSI/SS3 assembly, lone-ESC by 40 ms quiet, bracketed paste with newline-softening) + readline-shaped editor (history w/ draft, kills, palette nav) |
| `tui/render.py` | the visual language: palette, box cards, `+/!` tool marks (line-renderer muscle memory), block formatters |
| `tui/commands.py` | the slash registry — every handler calls the SAME code path its CLI flag uses |
| `tui/engage.py` | the engine bridge: cli.main's chain mirrored module-for-module; LoopEvent pump + journal on_event tap |
| `tui/app.py` | select-tick main loop, op queue, Ctrl-C ladder (job → engagement-soft → engagement-hard → clear → quit) |

## Command surface

`/scope` `/workspace` `/engage` `/status` `/reset` (engagement) ·
`/doctor` `/test` `/journal` `/ekd` `/health` `/agents` `/watchdog`
(diagnostics) · `/resume` `/report` (session) · `/help` `/version`
`/clear` `/compact` `/quit` (general). The REFACTOR-06 reserved 3.x
names (`/scope /compact /reset /health /report /resume`) all exist.

## Contracts preserved

1. **Zero new dependencies** — pure stdlib (termios/tty/fcntl/signal/
   select). The P0 "stdlib-plus-one" discipline is untouched (the
   scaffold test now imports every tui module to keep it that way).
2. **Zero engine changes** — the TUI is a second consumer of the
   `LoopEvent` stream; `query_loop`, the gate, the journal and the
   session store are unmodified. No Go binary, no alt-screen trap.
3. **Zero display-data loss** — every event class the headless line
   renderer prints is rendered here, plus three things it cannot
   show: live scope-gate denials, tool names on results, and the
   live EKD revision (all sourced from the journal's `on_event`
   tap — a constructor parameter that already existed).
4. **Every CLI flag path untouched** — the hook fires only for bare
   `hypervisor` with stdin AND stdout ttys, and an import failure
   falls through to the old usage error (never crashes the CLI).
5. **Scrollback is native** — no alternate screen; scrolled-off
   transcript lines live in the terminal's own scrollback buffer.

## Acceptance tests (tests/test_tui.py)

- registry completeness incl. REFACTOR-06 names; every command
  grouped, documented, and crash-guarded (handler exceptions become
  error lines, never kill the TUI)
- free-text routing: no scope → hint; scope armed → engagement
- key parser: split UTF-8, arrows/home/end/delete, lone ESC by
  quiet-period, bracketed-paste newlines are data, unknown CSI
  sequences (`ESC[2015~`) resolve to ignore without leaking text
- editor: cursor ops, word/line kills + yank, history with draft
  preservation, paste softening, submit semantics
- palette: filter, complete, navigate; closes on space/non-slash
- render: SGR-aware width math, rectangular header card, the `+/!`
  marks, stream sanitizer strips ANSI/C1 (model output is untrusted)
- cli hook: bare+tty → TUI; bare+non-tty → old usage error;
  `--version` untouched
- workspace handlers against fabricated state: journal tail (with
  DENY rendering), EKD summary, report fallback, resume listing +
  chain reconstruction, reset semantics
- **pty smoke**: boots the real TUI in a pseudo-terminal, drives
  `/help` → `/version` → `/quit`, asserts the rendered surface and
  exit 0

## Landing results

- 44/44 tests green (offline units + pty smoke), full suite green,
  no regressions in the existing 300+ tests.
- pty hexdump verified: byte-exact ANSI (DECSTTM region, SGR
  256-color, OSC title), header card renders before first input.
- The engagement bridge is exercised through the same E2E suites the
  CLI uses; what this card adds on top is presentation, and that is
  what these tests pin.
