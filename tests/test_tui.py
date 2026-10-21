"""UX-01 operator TUI — acceptance tests.

Offline units for every load-bearing piece (command registry, key
parser, line editor, palette, render language, stream sanitizer, the
cli bare-tty hook, workspace-reading handlers) plus one pty-driven
smoke test that boots the real TUI in a pseudo-terminal, drives it
through /help and /quit, and asserts the rendered surface.

The engine bridge (tui.engage) is intentionally NOT faked here
beyond import shape: its chain is cli.main's chain, exercised by the
existing E2E suites; what is new is the presentation, and that is
what these tests pin.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from hypervisor.tui import commands as CMDS            # noqa: E402
from hypervisor.tui import render as R                  # noqa: E402
from hypervisor.tui.editor import (KeyEvent, KeyParser,  # noqa: E402
                                   LineEditor)
from hypervisor.tui import term as T                     # noqa: E402
from hypervisor.tui import engage as ENG                # noqa: E402


# ─── harness ────────────────────────────────────────────────────────────

class FakeApp:
    """The command-surface contract from tui.app, minus the terminal."""

    def __init__(self, tmp_path):
        self.sf = None
        self.scope_path = None
        self.workspace = Path(tmp_path)
        self.messages = []
        self.session_id = None
        self.engagement = None
        self.cols = 100
        self.lines = []
        self.jobs = []
        self.quit_called = False
        self.cleared = 0
        self.engaged = []

    # surface
    def say(self, line):
        self.lines.append(line)

    def say_lines(self, lines):
        self.lines.extend(lines)

    def err(self, text):
        self.lines.append(("ERR", text))

    def hint(self, text):
        self.lines.append(("HINT", text))

    def run_job(self, title, fn):
        self.jobs.append((title, fn))

    def start_engagement(self, text):
        self.engaged.append(text)

    def clear_view(self):
        self.cleared += 1

    def quit(self):
        self.quit_called = True

    def plain(self):
        return [T.len_plain(l) if isinstance(l, str) else l
                for l in self.lines]

    def text(self):
        import re
        out = []
        for l in self.lines:
            s = l if isinstance(l, str) else str(l)
            out.append(re.sub(r"\x1b\[[0-9;]*m", "", s))
        return "\n".join(out)


SCOPE_JSON = {
    "mode": "strict",
    "targets": [{
        "target": "10.10.0.5", "type": "ip", "ports": [22, 80, 443],
        "protocols": ["tcp", "http", "https"], "authorized": True,
        "authorization_token": "TEST/2026-10-15/ref",
        "expires_at": None}],
    "excludes": [],
    "roe": {"poc_only": True, "allow_persistent_payloads": False,
            "destructive_allowed": False},
}


@pytest.fixture
def app(tmp_path):
    return FakeApp(tmp_path)


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(SCOPE_JSON), encoding="utf-8")
    return p


# ─── command registry ──────────────────────────────────────────────────

def test_registry_covers_the_pinned_surface():
    required = {
        # REFACTOR-06 reserved 3.x muscle-memory names
        "scope", "compact", "reset", "health", "report", "resume",
        # the UX-01 additions
        "engage", "status", "doctor", "test", "journal", "ekd",
        "agents", "watchdog", "workspace", "help", "version", "clear",
        "quit",
    }
    assert required <= set(CMDS.REGISTRY)
    for c in CMDS.REGISTRY.values():
        assert callable(c.handler)
        assert c.help


def test_every_command_has_a_group():
    groups = {"engagement", "diagnostics", "session", "general"}
    for c in CMDS.REGISTRY.values():
        assert c.group in groups, c.name


def test_help_lists_every_command(app):
    CMDS.REGISTRY["help"].handler(app, "")
    body = app.text()
    for name in CMDS.REGISTRY:
        assert f"/{name}" in body


def test_unknown_command_is_a_hint_not_a_crash(app):
    CMDS.dispatch(app, "/definitely-not-a-command")
    assert any("unknown command" in str(l) for l in app.lines)


def test_free_text_without_scope_hints(app):
    CMDS.dispatch(app, "hello agent")
    assert any("scope" in str(l) for l in app.lines)
    assert app.engaged == []


def test_free_text_with_scope_engages(app, scope_file):
    CMDS.REGISTRY["scope"].handler(app, str(scope_file))
    CMDS.dispatch(app, "do the assessment")
    assert app.engaged == ["do the assessment"]


# ─── handlers that read workspace state ────────────────────────────────

def test_scope_load_and_card(app, scope_file):
    CMDS.REGISTRY["scope"].handler(app, str(scope_file))
    assert app.sf is not None
    body = app.text()
    assert "mode:" in body and "strict" in body
    assert "rules:" in body
    assert "scope armed" in body


def test_scope_missing_file_is_an_error(app):
    CMDS.REGISTRY["scope"].handler(app, "/nope/missing.json")
    assert app.sf is None
    assert any("not found" in str(l) for l in app.lines)


def test_scope_invalid_json_is_an_error(app):
    p = app.workspace / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    CMDS.REGISTRY["scope"].handler(app, str(p))
    assert app.sf is None
    assert any("INVALID" in str(l) for l in app.lines)


def test_journal_tail(app):
    jd = app.workspace / ".aegis" / "journal"
    jd.mkdir(parents=True)
    rows = [
        {"seq": 1, "type": "boot", "rev": 0, "data": {"mode": "strict"}},
        {"seq": 2, "type": "ekd_mutation", "rev": 1,
         "data": {"rev_after": 1, "reason": "objective_commit"}},
        {"seq": 3, "type": "permission_decision", "rev": 1,
         "data": {"tool": "run_command", "allowed": False,
                  "reason": "target 10.9.9.9 out of scope"}},
        {"seq": 4, "type": "loop_transition", "rev": 1,
         "data": {"transition": "next_turn"}},
    ]
    with (jd / "journal.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    CMDS.REGISTRY["journal"].handler(app, "")
    body = app.text()
    assert "objective_commit" in body
    assert "DENY run_command" in body
    assert "next_turn" in body
    assert "4 events" in body


def test_ekd_summary(app):
    app.workspace.joinpath("ekd.json").write_text(json.dumps({
        "version": 2, "rev": 172, "counters": {"m": 44},
        "nodes": {"a": {}, "b": {}}, "edges": [{"e": 1}]}),
        encoding="utf-8")
    CMDS.REGISTRY["ekd"].handler(app, "")
    body = app.text()
    assert "172" in body and "2" in body


def test_report_falls_back_to_findings(app):
    app.workspace.joinpath("report_findings.md").write_text(
        "# findings\n\nCVE tested, not exploitable.", encoding="utf-8")
    CMDS.REGISTRY["report"].handler(app, "")
    assert "CVE tested" in app.text()


def test_report_missing_hints(app):
    CMDS.REGISTRY["report"].handler(app, "")
    assert any("no report" in str(l) for l in app.lines)


def test_resume_listing_and_load(app):
    sdir = app.workspace / ".aegis" / "sessions"
    sdir.mkdir(parents=True)
    from hypervisor.persist.sessions import SessionStore
    store = SessionStore(sdir, session_id="sess-001")
    store.record_user("first objective")
    store.record_meta("boot", {"purpose": "main"})
    CMDS.REGISTRY["resume"].handler(app, "")
    assert "sess-001" in app.text()
    CMDS.REGISTRY["resume"].handler(app, "sess-001")
    assert app.session_id == "sess-001"
    assert len(app.messages) == 1
    assert app.messages[0]["content"] == "first objective"


def test_reset_clears_conversation_keeps_scope(app, scope_file):
    CMDS.REGISTRY["scope"].handler(app, str(scope_file))
    app.messages = [{"role": "user", "content": "x"}]
    app.session_id = "s1"
    CMDS.REGISTRY["reset"].handler(app, "")
    assert app.messages == [] and app.session_id is None
    assert app.sf is not None


def test_engage_requires_scope(app):
    CMDS.REGISTRY["engage"].handler(app, "go")
    assert app.engaged == []
    assert any("scope" in str(l) for l in app.lines)


def test_engage_requires_objective(app, scope_file):
    CMDS.REGISTRY["scope"].handler(app, str(scope_file))
    CMDS.REGISTRY["engage"].handler(app, "   ")
    assert app.engaged == []


def test_doctor_and_test_use_the_job_runner(app):
    CMDS.REGISTRY["doctor"].handler(app, "")
    CMDS.REGISTRY["test"].handler(app, "")
    titles = [t for t, _ in app.jobs]
    assert "doctor" in titles and "pytest" in titles
    # jobs deferred to the runner: nothing printed synchronously
    assert app.lines == []


def test_doctor_job_runs_and_reports(app):
    CMDS.REGISTRY["doctor"].handler(app, "")
    _, fn = app.jobs[0]
    pushed = []
    import threading
    fn(pushed.append, threading.Event())
    assert any("doctor:" in p for p in pushed)


def test_health_is_offline(app):
    CMDS.REGISTRY["health"].handler(app, "")
    body = app.text()
    assert "endpoint:" in body and "model:" in body


def test_watchdog_knobs(app):
    CMDS.REGISTRY["watchdog"].handler(app, "")
    body = app.text()
    assert "turn_budget_s" in body and "blocking_ratio" in body


def test_version_command(app):
    CMDS.REGISTRY["version"].handler(app, "")
    from hypervisor import __version__
    assert __version__ in app.text()


# ─── key parser ─────────────────────────────────────────────────────────

def test_keyparser_utf8_split_across_feeds():
    p = KeyParser()
    assert p.feed("é".encode("utf-8")[:1]) == []
    evs = p.feed("é".encode("utf-8")[1:])
    assert [(e.kind, e.text) for e in evs] == [("text", "é")]


def test_keyparser_arrows_and_controls():
    p = KeyParser()
    evs = p.feed(b"\x1b[D\x1b[C\x1b[A\x1b[B\x1b[H\x1b[F\x1b[3~\x7f\r\x03")
    kinds = [e.kind for e in evs]
    assert kinds == ["left", "right", "up", "down", "home", "end",
                     "delete", "backspace", "enter", "ctrl-c"]


def test_keyparser_lone_esc_resolves_on_idle():
    p = KeyParser()
    p.feed(b"\x1b")
    assert p.flush_idle() == []
    time.sleep(0.05)
    assert [e.kind for e in p.flush_idle()] == ["esc"]


def test_keyparser_bracketed_paste_newlines_are_data():
    p = KeyParser()
    evs = p.feed(b"\x1b[200~multi\nline\x1b[201~")
    kinds = [(e.kind, e.text) for e in evs]
    assert kinds[0] == ("paste-start", "")
    assert ("text", "\n") in kinds
    assert kinds[-1] == ("paste-end", "")


def test_keyparser_ignores_unknown_sequences():
    p = KeyParser()
    evs = p.feed(b"\x1b[2015~\x1b[Z\x00")
    kinds = [e.kind for e in evs]
    assert kinds == ["ignore", "shift-tab"]


# ─── line editor ────────────────────────────────────────────────────────

def feed_keys(editor, keys):
    for k in keys:
        if isinstance(k, str) and len(k) == 1:
            ev = KeyEvent("text", k)
        else:
            ev = KeyEvent(k)
        editor.update(ev)


def test_editor_typing_and_cursor_movement():
    ed = LineEditor()
    feed_keys(ed, "hello")
    assert ed.text() == "hello" and ed.cursor == 5
    feed_keys(ed, ["left", "left"])
    assert ed.cursor == 3
    feed_keys(ed, "XY")
    assert ed.text() == "helXYlo"
    feed_keys(ed, ["end"])
    assert ed.cursor == 7


def test_editor_backspace_delete_and_kills():
    ed = LineEditor()
    feed_keys(ed, "abc def")
    feed_keys(ed, ["ctrl-w"])               # kill "def"
    assert ed.text() == "abc "
    feed_keys(ed, ["ctrl-y"])               # yank back
    assert ed.text() == "abc def"
    feed_keys(ed, ["home", "ctrl-k"])       # kill to end from start
    assert ed.text() == ""
    feed_keys(ed, "xy")
    feed_keys(ed, ["ctrl-u"])               # kill from start to cursor
    assert ed.text() == ""


def test_editor_history_with_draft_preservation():
    ed = LineEditor(history=["one", "two"])
    feed_keys(ed, "draf")
    feed_keys(ed, ["up", "up"])
    assert ed.text() == "one"
    feed_keys(ed, ["down"])
    assert ed.text() == "two"
    feed_keys(ed, ["down"])
    assert ed.text() == "draf"


def test_editor_submit_clears_and_records_history():
    ed = LineEditor()
    feed_keys(ed, "first")
    action, payload = ed.update(KeyEvent("enter"))
    assert (action, payload) == ("submit", "first")
    assert ed.text() == ""
    assert ed.history == ["first"]


def test_editor_ctrl_c_and_ctrl_d():
    ed = LineEditor()
    assert ed.update(KeyEvent("ctrl-c"))[0] == "interrupt"
    assert ed.update(KeyEvent("ctrl-d"))[0] == "eof"


def test_editor_pasted_newlines_soften_to_spaces():
    ed = LineEditor()
    ed.update(KeyEvent("text", "run this\nand that"))
    assert ed.text() == "run this and that"


# ─── palette ────────────────────────────────────────────────────────────

def test_palette_filters_and_completes():
    ed = LineEditor()
    feed_keys(ed, "/re")
    ed.refresh_palette(CMDS.completions())
    assert ed.palette_open
    assert set(ed.palette_items) == {"report", "reset", "resume"}
    ed.update(KeyEvent("tab"))
    assert ed.text() == "/report "


def test_palette_closes_on_space_and_non_slash():
    ed = LineEditor()
    feed_keys(ed, "/sc")
    ed.refresh_palette(CMDS.completions())
    assert ed.palette_open
    ed.update(KeyEvent("text", " "))
    ed.refresh_palette(CMDS.completions())
    assert not ed.palette_open
    ed._set("plain text")
    ed.refresh_palette(CMDS.completions())
    assert not ed.palette_open


def test_palette_navigation():
    ed = LineEditor()
    feed_keys(ed, "/r")
    ed.refresh_palette(CMDS.completions())
    n = len(ed.palette_items)
    assert n >= 3
    ed.update(KeyEvent("up"))               # wraps to top, stays valid
    ed.update(KeyEvent("down"))
    expected = ed.palette_items[ed.palette_sel]
    ed.update(KeyEvent("tab"))
    assert ed.text() == "/" + expected + " "


# ─── render language ────────────────────────────────────────────────────

def test_len_plain_ignores_sgr():
    assert T.len_plain(R.assistant_line("hello")) == 7    # "● " + 5
    assert T.len_plain("") == 0


def test_header_card_shape():
    rows = R.header_card("4.0.0a6", "cisai-ultra", "/app/ws",
                         "sha256:abcd@v1 · strict")
    assert rows[0].startswith(T.ESC) or "╭" in rows[0]
    assert any("model:" in r for r in rows)
    assert any("scope:" in r for r in rows)
    widths = {T.len_plain(r) for r in rows}
    assert len(widths) == 1                  # box is rectangular


def test_tool_line_marks_match_the_line_renderer():
    okl = R.tool_line(True, "nmap", "80/tcp open")
    errl = R.tool_line(False, "run_command", "denied")
    assert "+" in okl and "nmap" in okl
    assert "!" in errl


def test_sanitize_stream_strips_terminal_controls():
    dirty = "\x1b[31mred\x1b[0m\x1b]0;title\x07bell\x07\x00\x1bM\rcrlf\r\nok\ttab"
    clean = ENG.sanitize_stream(dirty)
    assert T.ESC not in clean
    assert "\x1b" not in clean and "\x07" not in clean and "\x00" not in clean
    assert "crlf\nok\ttab" in clean


# ─── cli hook ───────────────────────────────────────────────────────────

def test_cli_bare_tty_launches_tui(monkeypatch):
    import hypervisor.cli as cli
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    called = []
    monkeypatch.setattr("hypervisor.tui.run_tui",
                        lambda argv=None: called.append(True) or 42)
    assert cli.main([]) == 42
    assert called


def test_cli_bare_non_tty_keeps_headless_contract(monkeypatch, capsys):
    import hypervisor.cli as cli
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    rc = cli.main([])
    assert rc == cli.EXIT_SCOPE_ERROR
    assert "engagement mode requires" in capsys.readouterr().err


def test_cli_flag_paths_untouched(capsys):
    import hypervisor.cli as cli
    assert cli.main(["--version"]) == 0
    assert "hypervisor" in capsys.readouterr().out


# ─── pty smoke — the real TUI, no human ────────────────────────────────

def test_pty_smoke_help_and_quit():
    pytest.importorskip("pty")
    import pty
    import subprocess

    env = dict(os.environ, TERM="xterm-256color",
               PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "hypervisor.tui"],
        cwd=str(REPO), env=env, stdin=slave, stdout=slave,
        stderr=subprocess.DEVNULL, close_fds=True)
    os.close(slave)
    try:
        import fcntl
        import struct
        import termios as _termios
        fcntl.ioctl(master, _termios.TIOCSWINSZ,
                    struct.pack("hhhh", 30, 100, 0, 0))

        def read_until(patterns, timeout=12.0):
            buf = b""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                import select as _s
                r, _, _ = _s.select([master], [], [], 0.2)
                if r:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    if any(p in buf for p in patterns):
                        return buf
            return buf

        out = read_until([b"scope:"])       # header card row (the OSC
        assert b"AEGIS Hypervisor" in out, "header card did not render"
        assert b"scope" in out               # title alone would match
        assert b"model:" in out and b"workspace:" in out

        time.sleep(0.3)
        os.write(master, b"/help\r")
        out2 = read_until([b"/journal"])
        assert b"/doctor" in out2 and b"/engage" in out2, \
            "help listing incomplete"

        time.sleep(0.2)
        os.write(master, b"/version\r")
        out3 = read_until([b"4.0.0"], timeout=6.0)
        assert b"4.0.0" in out3

        time.sleep(0.2)
        os.write(master, b"/quit\r")
        rc = proc.wait(timeout=8.0)
        assert rc == 0, f"unexpected exit {rc}"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)
        os.close(master)
