"""hypervisor.tui.commands — the slash-command registry (UX-01).

Every lengthy flag invocation the operator types today becomes one
token here, backed by the EXACT same code path the CLI flag uses —
/doctor calls hypervisor.doctor.run_doctor, /scope validates through
hypervisor.permissions.ScopeFile, /engage runs the same entry chain
cli.main drives. Nothing is re-implemented; nothing diverges.

Command set (REFACTOR-06 reserved the 3.x muscle-memory names —
/scope /compact /reset /health /report /resume all exist here):

  engagement : /scope /workspace /engage /status /reset
  diagnostics: /doctor /test /journal /ekd /health /agents /watchdog
  session    : /resume /report
  general    : /help /version /clear /compact /quit

Handlers receive (app, args) where app exposes the small surface
documented in app.py (say/say_lines/err/hint/run_job/...). That
surface is deliberately narrow so a fake app can drive every handler
in unit tests without a terminal.
"""
from __future__ import annotations

import io
import json
import os
import shlex
import subprocess
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import render as R
from .term import len_plain

REPO_ROOT = Path(__file__).resolve().parents[2]


class Command:
    def __init__(self, name: str, args: str, help: str, group: str,
                 handler: Callable) -> None:
        self.name = name
        self.args = args            # arg hint shown in the palette
        self.help = help
        self.group = group
        self.handler = handler


REGISTRY: Dict[str, Command] = {}


def command(name: str, args: str = "", help: str = "",
            group: str = "general", alias: Optional[str] = None):
    def deco(fn):
        REGISTRY[name] = Command(name, args, help, group, fn)
        if alias:
            REGISTRY[alias] = Command(alias, args, help, group, fn)
        return fn
    return deco


def completions() -> List[str]:
    return sorted(REGISTRY.keys())


def palette_hints() -> Dict[str, str]:
    return {c.name: (c.args or c.help).split(" — ")[0][:38]
            for c in REGISTRY.values()}


def dispatch(app, line: str) -> None:
    """Route one submitted input line: slash command or free text."""
    line = line.strip()
    if not line:
        return
    if line.startswith("/"):
        parts = line[1:].split(None, 1)
        name = (parts[0] or "").lower()
        args = parts[1].strip() if len(parts) > 1 else ""
        cmd = REGISTRY.get(name)
        if cmd is None:
            app.err(f"unknown command /{name} — /help lists everything")
            return
        try:
            cmd.handler(app, args)
        except Exception as exc:                    # handler bugs must
            app.err(f"/{name} failed: {type(exc).__name__}: {exc}")   # never
            return                                  # kill the TUI
        return
    # free text -> the agent
    if getattr(app, "engagement", None) is not None and \
            app.engagement.started:
        app.start_engagement(line)
    elif getattr(app, "sf", None) is not None:
        app.start_engagement(line)
    else:
        app.hint("free text goes to the agent once a scope is armed — "
                 "load one first: /scope <file>")


# ─── general ────────────────────────────────────────────────────────────

@command("help", help="list every command", group="general")
def _help(app, args):
    app.say_lines([R.section_line("AEGIS operator TUI")])
    groups: Dict[str, List[Command]] = {}
    for c in REGISTRY.values():
        groups.setdefault(c.group, []).append(c)
    for group in ("engagement", "diagnostics", "session", "general"):
        cmds = sorted(groups.get(group, []), key=lambda c: c.name)
        if not cmds:
            continue
        app.say(R.muted(f"  {group}"))
        for c in cmds:
            arg = R.dim(f" {c.args}") if c.args else ""
            app.say(f"    {R.fg('/' + c.name, 15, bold=True)}{arg}"
                    f"{R.dim('  — ' + c.help)}")
    app.say("")
    app.say(R.system_line(
        "free text (no slash) talks to the agent once /scope is armed; "
        "Tab completes commands; Ctrl-C aborts an engagement, twice quits"))
    app.say("")


@command("version", help="print the platform version")
def _version(app, args):
    from .. import __version__
    app.say(R.kv_line("version", __version__))


@command("quit", help="leave the TUI", alias="exit")
def _quit(app, args):
    app.quit()


@command("clear", help="clear the view (scrollback is kept by your terminal)")
def _clear(app, args):
    app.clear_view()


# ─── engagement ─────────────────────────────────────────────────────────

@command("scope", args="<file>", help="load + validate an operator scope",
         group="engagement")
def _scope(app, args):
    from ..permissions import ScopeFile
    if not args:
        if getattr(app, "sf", None) is not None:
            _scope_card(app)
        else:
            app.hint("usage: /scope <file> — the operator-signed "
                     "engagement scope (JSON)")
        return
    path = Path(args).expanduser()
    if not path.is_file():
        app.err(f"scope file not found: {path}")
        return
    try:
        sf = ScopeFile.load(str(path))
    except Exception as exc:
        app.err(f"SCOPE FILE INVALID: {exc}")
        return
    app.sf = sf
    app.scope_path = str(path)
    _scope_card(app)


def _scope_card(app):
    sf = app.sf
    lines = [
        R.label_value("scope_ref:", sf.scope_ref()),
        R.label_value("mode:", str(sf.mode)),
        R.label_value("rules:", f"{len(sf.rules)}"),
        R.label_value("excludes:", f"{len(sf.excludes)}"),
        R.label_value("roe.poc_only:", str(sf.roe.poc_only)),
        R.label_value("signed:", "yes" if sf.signed
                      else "NO — integrity-fingerprinted only"),
    ]
    app.say_lines(R.card(lines))
    app.say(R.system_line(
        "scope armed — /engage <objective> (or just type the objective) "
        "starts the engagement"))


@command("workspace", args="<dir>",
         help="show or set the engagement workspace", group="engagement")
def _workspace(app, args):
    if not args:
        app.say(R.kv_line("workspace", str(app.workspace)))
        return
    app.workspace = Path(args).expanduser().resolve()
    app.say(R.kv_line("workspace", str(app.workspace)))


@command("engage", args="<objective>",
         help="start (or continue) the engagement", group="engagement")
def _engage(app, args):
    if getattr(app, "sf", None) is None:
        app.hint("arm a scope first: /scope <file>")
        return
    if not args.strip():
        app.hint("usage: /engage <objective text>")
        return
    app.start_engagement(args.strip())


@command("status", help="engagement state at a glance", group="engagement")
def _status(app, args):
    from .. import __version__
    eng = getattr(app, "engagement", None)
    state = "idle"
    if eng is not None and eng.running:
        state = f"engaging (turn {eng.turn})"
    lines = [
        R.label_value("version:", __version__),
        R.label_value("workspace:", str(app.workspace)),
        R.label_value("scope:",
                      app.sf.scope_ref() if getattr(app, "sf", None)
                      else "(none)"),
        R.label_value("state:", state),
        R.label_value("messages:", str(len(app.messages))),
    ]
    if getattr(app, "session_id", None):
        lines.append(R.label_value("session:", app.session_id))
    if eng is not None and eng.total_tokens:
        lines.append(R.label_value("tokens:", R.fmt_tokens(
            eng.total_tokens)))
    app.say_lines(R.card(lines))


@command("reset", help="drop the conversation (scope stays armed)",
         group="engagement")
def _reset(app, args):
    app.messages = []
    app.session_id = None
    app.say(R.system_line("conversation cleared — scope stays armed, "
                          "next /engage starts fresh"))


# ─── diagnostics ────────────────────────────────────────────────────────

@command("doctor", help="host pre-flight (same as hypervisor --doctor)",
         group="diagnostics")
def _doctor(app, args):
    def job(push, abort):
        from ..doctor import run_doctor
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_doctor()
        for line in buf.getvalue().splitlines():
            push(line)
        push("")
        push((R.ok("doctor: READY (rc=0)") if rc == 0
              else R.err(f"doctor: FAILURES (rc={rc}) — see above")))
    app.run_job("doctor", job)


@command("test", args="[pytest args]",
         help="run the acceptance suite (pytest -q)", group="diagnostics")
def _test(app, args):
    argv = [sys.executable, "-m", "pytest", "-q"] + shlex.split(args)

    def job(push, abort):
        push(R.section_line(f"pytest {' '.join(argv[3:]) or 'suite'}"))
        try:
            proc = subprocess.Popen(
                argv, cwd=str(REPO_ROOT), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, env=dict(os.environ))
        except OSError as exc:
            push(R.err(f"failed to start pytest: {exc}"))
            return
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if abort.is_set():
                    proc.terminate()
                    push(R.warn("aborted by operator"))
                    break
                push(R.dim(line.rstrip()))
            rc = proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()
        if not abort.is_set():
            mark = R.ok("PASS") if rc == 0 else R.err("FAIL")
            push("")
            push(f"{mark} {R.muted(f'pytest rc={rc}')}")
    app.run_job("pytest", job)


@command("journal", args="[n]", help="tail the engagement journal",
         group="diagnostics")
def _journal(app, args):
    try:
        n = max(1, min(500, int(args or "25")))
    except ValueError:
        n = 25
    path = Path(app.workspace) / ".aegis" / "journal" / "journal.jsonl"
    if not path.is_file():
        app.hint(f"no journal yet at {path} — run an engagement first")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    app.say(R.section_line(f"journal tail · {len(lines)} events"))
    for raw in lines[-n:]:
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            app.say(R.dim("  ? (torn line)"))
            continue
        d = e.get("data") or {}
        rev = d.get("rev_after") or d.get("rev") or e.get("rev") or ""
        kind = e.get("type", "?")
        note = ""
        if kind == "permission_decision" and not d.get("allowed"):
            note = "DENY " + str(d.get("tool") or "")
        elif kind == "ekd_mutation":
            note = str(d.get("reason") or "")
        elif kind == "loop_transition":
            note = str(d.get("transition") or d.get("detail", "") or "")
        elif kind in ("llm_call", "llm_call_end"):
            note = str(d.get("purpose") or "")
        # clip PLAIN text before styling — slicing a styled string can
        # cut an escape sequence in half
        room = max(8, app.cols - 40)
        note = note[:room]
        app.say(R.dim(f"  {e.get('seq', '?'):>4}  ")
                + R.fg(f"{kind:<20}", R.C_INFO)
                + R.dim(f" rev={str(rev):<5} {note}"))
    app.say(R.dim(f"  … showing last {n} of {len(lines)} — "
                  f"full file: {path}"))


@command("ekd", help="engagement graph state (rev / nodes / edges)",
         group="diagnostics")
def _ekd(app, args):
    path = Path(app.workspace) / "ekd.json"
    if not path.is_file():
        app.hint(f"no EKD state at {path} yet")
        return
    try:
        e = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        app.err(f"ekd.json unreadable: {exc}")
        return
    nodes = e.get("nodes") or {}
    edges = e.get("edges") or []
    counters = e.get("counters") or {}
    lines = [
        R.label_value("rev:", str(e.get("rev", "?"))),
        R.label_value("nodes:", str(len(nodes))),
        R.label_value("edges:", str(len(edges))),
        R.label_value("counters:", json.dumps(counters)[:48]),
    ]
    app.say_lines(R.card(lines))


@command("health", help="offline environment sanity check",
         group="diagnostics")
def _health(app, args):
    from .. import __version__
    base = os.environ.get("AEGIS_OPENAI_BASE_URL", "")
    key = os.environ.get("AEGIS_OPENAI_API_KEY", "")
    model = os.environ.get("AEGIS_MODEL", "(adapter default)")
    lines = [
        R.label_value("version:", __version__),
        R.label_value("endpoint:", base if base else "NOT SET"),
        R.label_value("api key:", "set" if key else "NOT SET"),
        R.label_value("model:", model),
        R.label_value("scope:",
                      "armed" if getattr(app, "sf", None) else "none"),
        R.label_value("workspace:", str(app.workspace)),
    ]
    app.say_lines(R.card(lines))
    if not base or not key:
        app.hint("AEGIS_OPENAI_BASE_URL / AEGIS_OPENAI_API_KEY missing "
                 "— model calls will fail (this check is offline by "
                 "design; /doctor probes the endpoint)")


@command("agents", help="list the expert agent definitions",
         group="diagnostics")
def _agents(app, args):
    defs = REPO_ROOT / "hypervisor" / "agents" / "defs"
    files = sorted(defs.glob("*.md"))
    if not files:
        app.hint(f"no agent defs found under {defs}")
        return
    app.say(R.section_line(f"agent defs · {len(files)}"))
    for f in files:
        first = ""
        try:
            for line in f.read_text(encoding="utf-8",
                                    errors="replace").splitlines():
                if line.strip() and not line.startswith("#"):
                    first = line.strip()[:64]
                    break
                if line.startswith("#") and not first:
                    first = line.lstrip("# ").strip()[:64]
        except OSError:
            pass
        app.say(f"  {R.fg(f.stem, R.C_INFO)}{R.dim('  — ' + first)}")
    app.say("")


@command("watchdog", help="loop knobs as resolved from the environment",
         group="diagnostics")
def _watchdog(app, args):
    from .. import query as Q
    lines = [
        R.label_value("turn_budget_s:", f"{Q.TURN_BUDGET_S:g}"),
        R.label_value("context_window:", f"{Q.CONTEXT_WINDOW}"),
        R.label_value("max_output_tokens:", f"{Q.MAX_OUTPUT_TOKENS}"),
        R.label_value("output_ceiling:", f"{Q.MAX_OUTPUT_TOKENS_CEILING}"),
        R.label_value("recoveries:", f"{Q.RECOVERY_CONTINUATIONS}"),
        R.label_value("blocking_ratio:", f"{Q.BLOCKING_RATIO:g}"),
    ]
    app.say_lines(R.card(lines))


@command("compact", help="compaction is the P2 auto ladder (informational)")
def _compact(app, args):
    eng = getattr(app, "engagement", None)
    app.say(R.system_line(
        "compaction is automatic in 4.0 (P2 ladder: fold -> microcompact "
        "-> autocompact before the blocking gate) — no manual fold"))
    if eng is not None and getattr(eng, "autocompacts", 0):
        app.say(R.kv_line("autocompacts", str(eng.autocompacts)))


# ─── session ────────────────────────────────────────────────────────────

@command("report", args="[findings|<path>]",
         help="show the engagement report", group="session")
def _report(app, args):
    ws = Path(app.workspace)
    if args in ("findings", "f"):
        path = ws / "report_findings.md"
    elif args:
        path = ws / args
    else:
        path = ws / "report.md"
    if not path.is_file():
        alt = ws / "report_findings.md" if path == ws / "report.md" \
            else ws / "report.md"
        if alt.is_file():
            path = alt
        else:
            app.hint(f"no report at {path} — the agent writes report.md "
                     "on compile_report")
            return
    app.say(R.section_line(str(path)))
    width = max(30, app.cols - 2)
    for line in path.read_text(encoding="utf-8",
                               errors="replace").splitlines()[:400]:
        if line.strip():
            for chunk in R.wrap_plain(line.expandtabs(4), width):
                app.say(R.text(chunk))
        else:
            app.say("")
    app.say("")


@command("resume", args="[id]", help="list or continue a session",
         group="session")
def _resume(app, args):
    sdir = Path(app.workspace) / ".aegis" / "sessions"
    files = sorted(sdir.glob("*.jsonl")) if sdir.is_dir() else []
    if not args:
        if not files:
            app.hint(f"no sessions under {sdir} yet")
            return
        app.say(R.section_line(f"sessions · {len(files)}"))
        for f in files:
            n = sum(1 for _ in f.open(encoding="utf-8", errors="replace"))
            when = time.strftime("%m-%d %H:%M",
                                 time.localtime(f.stat().st_mtime))
            app.say(f"  {R.fg(f.stem, R.C_INFO)}"
                    + R.dim(f"  {n} records  {when}"))
        app.say(R.system_line("/resume <id> continues that transcript"))
        app.say("")
        return
    sid = args.strip()
    path = sdir / f"{sid}.jsonl"
    if not path.is_file():
        app.err(f"session not found: {sid}")
        return
    from ..persist.sessions import SessionStore
    store = SessionStore(sdir, session_id=sid)
    messages = []
    for rec in store.read_all():
        msg = rec.get("message")
        if rec.get("type") in ("user", "assistant", "tool_result") \
                and isinstance(msg, dict) and msg.get("role"):
            messages.append(msg)
    app.messages = messages
    app.session_id = sid
    app.say(R.kv_line("resumed", f"{sid} ({len(messages)} messages)"))
    app.say(R.system_line(
        "transcript loaded — the next /engage or free text continues "
        "this conversation (scope must be armed for tool use)"))
