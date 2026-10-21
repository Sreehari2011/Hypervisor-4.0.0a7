"""AEGIS Debug Kit — runtime patches (all reversible, none touch source).

Port card: PORT-08. The 3.7.3 patcher had four taps; three survive into
4.0 with re-aimed targets, one dies with the grid:

  1. journal tap   — wraps Journal.append so every journal event lands
     in the unified timeline as cat='journal' (the internal perspective
     correlated against the external wire captures: one timeline, both
     sides of every decision). Guarded; a missing API degrades to a
     timeline note, never a platform failure.
  2. EKD tap       — armed as a deterministic import hook on
     hypervisor.memory.ekd (lands in P2). Same mechanism as the 3.7.3
     DAG tap: instrumentation lands the moment the module is imported,
     before any caller can bind its names. No-op until then.
  3. sessions tap  — armed for hypervisor.persist.sessions (P1) the
     same way; will time the 0o600 JSONL writer's append/fsync.
  4. saver tap     — DELETED. AsyncSqliteSaver was a LangGraph organ;
     nothing in 4.0 checkpoints through it. (Listed in the port card's
     deltas; the grid's persistence is replaced by persist/sessions.)
"""
import functools
import sys
import threading
import time

from . import timeline


def install_journal_tap():
    """Tap the engagement journal so every event (message, compaction,
    subagent, breaker, permission_decision, loop_transition, ...) lands
    in the unified timeline as cat='journal'. Guarded; a missing or
    renamed Journal API degrades to a timeline note, never an agent
    failure."""
    try:
        from hypervisor.persist import journal as journal_mod
    except Exception as exc:
        timeline.emit("meta", "journal_tap_unavailable",
                      reason=f"{type(exc).__name__}: {exc}")
        return

    if getattr(journal_mod.Journal, "_aegis_debug_tapped", False):
        return
    orig_append = journal_mod.Journal.append

    @functools.wraps(orig_append)
    def tapped_append(self, event_type, *a, **kw):
        ev = orig_append(self, event_type, *a, **kw)
        try:
            if ev is not None:
                data = ev.get("data")
                cap = None
                if isinstance(data, dict):
                    cap = {k: (v if not isinstance(v, str) or len(v) <= 120
                               else v[:120] + "...")
                           for k, v in list(data.items())[:12]}
                timeline.emit(
                    "journal", ev.get("type", event_type),
                    id=str(ev.get("seq")),
                    seq=ev.get("seq"), turn=ev.get("turn"),
                    rev=ev.get("rev"), actor=ev.get("actor"),
                    data=cap)
        except Exception:
            pass  # the tap must never break the journal
        return ev

    journal_mod.Journal.append = tapped_append
    journal_mod.Journal._aegis_debug_tapped = True
    timeline.emit("meta", "journal_tap_installed",
                  note="journal events now mirror into the timeline")


class _ModuleLoadHook:
    """Deterministic module tap: wraps a module loader so
    instrumentation lands the moment it is imported — BEFORE any
    `from hypervisor.memory.ekd import ...` binding in caller code. A
    polling watcher alone can lose that race (the 3.7.3 lesson, kept)."""

    def __init__(self, target: str, patch_fn):
        self.target = target
        self.patch_fn = patch_fn

    def find_spec(self, fullname, path=None, target=None):
        if fullname != self.target:
            return None
        import importlib.util
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        except Exception:
            spec = None
        finally:
            sys.meta_path.insert(0, self)
        if spec is None or spec.loader is None:
            return None
        try:
            orig_exec = spec.loader.exec_module
        except Exception:
            return spec  # legacy loader — leave untouched

        def exec_module(module, _orig=orig_exec):
            _orig(module)
            try:
                self.patch_fn(module)
                timeline.emit("meta", "module_tap_installed",
                              module=self.target)
            except Exception as exc:
                timeline.emit("meta", "module_tap_patch_failed",
                              module=self.target,
                              reason=f"{type(exc).__name__}: {exc}")

        spec.loader.exec_module = exec_module
        return spec


_PATCHED = set()


def _patch_sessions(mod):
    """Time the sessions writer's durable append (the J1 write-ahead's
    disk cost — a growing session file makes fsync a real suspect, the
    same question the 3.7.3 saver tap answered for sqlite)."""
    Sessions = getattr(mod, "SessionStore", None)
    if Sessions is None or id(Sessions) in _PATCHED:
        return
    _PATCHED.add(id(Sessions))
    orig = getattr(Sessions, "append", None)
    if orig is None:
        return

    @functools.wraps(orig)
    def tapped(self, *a, **kw):
        t0 = time.monotonic()
        out = orig(self, *a, **kw)
        timeline.emit("persist", "session_append",
                      dur_ms=round((time.monotonic() - t0) * 1000, 1))
        return out

    Sessions.append = tapped


def _patch_ekd(mod):
    """Instrument the EKD's serialization surfaces (P2 will refine the
    method names; the hook re-arms cheaply — patch failures are notes,
    not errors)."""
    EKD = getattr(mod, "EngagementDAG", None)
    if EKD is None or id(EKD) in _PATCHED:
        return
    _PATCHED.add(id(EKD))
    for meth in ("render_brief", "to_json"):
        orig = getattr(EKD, meth, None)
        if orig is None:
            continue

        def wrapped(self, *a, _orig=orig, _m=meth, **kw):
            t0 = time.monotonic()
            out = _orig(self, *a, **kw)
            n = e = None
            try:
                n, e = len(self.nodes), len(self.edges)
            except Exception:
                pass
            timeline.emit("memory", _m,
                          dur_ms=round((time.monotonic() - t0) * 1000, 1),
                          nodes=n, edges=e,
                          out_chars=len(out) if isinstance(out, str) else None)
            return out

        setattr(EKD, meth, wrapped)


def _arm_hook(module_name: str, patch_fn, label: str):
    already = module_name in sys.modules
    if already:
        try:
            patch_fn(sys.modules[module_name])
            timeline.emit("meta", f"{label}_tap_installed",
                          module="preimported")
            return
        except Exception as exc:
            timeline.emit("meta", f"{label}_tap_patch_failed",
                          module="preimported",
                          reason=f"{type(exc).__name__}: {exc}")
    hook = _ModuleLoadHook(module_name, patch_fn)
    try:
        sys.meta_path.insert(0, hook)
        timeline.emit("meta", f"{label}_tap_hook_armed",
                      note=f"import hook watching for {module_name}")
    except Exception as exc:
        timeline.emit("meta", f"{label}_tap_hook_failed",
                      reason=f"{type(exc).__name__}: {exc}")

    # Fallback watcher (covers legacy loaders the hook declined).
    def watcher():
        for _ in range(450):  # ~15 min of patience
            if module_name in _PATCHED:
                return
            time.sleep(2.0)
            m = sys.modules.get(module_name)
            if m is not None:
                try:
                    patch_fn(m)
                    timeline.emit("meta", f"{label}_tap_installed",
                                  module=f"{module_name} (watcher)")
                except Exception as exc:
                    timeline.emit("meta", f"{label}_tap_probe_failed",
                                  reason=f"{type(exc).__name__}: {exc}")
                    return
                return
        timeline.emit("meta", f"{label}_tap_gave_up",
                      reason=f"{module_name} never importable")

    threading.Thread(target=watcher, name=f"aegis-debug-{label}-watcher",
                     daemon=True).start()


def install_ekd_tap():
    """No-op until hypervisor.memory.ekd exists (P2); arms the
    deterministic hook now so the day it lands, it is born observed."""
    _arm_hook("hypervisor.memory.ekd", _patch_ekd, "ekd")


def install_sessions_tap():
    """No-op until hypervisor.persist.sessions exists (P1)."""
    _arm_hook("hypervisor.persist.sessions", _patch_sessions, "sessions")
