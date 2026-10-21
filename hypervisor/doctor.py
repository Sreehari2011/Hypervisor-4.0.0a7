"""hypervisor.doctor — the cutover pre-flight (P4, blueprint Ch.14).

The operator-facing readiness check for the 3.7.3 -> 4.0 production
cutover: version + environment, endpoint reachability (when
configured), registry composition (platform / VAPT / operator /
task), operator runtime attachments (frida / mitmdump / ssh /
sshpass / nmap), journal/replay tooling importability, and the
declared-dependency contract (stdlib core + the adapter transport).
Exit 0 = host ready; every failure prints its remediation.

python -m hypervisor.cli --doctor
"""
from __future__ import annotations

import importlib
import os
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Any, Dict, List

CHECKS: List[Dict[str, Any]] = []


def _check(name: str, ok: bool, detail: str, fix: str = "") -> None:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": detail,
                   "fix": fix})


_VERSION_FLAG = {
    "frida": "--version", "mitmdump": "--version", "ssh": "-V",
    "nmap": "--version", "sshpass": None,   # bare usage is the probe
}

_CAPS_FIX = ("compose cap_add must cover EVERY file capability on the "
             "binary (Kali nmap: add NET_BIND_SERVICE), or setcap the "
             "binary to the granted set (kit Dockerfile step 1b)")


def _probe_exec(path: str, flag) -> tuple:
    """Exec-probe a runtime attachment: any completed invocation that is
    not a shell cannot-execute (rc 126/127) or EPERM proves the binary
    runs; the version output itself is irrelevant. Returns (ok, detail,
    fix). PILOT-02: nmap was present yet dead for every user — file
    caps outside the container bounding set refuse execve outright."""
    argv = [path] + ([flag] if flag else [])
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=20)
    except PermissionError:
        return False, (f"{path} present but NOT EXECUTABLE (EPERM) — "
                       f"file caps outside the container bounding set?"), \
            _CAPS_FIX
    except subprocess.TimeoutExpired:
        return True, f"{path} (exec ok; version probe slow)", ""
    except OSError as exc:
        return False, f"{path}: {type(exc).__name__}: {str(exc)[:60]}", ""
    text = ((proc.stderr or b"") + (proc.stdout or b"")).decode(
        "utf-8", "replace")
    if proc.returncode in (126, 127) or \
            "operation not permitted" in text.lower():
        return False, (f"{path} present but NOT EXECUTABLE "
                       f"(rc={proc.returncode}) — file caps outside "
                       f"the container bounding set?"), _CAPS_FIX
    return True, f"{path} (exec ok)", ""


def run_doctor() -> int:
    from . import __version__
    print(f"AEGIS Hypervisor doctor — pre-flight for cutover")
    print(f"  version        : {__version__}")
    py = sys.version_info
    _check("python >= 3.11", (py.major, py.minor) >= (3, 11),
           f"{py.major}.{py.minor}.{py.micro}",
           "upgrade to Python 3.11+")

    # ── the dependency contract ────────────────────────────────────────────────────────────
    # P0 discipline: stdlib-only runtime with ONE declared exception —
    # the P1 adapter's transport (httpx, imported lazily at call time
    # inside OpenAICompatClient._http). Test-4's clean container caught
    # the declaration gap: pyproject still said dependencies = [] while
    # the adapter required httpx; the old check grepped for that literal
    # string and the endpoint probe rode urllib — a green doctor whose
    # every model call died on import.
    try:
        proj = importlib.import_module("hypervisor")
        init = os.path.dirname(proj.__file__) if proj.__file__ else ""
        pyproject = os.path.join(os.path.dirname(init), "pyproject.toml")
        deps: List[str] = []
        if os.path.isfile(pyproject):
            with open(pyproject, "rb") as f:
                deps = list(tomllib.load(f)
                            .get("project", {}).get("dependencies", []))
        found: List[str] = []
        missing: List[str] = []
        for dep in deps:
            m = re.match(r"[A-Za-z0-9_.\-]+", dep.strip())
            top = m.group(0) if m else dep.strip()
            try:
                mod = importlib.import_module(top)
                found.append(f"{top} {getattr(mod, '__version__', '?')}")
            except Exception:
                missing.append(top)
        detail = ", ".join(found) if found else "none declared"
        if missing:
            detail += f" — MISSING: {', '.join(missing)}"
        _check("declared runtime deps", not missing, detail,
               "install the declared dependencies (pip install -e . on "
               "the workstation, or rebuild the engagement image)")
    except Exception as exc:
        _check("declared runtime deps", False, str(exc)[:80], "")

    # The adapter's transport is load-bearing for EVERY model call —
    # verified explicitly, declaration or not, so no image can ship
    # green-but-dead again (the Test-4 lesson). Blocking on failure.
    try:
        import httpx
        _check("adapter transport: httpx", True, httpx.__version__, "")
    except Exception:
        _check("adapter transport: httpx", False,
               "not importable — every model call will refuse honestly",
               "pip install 'httpx>=0.27' on the engagement host "
               "(or rebuild the engagement image)")

    # ── the model endpoint ────────────────────────────────────────
    base_url = os.environ.get("AEGIS_OPENAI_BASE_URL", "").strip()
    model = os.environ.get("AEGIS_MODEL", "").strip()
    if not base_url:
        _check("model endpoint", False, "AEGIS_OPENAI_BASE_URL not set",
               "export AEGIS_OPENAI_BASE_URL (the Kemi K2.7 / "
               "cisai-ultra OpenAI-compatible endpoint)")
    else:
        reachable = False
        detail = base_url
        try:
            import urllib.request
            req = urllib.request.Request(
                base_url.rstrip("/") + "/models",
                headers={"Authorization": "Bearer "
                         + os.environ.get("AEGIS_OPENAI_API_KEY", "")})
            with urllib.request.urlopen(req, timeout=10) as r:
                reachable = r.status == 200
                detail = f"{base_url} -> HTTP {r.status}"
        except Exception as exc:
            detail = f"{base_url} -> {type(exc).__name__}: {str(exc)[:60]}"
        _check("model endpoint", reachable, detail,
               "check the endpoint URL / API key / network")
    _check("model name", bool(model),
           model or "AEGIS_MODEL not set",
           "export AEGIS_MODEL (e.g. the cisai-ultra deployment name)")

    # ── the tool plane composition ─────────────────────────────────
    try:
        from .tools.core import build_registry
        from .tools.vapt import operator_enabled, vapt_enabled
        plat = build_registry()
        vapt = build_registry(include_vapt=True)
        full = build_registry(include_vapt=True, include_task=True)
        _check("registry: platform set", len(plat) >= 9,
               f"{len(plat)} tools",
               "the platform core should carry at least 9 tools")
        _check("registry: VAPT family", vapt_enabled() and len(vapt) > len(plat),
               f"{len(vapt)} tools with include_vapt"
               + ("" if vapt_enabled() else " (AEGIS_VAPT_TOOLS=0)"),
               "unset AEGIS_VAPT_TOOLS=0 or accept the trimmed surface")
        _check("registry: operator attachments", operator_enabled(),
               f"{len(vapt)} incl. frida_hook/mitm_intercept/"
               f"ssh_interactive_exec"
               + ("" if operator_enabled() else " (AEGIS_OPERATOR_TOOLS=0)"),
               "unset AEGIS_OPERATOR_TOOLS=0 to offer the operator tools")
        _check("registry: task tool", "task" in full.names(),
               f"{len(full)} tools with include_task; task="
               f"{'task' in full.names()}", "")
    except Exception as exc:
        _check("registry composition", False,
               f"{type(exc).__name__}: {str(exc)[:80]}", "")

    # ── operator runtime attachments ──────────────────────────────
    # Presence is not executability. The engagement container drops
    # ALL capabilities and re-adds a subset; any file-capped binary
    # whose cap set exceeds the container bounding set (Kali's nmap
    # ships cap_net_bind_service,cap_net_admin,cap_net_raw) then fails
    # execve with EPERM — for every user, root included — and the sh
    # wrapper surfaces it as rc=127 "Operation not permitted". The
    # PILOT-02 engagement hit exactly this on nmap. Probe-exec each
    # attachment so the pre-flight says it up front instead of the
    # first mid-engagement network_scan_nmap call.
    for binary, what in (
            ("frida", "frida_hook (mobile dynamic instrumentation)"),
            ("mitmdump", "mitm_intercept (traffic capture)"),
            ("ssh", "ssh_interactive_exec (remote command execution)"),
            ("sshpass", "ssh_interactive_exec password auth (optional)"),
            ("nmap", "network_scan_nmap (port/service scanning)")):
        path = shutil.which(binary)
        if path is None:
            _check(f"runtime: {binary}", False,
                   f"not on PATH — {what} will refuse honestly",
                   f"install {binary} on the engagement host" +
                   (" (optional)" if "optional" in what else ""))
            continue
        ok, detail, fix = _probe_exec(path, _VERSION_FLAG.get(binary))
        _check(f"runtime: {binary}", ok, detail, fix)

    # ── the persist/verify plane ──────────────────────────────────
    for mod in ("hypervisor.persist.replay", "hypervisor.debug.slo",
                "hypervisor.hooks"):
        try:
            importlib.import_module(mod)
            _check(f"import: {mod}", True, "", "")
        except Exception as exc:
            _check(f"import: {mod}", False,
                   f"{type(exc).__name__}: {str(exc)[:60]}", "")

    # ── stop-hook configuration ───────────────────────────────────
    hook = os.environ.get("AEGIS_STOP_HOOK", "").strip()
    _check("stop-hook", True,
           f"{'armed: ' + hook if hook else 'not configured (optional)'}",
           "")

    # ── render ────────────────────────────────────────────────────
    failures = 0
    soft = ("model endpoint", "model name",
            "runtime: frida", "runtime: mitmdump", "runtime: ssh",
            "runtime: sshpass", "runtime: nmap", "stop-hook")
    for c in CHECKS:
        mark = "OK " if c["ok"] else "FAIL"
        line = f"  [{mark}] {c['name']}: {c['detail']}"
        if not c["ok"] and c["fix"]:
            line += f"\n         fix: {c['fix']}"
        print(line)
        if not c["ok"] and c["name"] not in soft:
            failures += 1
    hard = [c for c in CHECKS if not c["ok"] and c["name"] not in soft]
    print()
    if hard:
        print(f"DOCTOR: {len(hard)} blocking failure(s) — host NOT ready "
              f"for cutover")
        return 1
    print("DOCTOR: host ready — no blocking failures "
          "(endpoint + optional runtimes may still need configuration)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_doctor())
