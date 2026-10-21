"""P1 transport declaration — the Test-4 container regression.

The engagement container (clean Kali image, no pip site-packages) died
on the FIRST model call: ``import httpx`` inside
``OpenAICompatClient._http`` raised ModuleNotFoundError because httpx
was never declared — pyproject said ``dependencies = []`` ("the adapter
(P1) will add the OpenAI-compatible client dependency when it lands")
and the doctor's stdlib-only check grepped for that literal string,
so every environment with httpx lying around (workstation, dev venv)
hid the gap. These tests pin all three layers of the fix:

1. pyproject DECLARES the transport (clean installs get it),
2. the adapter REFUSES HONESTLY with an actionable message when the
   transport is missing (platform discipline: environment defects are
   reported, not crashed),
3. the doctor CATCHES it (real declared-deps parse + an explicit,
   blocking adapter-transport check) so no image ships green-but-dead.
"""
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent


# ── 1. the declaration ────────────────────────────────────────────────

def test_pyproject_declares_the_adapter_transport():
    deps = tomllib.loads(
        (PROJECT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["dependencies"]
    assert any(d.strip().startswith("httpx") for d in deps), (
        "adapters/openai.py rides httpx at call time (lazy import inside "
        "OpenAICompatClient._http); it MUST be declared in pyproject or "
        "clean environments die on the first model call (Test-4 container)")


# ── 2. honest refusal ─────────────────────────────────────────────────

def test_missing_transport_refuses_honestly(monkeypatch):
    """A missing transport must raise an actionable RuntimeError naming
    the fix — not a raw ModuleNotFoundError from inside the client
    factory (Test-4: the first model call died at import httpx)."""
    from hypervisor.adapters.openai import OpenAICompatClient
    # None in sys.modules makes the lazy `import httpx` raise ImportError
    monkeypatch.setitem(sys.modules, "httpx", None)
    client = OpenAICompatClient(
        base_url="http://127.0.0.1:9/v1", api_key="k",
        model="cisai-ultra", fallback_model="")
    with pytest.raises(RuntimeError) as ei:
        client._http()
    msg = str(ei.value)
    assert "adapter transport missing" in msg
    assert "httpx>=0.27" in msg          # the remediation
    assert "doctor" in msg               # points at the doctor check
    assert ei.value.__cause__ is not None  # chained to the ImportError


# ── 3. the doctor catches it ──────────────────────────────────────────

def _doctor_subprocess(block_httpx: bool):
    code = "import sys\n"
    if block_httpx:
        code += "sys.modules['httpx'] = None\n"  # simulate clean container
    code += ("from hypervisor.doctor import run_doctor\n"
             "sys.exit(run_doctor())\n")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("AEGIS_")}
    env["PYTHONPATH"] = str(PROJECT)
    return subprocess.run(
        [sys.executable, "-c", code], cwd=str(PROJECT), env=env,
        capture_output=True, text=True, timeout=180)


def test_doctor_blocks_on_missing_transport():
    """The exact condition that shipped green-but-dead in the first
    Test-4 image: transport missing -> doctor FAILS with its fix line
    and exits 1 (blocking — the host is NOT ready)."""
    proc = _doctor_subprocess(block_httpx=True)
    out = proc.stdout
    assert "[FAIL] adapter transport: httpx" in out
    assert "pip install 'httpx>=0.27'" in out     # remediation printed
    assert "MISSING: httpx" in out                # declared-deps check too
    assert proc.returncode == 1


def test_doctor_green_with_transport_declared():
    """Healthy environment: both new checks render [OK] and the doctor
    still exits 0 without an endpoint configured (soft check)."""
    proc = _doctor_subprocess(block_httpx=False)
    out = proc.stdout
    assert "[OK ] declared runtime deps" in out
    assert "httpx" in out
    assert "[OK ] adapter transport: httpx" in out
    assert proc.returncode == 0
