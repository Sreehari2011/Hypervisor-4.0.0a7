"""Operator-fake placement for the exit-criterion harness.

Test-4 (engagement container, aegis-hypervisor:4.0.0a5 on Kali) exposed
a second environment-parity defect the criterion verdict cannot see:
the container kit's compose mounts ``/tmp`` as a tmpfs, Docker defaults
tmpfs mounts to ``noexec``, and the harness placed its operator fakes
in ``tempfile.mkdtemp()`` — i.e. on that noexec /tmp. ``os.access()``
with ``X_OK`` fails on a noexec mount, so ``shutil.which()`` silently
SKIPPED the fakes, the image's REAL frida/mitmdump ran instead, and
the real frida rejected the (since-removed) ``--no-pause`` flag — a
usage error harvested as if it were the scenario's capture, while the
run still reported rc=0 / replay=True / slo=pass.

The harness now installs the fakes into the run scratch (under OUTPUT,
the container's exec-allowed evidence volume) and refuses LOUDLY if the
placement is not executable. These tests pin all three sides: the
install, the guard, and the PATH shadowing that silently broke.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "run_exit_criterion", PROJECT / "scripts" / "run_exit_criterion.py")
criterion = importlib.util.module_from_spec(_spec)
sys.modules["run_exit_criterion"] = criterion
_spec.loader.exec_module(criterion)


def test_fake_battery_covers_the_operator_runtimes():
    """The fakes exist for exactly the binaries the operator tools
    resolve at call time (frida_hook / mitm_intercept /
    ssh_interactive_exec + sshpass)."""
    assert set(criterion.FAKE_BINARIES) == {
        "frida", "mitmdump", "ssh", "sshpass"}


def test_fakes_install_executable_and_run(tmp_path):
    """Happy path: on an exec-allowed directory the fakes install with
    the execute bit, pass the guard, and actually execute (the sshpass
    fake execs its command vector — the fastest one to prove)."""
    bindir = tmp_path / "fake-bin"
    criterion.install_operator_fakes(bindir)          # guard inside
    for name in criterion.FAKE_BINARIES:
        assert os.access(bindir / name, os.X_OK), name
    proc = subprocess.run(
        [str(bindir / "sshpass"), "-p", "x", "echo", "ran-under-fake"],
        capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "ran-under-fake"


def test_non_executable_placement_refuses_loudly(tmp_path):
    """The exact container condition, simulated: a directory whose
    contents fail the X_OK check (chmod 0644 stands in for what a
    noexec mount does to os.access) must raise SystemExit naming the
    failure mode — never fall through to running the REAL binaries."""
    bindir = tmp_path / "noexec-ish"
    criterion.install_operator_fakes(bindir)
    (bindir / "frida").chmod(0o644)     # simulate the noexec X_OK miss
    with pytest.raises(SystemExit) as ei:
        criterion._assert_fakes_runnable(bindir)
    msg = str(ei.value)
    assert "frida" in msg               # names the dead fake
    assert "noexec" in msg              # names the cause
    assert "REAL" in msg                # names the consequence


def test_fakes_win_path_shadowing_over_a_real_binary(
        tmp_path, monkeypatch):
    """The resolution site that silently broke in the container: with a
    REAL frida installed earlier on PATH (the engagement image) and the
    harness fakes prepended the way run_one_fake does, shutil.which
    must resolve the FAKE — on a noexec fake dir it resolved the real
    binary and the scripted leg stopped being the scripted leg."""
    realbin = tmp_path / "real-bin"
    realbin.mkdir()
    (realbin / "frida").write_text("#!/bin/sh\necho REAL-FRIDA-RAN\n")
    (realbin / "frida").chmod(0o755)
    # the image's PATH: real binary reachable...
    monkeypatch.setenv("PATH", str(realbin) + os.pathsep +
                       os.environ.get("PATH", ""))
    assert os.access(realbin / "frida", os.X_OK)      # a live candidate
    # ...then the harness's scratch placement + prepend (run_one_fake):
    fakebin = tmp_path / "scratch" / "run-4-operator-frida" / "fake-bin"
    criterion.install_operator_fakes(fakebin)
    monkeypatch.setenv("PATH", str(fakebin) + os.pathsep +
                       os.environ.get("PATH", ""))
    assert shutil.which("frida") == str(fakebin / "frida")
