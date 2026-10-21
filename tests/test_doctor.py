"""tests/test_doctor.py — the runtime exec-probe.

PILOT-02: nmap was present but not executable (file caps outside the
container bounding set) and passed the presence-only pre-flight. The
probe is the unit-testable seam: _probe_exec against fabricated
binaries mimicking the failure shapes observed in the engagement
container (rc=127 from the sh wrapper, direct EPERM) and a healthy
one, plus one run_doctor integration pass.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from hypervisor.doctor import _probe_exec


def _make_bin(tmp_path: Path, name: str, body: str,
              mode: int = 0o755) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    p.chmod(mode)
    return p


def test_probe_exec_ok(tmp_path):
    p = _make_bin(tmp_path, "fake-nmap", """\
        #!/bin/sh
        echo "Fake Nmap 7.94"
        """)
    ok, detail, fix = _probe_exec(str(p), "--version")
    assert ok and "exec ok" in detail and fix == ""


def test_probe_exec_wrapper_rc127_shape(tmp_path):
    # the engagement container's exact shape: the sh wrapper's exec of
    # the file-capped binary fails and sh reports it, rc 127
    p = _make_bin(tmp_path, "fake-nmap", """\
        #!/bin/sh
        echo "/usr/bin/nmap: 6: exec: /usr/lib/nmap/nmap: Operation not permitted" >&2
        exit 127
        """)
    ok, detail, fix = _probe_exec(str(p), "--version")
    assert not ok
    assert "NOT EXECUTABLE" in detail
    assert "NET_BIND_SERVICE" in fix


def test_probe_exec_rc126_shape(tmp_path):
    p = _make_bin(tmp_path, "fake-tool", """\
        #!/bin/sh
        echo "permission denied" >&2
        exit 126
        """)
    ok, detail, fix = _probe_exec(str(p), None)
    assert not ok and "NOT EXECUTABLE" in detail


def test_probe_exec_direct_eperm(tmp_path):
    # binary without the exec bit: execve itself raises
    p = _make_bin(tmp_path, "fake-tool", "#!/bin/sh\n", mode=0o644)
    ok, detail, fix = _probe_exec(str(p), None)
    assert not ok and "EPERM" in detail


def test_probe_exec_nonzero_rc_is_ok(tmp_path):
    # ssh -V style: version flags may exit nonzero on some builds —
    # a completed invocation proves an executable binary
    p = _make_bin(tmp_path, "fake-ssh", """\
        #!/bin/sh
        echo "OpenSSH_9.6" >&2
        exit 1
        """)
    ok, detail, fix = _probe_exec(str(p), "-V")
    assert ok and fix == ""


def test_runtime_check_surface(tmp_path, monkeypatch):
    # integration: run_doctor's runtime loop must surface the
    # present-but-dead binary through the named check
    _make_bin(tmp_path, "nmap", """\
        #!/bin/sh
        echo "exec: Operation not permitted" >&2
        exit 127
        """)
    monkeypatch.setenv(
        "PATH", str(tmp_path) + ":" + __import__("os").environ.get(
            "PATH", ""))
    from hypervisor import doctor
    doctor.CHECKS.clear()
    doctor.run_doctor()
    ent = [c for c in doctor.CHECKS if c["name"] == "runtime: nmap"]
    assert ent and not ent[0]["ok"]
    assert "NOT EXECUTABLE" in ent[0]["detail"]
