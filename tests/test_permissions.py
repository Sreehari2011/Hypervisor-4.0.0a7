"""P1 acceptance tests — permissions.py (PORT-09, the standing critical
fix) + Skeleton 9-3 gate composition.

The port-card acceptance list, in order:
  1. default-deny: unset/absent scope -> every tool refused, journaled
  2. in-scope auto-approve with audit; out-of-scope deny with audit
  3. CIDR/range/host/port-window matrix — oracle parity on the check
     semantics (fixtures from engagement_context's own behavior)
  4. live tightening narrows mid-engagement; expansions capped
  5. path traversal: `../../` payloads rejected by the resolver
Plus the 4.0-specific inversion checks: no TEST MODE exists, signature
mismatch refuses to load, every decision is journaled."""
import asyncio
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

from hypervisor.adapters.openai import frozen_json
from hypervisor.permissions import (Decision, PermissionEngine, RoE,
                                    SafetyClass, ScopeFile, ScopeManager,
                                    ScopeRule, extract_targets_from_command,
                                    infer_target_type, resolve_safe_path)


def make_scope(tmp_path, body, name="scope.json", sign=True):
    body = dict(body)
    if sign:
        fp = hashlib.sha256(frozen_json(body).encode()).hexdigest()
        body["authorization"] = {"operator": "test",
                                 "signed_sha256": fp}
    p = Path(tmp_path) / name
    p.write_text(json.dumps(body))
    return p


@pytest.fixture()
def scope_body():
    return {
        "version": 1, "engagement_id": "ENG-TEST", "mode": "strict",
        "targets": [
            {"target": "10.0.0.0/24", "type": "cidr", "ports": [80, 443]},
            {"target": "*.target.com", "type": "wildcard"},
            {"target": "203.0.113.7", "type": "ip", "ports": [22]},
            {"target": "legacy.example.net", "type": "domain",
             "expires_at": 1000.0},
            {"target": "fresh.example.net", "type": "domain",
             "expires_at": 2000000000.0},
        ],
        "excludes": ["10.0.0.1", "printer.target.com"],
        "roe": {"poc_only": True},
    }


@pytest.fixture()
def sm(scope_body, tmp_path):
    return ScopeManager(ScopeFile.load(
        make_scope(tmp_path, scope_body)))


class NetTool:
    name = "run_command"

    def safety_class(self, args):
        return SafetyClass.EXPLOIT

    def extract_targets(self, args):
        return extract_targets_from_command(args["command"])


class ReadTool(NetTool):
    name = "read_file"

    def safety_class(self, args):
        return SafetyClass.READ

    def extract_targets(self, args):
        return []


class DestructiveTool(NetTool):
    def safety_class(self, args):
        return SafetyClass.DESTRUCTIVE


class PathTool:
    name = "write_file"
    path_args = ("path",)

    def safety_class(self, args):
        return SafetyClass.WRITE

    def extract_targets(self, args):
        return []


# ─── 1. default-deny ───────────────────────────────────────────────────


def test_absent_scope_file_refuses_to_load(tmp_path):
    with pytest.raises((FileNotFoundError, json.JSONDecodeError)):
        ScopeFile.load(tmp_path / "missing.json")


def test_empty_scope_refuses_to_load(tmp_path):
    p = make_scope(tmp_path, {"targets": []}, name="empty.json")
    with pytest.raises(ValueError, match="no targets"):
        ScopeFile.load(p)


def test_unset_scope_means_every_tool_refused(tmp_path):
    """Structural: an engine cannot exist without a loaded scope file —
    there is no flag, no TEST MODE, no bypass anywhere in the module."""
    import ast
    import inspect
    import hypervisor.permissions as perm
    # scan CODE only (docstrings quote the 3.x pathology and must not
    # trip the ban)
    tree = ast.parse(inspect.getsource(perm))
    code_segments = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Assign, ast.If, ast.For, ast.While)):
            code_segments.append(ast.unparse(node))
    code = "\n".join(code_segments)
    for banned in ("SCOPE_ENFORCEMENT", "TEST MODE",
                   "enforcement disabled"):
        assert banned not in code, banned
    assert not hasattr(perm, "scope_enforcement_enabled")


# ─── signature / scope-file integrity ──────────────────────────────────


def test_signature_mismatch_refuses_to_load(tmp_path, scope_body):
    tampered = dict(scope_body)
    tampered["targets"] = scope_body["targets"] + [
        {"target": "9.9.9.9", "type": "ip"}]
    # keep the ORIGINAL signature over the tampered body
    fp = hashlib.sha256(frozen_json(scope_body).encode()).hexdigest()
    tampered["authorization"] = {"signed_sha256": fp}
    p = Path(tmp_path) / "tampered.json"
    p.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="signature mismatch"):
        ScopeFile.load(p)


def test_scope_ref_rides_the_fingerprint(tmp_path, scope_body):
    sf = ScopeFile.load(make_scope(tmp_path, scope_body))
    ref = sf.scope_ref()
    assert ref.startswith("sha256:") and "(signed)" in ref
    sf2 = ScopeFile.load(make_scope(tmp_path, scope_body,
                                    name="unsigned.json", sign=False))
    assert "(unsigned)" in sf2.scope_ref()


# ─── 3. oracle-parity check matrix ─────────────────────────────────────


@pytest.mark.parametrize("target,port,want", [
    ("10.0.0.5", None, True),     # CIDR member
    ("10.0.0.1", None, False),    # exclude beats include
    ("10.0.0.5", 22, False),      # port window (80/443 only)
    ("10.0.0.5", 80, True),
    ("10.0.0.5", 8080, False),
    ("app.target.com", None, True),    # wildcard
    ("printer.target.com", None, False),
    ("deep.sub.target.com", None, True),
    ("203.0.113.7", 22, True),         # IP + port
    ("203.0.113.7", 23, False),
    ("203.0.113.8", None, False),
    ("legacy.example.net", None, False),   # expired rule
    ("fresh.example.net", None, True),     # unexpired
    ("evil.com", None, False),             # deny-by-default
    ("", None, False),
    ("10.0.0.256", None, False),
])
def test_is_authorized_matrix(sm, target, port, want):
    ok, reason = sm.is_authorized(target, port)
    assert ok == want, (target, port, reason)


def test_protocol_and_port_window_semantics():
    rules = [ScopeRule.from_dict({
        "target": "10.0.0.5", "ports": [443],
        "protocols": ["https"]})]
    sf = ScopeFile.__new__(ScopeFile)     # bypass load for a unit probe
    sf.rules, sf.mode, sf.excludes = rules, "strict", []
    sf.expansion_cap, sf.roe, sf.signed = 256, RoE(), False
    sf.fingerprint, sf.version, sf.engagement_id = "x" * 64, 1, "t"
    sf.path = None
    m = ScopeManager(sf)
    assert m.is_authorized("10.0.0.5", 443, "https") == (True, "Authorized")
    assert m.is_authorized("10.0.0.5", 443, "tcp")[0] is False
    assert m.is_authorized("10.0.0.5", 8443, "https")[0] is False


def test_infer_target_type():
    assert infer_target_type("1.2.3.4") == "ip"
    assert infer_target_type("10.0.0.0/8") == "cidr"
    assert infer_target_type("*.x.com") == "wildcard"
    assert infer_target_type("x.com") == "domain"


# ─── 2. gate composition + audit ───────────────────────────────────────


def test_gate_scoped_full_auto(sm, tmp_path):
    from hypervisor.persist.journal import Journal
    j = Journal(tmp_path / "j")
    eng = PermissionEngine(sm, journal=j)

    async def check(tool, args):
        return await eng.check_permission(tool, args)

    # in-scope EXPLOIT -> auto-approve with action audit
    d = asyncio.run(check(NetTool(), {"command": "nmap 10.0.0.5"}))
    assert d.allowed and d.audit == "action"
    assert d.rule == "scope:action-in-scope"
    # out-of-scope -> deny
    d = asyncio.run(check(NetTool(), {"command": "nmap 192.168.1.1"}))
    assert not d.allowed and d.rule == "scope:out-of-scope"
    # READ, no targets -> allow with recon audit
    d = asyncio.run(check(ReadTool(), {"path": "x"}))
    assert d.allowed and d.audit == "recon"
    # DESTRUCTIVE -> RoE owns it
    d = asyncio.run(check(DestructiveTool(), {"command": "rm -rf /"}))
    assert not d.allowed and d.rule == "roe:destructive-disabled"

    # EVERY decision journaled (allow AND deny), each with scope_ref
    evs = [e for e in j.events()
           if e["type"] == "permission_decision"]
    assert len(evs) == 4
    assert sum(1 for e in evs if e["data"]["allowed"]) == 2
    assert all(e["data"]["scope_ref"].startswith("sha256:")
               for e in evs)
    assert all(e["data"].get("args_digest") for e in evs)


def test_gate_poc_only_blocks_persistent(sm):
    class PersistentTool(NetTool):
        def is_persistent(self, args):
            return True

    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            PersistentTool(), {"command": "install backdoor 10.0.0.5"})
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "roe:poc-only"


def test_unclassifiable_tool_gets_the_safest_class(sm):
    class Weird:
        name = "weird"

        def safety_class(self, args):
            raise RuntimeError("nope")

    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(Weird(), {})
    d = asyncio.run(go())
    assert not d.allowed and d.safety == "destructive"


# ─── 4. tightening + expansion cap ─────────────────────────────────────


def test_live_tightening_and_expansion_cap(tmp_path, scope_body):
    body = dict(scope_body)
    body["mode"] = "expand"
    body["expansion_cap"] = 2
    sm = ScopeManager(ScopeFile.load(make_scope(tmp_path, body, "ex.json")))
    assert sm.mode == "expand"
    assert sm.classify_host("a.target.com")["outcome"] == "admitted"
    assert sm.classify_host("b.target.com")["outcome"] == "admitted"
    assert sm.classify_host("c.target.com")["outcome"] == "cap"
    assert sm.classify_host("saas.example.io")["outcome"] == \
        "non-subdomain"
    assert sm.classify_host("printer.target.com")["outcome"] == "excluded"
    # admission authorizes the gate
    ok, _ = sm.is_authorized("a.target.com")
    assert ok
    # live tightening is the ONLY runtime mode mutation
    assert sm.tighten_strict() is True
    assert sm.mode == "strict"
    assert sm.tighten_strict() is False   # idempotent


def test_tightening_journals_scope_mode(tmp_path, scope_body):
    from hypervisor.persist.journal import Journal
    j = Journal(tmp_path / "j")
    body = dict(scope_body)
    body["mode"] = "expand"
    sm = ScopeManager(ScopeFile.load(make_scope(tmp_path, body, "t.json")),
                      journal=j)
    assert sm.tighten_strict(source="operator")
    evs = [e for e in j.events() if e["type"] == "scope_mode"]
    assert evs and evs[-1]["data"]["mode"] == "strict"


# ─── 5. path traversal ─────────────────────────────────────────────────


def test_path_resolver_traversal_matrix(tmp_path):
    ws = str(tmp_path)
    os.makedirs(os.path.join(ws, "buffers"), exist_ok=True)
    assert resolve_safe_path("notes.txt", ws) == \
        os.path.realpath(os.path.join(ws, "notes.txt"))
    assert resolve_safe_path("../../../etc/passwd", ws) is None
    assert resolve_safe_path("workspace/buffers/x.log", ws) is not None
    assert resolve_safe_path("workspace/buffers/../../etc", ws) is None
    deep = "a/b/c/../../../../../../etc"
    assert resolve_safe_path(deep, ws) is None


def test_gate_denies_path_escape(sm, tmp_path):
    from hypervisor.tools.base import ToolContext, ToolRegistry
    eng = PermissionEngine(sm)
    ctx = ToolContext(workspace=str(tmp_path), registry=ToolRegistry(),
                      permissions=eng)

    async def go():
        return await eng.check_permission(
            PathTool(), {"path": "../../outside.txt"}, ctx)
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "path-escape"


def test_decision_helpers():
    d = Decision.allow("r", audit="recon")
    assert d.allowed and d.audit == "recon"
    d = Decision.deny("r", reason="why")
    assert not d.allowed and d.reason == "why"


# ─── 9. command-target extraction: the PILOT-02 false-positive classes ──


def test_url_path_suffix_is_not_a_cidr():
    # pilot-02 turn 10: "curl ... http://10.10.0.5/22" was denied
    # because the URL path was read as a CIDR token
    got = extract_targets_from_command("curl -m 8 http://10.10.0.5/22")
    assert "10.10.0.5/22" not in got
    assert "10.10.0.5" in got          # the host still gates


def test_argument_position_cidr_stays_strict():
    # nmap semantics: network-scan intent keeps deny-by-default —
    # canonical AND sloppy host-bits-set notation alike
    assert "10.0.0.0/22" in extract_targets_from_command(
        "nmap -sV 10.0.0.0/22")
    assert "10.0.0.5/22" in extract_targets_from_command(
        "nmap -sV 10.0.0.5/22")


def test_prefix_over_32_is_never_a_cidr():
    got = extract_targets_from_command("curl 10.10.0.5/80")
    assert "10.10.0.5/80" not in got
    assert "10.10.0.5" in got          # host/port or path notation


def test_path_component_domains_are_not_targets():
    assert "probe.py" not in extract_targets_from_command(
        "python3 /app/workspace/pilot-02/probe.py")
    assert "hosts.txt" not in extract_targets_from_command(
        "nmap -iL /tmp/hosts.txt")


def test_output_and_exception_tokens_are_not_domains():
    # pilot-02 turn 3: "socket.timeout" denied the fallback probe
    got = extract_targets_from_command("echo 'socket.timeout' | tee probe.log")
    assert "socket.timeout" not in got
    assert "probe.log" not in got


def test_bare_cctld_shaped_hosts_stay_gated():
    # .py (Paraguay), .sh (St. Helena), .md (Moldova) are real TLDs:
    # bare connection targets keep deny-by-default — filename-shaped
    # false positives lose the tie, on purpose
    assert "probe.py" in extract_targets_from_command("python3 probe.py")
    assert "evil.sh" in extract_targets_from_command("nc -zv evil.sh 22")


def test_gate_allows_url_path_suffix_on_in_scope_host(sm):
    # the exact pilot-02 shape: authorized host, /NN URL path
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            NetTool(), {"command": "curl -m 8 http://10.0.0.5/22"})
    d = asyncio.run(go())
    assert d.allowed and d.rule == "scope:action-in-scope"


def test_gate_still_denies_argument_position_cidr(sm):
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            NetTool(), {"command": "nmap -sV 10.0.0.0/22"})
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "scope:out-of-scope"


def test_gate_still_denies_sloppy_host_bits_cidr(sm):
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            NetTool(), {"command": "nmap -sV 10.0.0.5/22"})
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "scope:out-of-scope"


# ─── PILOT-03: multi-label hosts must extract whole (run-1 defect) ─────

def test_four_label_host_extracts_whole():
    # run-1: the single-optional-label regex truncated the sanctioned
    # target to 'dppmsserchhip.mizoram.gov' and the scope check denied
    # every bare-hostname shell action as out-of-scope
    got = extract_targets_from_command(
        "dig +short dppmsserchhip.mizoram.gov.in A")
    assert "dppmsserchhip.mizoram.gov.in" in got
    assert "dppmsserchhip.mizoram.gov" not in got

def test_five_label_host_extracts_whole():
    got = extract_targets_from_command(
        "nmap -sT -p 80,443 www.dppmsserchhip.mizoram.gov.in")
    assert "www.dppmsserchhip.mizoram.gov.in" in got

def test_bare_and_url_forms_agree_on_multi_label():
    a = extract_targets_from_command(
        "curl -m 8 https://dppmsserchhip.mizoram.gov.in/")
    b = extract_targets_from_command(
        "curl -m 8 dppmsserchhip.mizoram.gov.in")
    assert "dppmsserchhip.mizoram.gov.in" in a
    assert "dppmsserchhip.mizoram.gov.in" in b

def test_multi_label_suffix_filter_still_applies():
    # the code-attr filter keys on the LAST label; greedy multi-label
    # must not bypass it
    got = extract_targets_from_command("echo a.b.socket.timeout")
    assert "a.b.socket.timeout" not in got

def test_multi_label_code_text_denies_failsafe():
    # documented trade-off: deep dotted chains in code text now extract
    # and DENY (fail-safe direction) rather than silently passing
    got = extract_targets_from_command(
        "python3 -c 'import org.springframework.boot.autoconfigure'")
    assert "org.springframework.boot.autoconfigure" in got


# ─── PILOT-03: fail-closed guard for targetless network commands ──────

class ShellTool(NetTool):
    """RunCommandTool wiring for the guard: EXPLOIT class, shared
    extraction, and the production target_required hook."""

    def target_required(self, args):
        from hypervisor.tools.core import _invokes_network_binary
        return _invokes_network_binary(args["command"])


def test_guard_flags_network_binaries():
    from hypervisor.tools.core import _invokes_network_binary as net
    assert net("curl -sS -o /dev/null")
    assert net("wget -qO- https://example.com/")
    assert net("dig +short example.com")
    assert net("nmap -sT -p 80 example.com")
    assert net("/usr/bin/curl --version")
    assert net("timeout 10 curl -s http://example.com/")
    assert net("proxychains4 nmap -sT example.com")
    assert net("echo hi; curl http://example.com/")
    assert net("echo $(curl http://example.com/)")


def test_guard_ignores_prose_and_local_commands():
    from hypervisor.tools.core import _invokes_network_binary as net
    assert not net('echo "run nmap later"')
    assert not net("ls -la")
    assert not net("grep -rn nmap .")
    assert not net("python3 exploit.py --host x")
    assert not net("cat notes.txt | grep curl")


def test_gate_denies_targetless_network_command(sm):
    # run-1 turn-6 class: network binary, zero extractable targets —
    # deny, not pass
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            ShellTool(), {"command": "curl -m 8 -sS -o /dev/null"})
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "scope:no-target"


def test_gate_denies_targetless_curl_behind_wrappers(sm):
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            ShellTool(), {"command": "timeout 5 curl -m 4; echo done"})
    d = asyncio.run(go())
    assert not d.allowed and d.rule == "scope:no-target"


def test_gate_targetless_local_command_still_allowed(sm):
    # boundary: the guard demands targets only of network binaries —
    # a targetless local side-effect stays allowed
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            ShellTool(), {"command": "echo hello-world-no-target"})
    d = asyncio.run(go())
    assert d.allowed and d.rule == "scope:action-in-scope"


def test_gate_targeted_curl_in_scope_still_allowed(sm):
    # regression pin for the P0 fix: a real in-scope target must pass
    eng = PermissionEngine(sm)

    async def go():
        return await eng.check_permission(
            ShellTool(), {"command": "curl -m 8 http://10.0.0.5/"})
    d = asyncio.run(go())
    assert d.allowed and d.rule == "scope:action-in-scope"
