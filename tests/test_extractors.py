"""Acceptance tests for the Tier-A extractor port (PORT-04).

Fixture corpus -> extracted nodes/edges; crash containment (the batch
skips, flags, never breaks the tool path); the fold auditor's
force-add guarantee (the MD-2 killer); the security-entity regex
battery including the M14 truncation signal.
"""
import json
from pathlib import Path

import pytest

from hypervisor.memory import ekd as ekd_mod
from hypervisor.memory.ekd import (
    DAGNode, EdgeKind, EngagementDAG, EkdBatch,
)
from hypervisor.memory.extractors import (
    CVE_RE, audit_fold, ensure_objective, extract_security_entities,
    extract_tool_result, parse_free_text, parse_http_response,
    parse_nmap, parse_nuclei, run_post_hook, sync_todos,
)
from hypervisor.persist.journal import Journal


class _Scope:
    mode = "strict"

    def is_authorized(self, target, port=None):
        return (str(target).startswith("10.10.11."), "scope rule")

    def classify_host(self, host, method="", strict_classify=True):
        if str(host).startswith("10.10.11."):
            return {"in_scope": True, "scope_reason": "rule:lab-cidr"}
        return {"in_scope": False, "scope_reason": "adjacent:no-match"}


class _Gate:
    scope = _Scope()


class _Ctx:
    def __init__(self, journal=None, extra=None, workspace=None):
        self.journal = journal
        self.extra = dict(extra or {})
        self.permissions = _Gate()
        self.workspace = workspace or ""
        self.label = "main"


NMAP_JSON = json.dumps([{
    "host": "10.10.11.23",
    "hostname": "app.example.com",
    "ports": [
        {"port": 22, "protocol": "tcp", "state": "open",
         "service": {"name": "ssh", "product": "OpenSSH",
                     "version": "8.4p1"}},
        {"port": 8080, "protocol": "tcp", "state": "filtered",
         "service": {"name": "http-proxy"}},
    ],
}])

NUCLEI_JSONL = "\n".join([
    json.dumps({"template-id": "CVE-2021-44228-log4shell",
                "info": {"name": "Log4Shell RCE", "severity": "critical",
                         "tags": ["rce", "log4j"]},
                "matched-at": "http://10.10.11.23:8080/login",
                "reference": ["https://nvd.nist.gov/vuln/detail/"
                              "CVE-2021-44228"]}),
    json.dumps({"template-id": "tech-detect",
                "info": {"name": "Tech: Apache Struts",
                         "severity": "info"},
                "matched-at": "10.10.11.23:8080"}),
    "not json at all",
])

HTTP_OUTPUT = (
    "--- HTTP METADATA ---\n"
    + json.dumps({"status_code": 200, "headers": {
        "Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}}) + "\n"
    "--- HTTP BODY ---\n"
    "<html>welcome</html>\n"
    "SECURITY INDICATORS DETECTED\n"
    "== Missing X-Frame-Options header (clickjacking) ==\n"
    "== Server header leaks version nginx/1.18.0 ==\n"
    "--- HTTP BODY ---\n"
)

FREE_TEXT = """
Found credential: password = 'Sup3rS3cret!' for admin at 10.10.11.23:22
JWT observed: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP
mB92K27uhbUJU1p1r_wW1gFWFOEjXk
Endpoint http://10.10.11.23:8080/api/v1/login is vulnerable to SQL injection
(CWE-89). Also references CVE-2023-44487.
"""


# ── fixture corpus: oracle-recorded tool outputs -> nodes/edges ──────

def test_parse_nmap_creates_host_ports_tech():
    ekd = EngagementDAG()
    call = ekd.add(DAGNode(id="", type="call", title="nmap"))
    ctx = _Ctx()
    added = parse_nmap(ekd, NMAP_JSON, call, ctx)
    assert added >= 3          # oracle metric: hosts + ports
    host = ekd.by_key("ip:10.10.11.23")
    assert host is not None and host.attrs["state"] == "up"
    ssh = ekd.by_key("port:10.10.11.23:22/tcp")
    assert ssh is not None
    assert ssh.attrs["service"] == "ssh"
    assert ssh.attrs["service_version"] == "OpenSSH 8.4p1"
    domain = ekd.by_key("domain:app.example.com")
    assert domain is not None
    tech = ekd.by_key("tech:openssh@8.4p1")
    assert tech is not None
    # scope admission traveled with the entity (SD-1)
    assert host.attrs["in_scope"] is True
    # state-change supersession: filtered -> open invalidates + revives
    opened = json.loads(NMAP_JSON)
    opened[0]["ports"][1]["state"] = "open"
    parse_nmap(ekd, json.dumps(opened), call, ctx)
    ps = ekd.by_key("port:10.10.11.23:8080/tcp")
    assert ps.attrs["state"] == "open"
    history = [n for n in ekd.nodes.values()
               if n.subtype == "port_service"
               and n.key == "port:10.10.11.23:8080/tcp"]
    assert any(n.valid_to is not None for n in history)  # superseded kept


def test_parse_nuclei_findings_and_cve_nodes():
    ekd = EngagementDAG()
    call = ekd.add(DAGNode(id="", type="call", title="nuclei"))
    added = parse_nuclei(ekd, NUCLEI_JSONL, call, _Ctx())
    assert added >= 2
    crit = ekd.by_key(
        "finding:nuclei:CVE-2021-44228-log4shell:"
        + __import__("hashlib").sha256(
            b"http://10.10.11.23:8080/login").hexdigest()[:12])
    assert crit is not None
    assert crit.attrs["severity"] == "critical"
    assert crit.attrs["cve"] == "CVE-2021-44228"
    # the CVE itself became a node (fold-audit guarantee for nuclei)
    cve = ekd.by_key("cve:CVE-2021-44228")
    assert cve is not None and cve.type == "finding"
    # endpoint entity from matched-at URL
    ep = ekd.by_key("url:http://10.10.11.23:8080/login")
    assert ep is not None
    # observed_on edge links finding -> endpoint
    obs = ekd.neighbors(crit.id, kinds=(EdgeKind.OBSERVED_ON,))
    assert obs and obs[0].id == ep.id


def test_parse_http_response_metadata_and_indicators():
    ekd = EngagementDAG()
    call = ekd.add(DAGNode(id="", type="call", title="http"))
    args = {"url": "http://10.10.11.23:8080/login"}
    added = parse_http_response(ekd, HTTP_OUTPUT, call, args, _Ctx())
    assert added >= 3
    ep = ekd.by_key("url:http://10.10.11.23:8080/login")
    assert ep.attrs["status"] == 200
    assert ep.attrs["server"] == "nginx/1.18.0"
    assert ep.attrs["state"] == "http_200"
    tech = ekd.by_key("tech:nginx/1.18.0")
    assert tech is not None
    # passive indicators -> findings
    findings = ekd.nodes_of_type("finding")
    titles = " ".join(f.title for f in findings)
    assert "X-Frame-Options" in titles


def test_parse_free_text_battery():
    ekd = EngagementDAG()
    call = ekd.add(DAGNode(id="", type="call", title="shell"))
    added = parse_free_text(ekd, FREE_TEXT, call, _Ctx())
    assert added >= 5
    assert ekd.by_key("ip:10.10.11.23") is not None
    assert ekd.by_key("port:10.10.11.23:22/tcp") is not None
    cred = ekd.by_key("cred:fp:cred:"
                      + __import__("hashlib").sha256(
                          b"Sup3rS3cret!").hexdigest()[:8])
    assert cred is not None
    # the VALUE is never stored — masked only
    assert "Sup3rS3cret!" not in json.dumps(cred.attrs)
    assert cred.attrs["masked"].startswith("Su")
    assert ekd.by_key("url:http://10.10.11.23:8080/api/v1/login") is not None
    assert ekd.by_key("cve:CVE-2023-44487") is not None
    # vuln class referenced -> class finding
    classes = [f for f in ekd.nodes_of_type("finding")
               if f.attrs.get("source") == "text_reference"]
    assert any("SQL injection" in f.title for f in classes)


def test_extract_security_entities_priority_and_dedup():
    ents = extract_security_entities(FREE_TEXT)
    kinds = [k for k, _ in ents]
    assert "credential" in kinds and "jwt" in kinds
    assert "ipv4" in kinds and "url" in kinds and "vuln_class" in kinds
    # dedup: same ip appears multiple times, extracted once
    ips = [v for k, v in ents if k == "ipv4"]
    assert ips == ["10.10.11.23"]
    # M14: truncation signal when the per-kind cap truly drops values
    noisy = " ".join(f"10.1.{i // 256}.{i % 256}" for i in range(60))
    found, truncated = extract_security_entities(
        noisy, max_per_kind=10, return_truncated=True)
    assert len([v for k, v in found if k == "ipv4"]) == 10
    assert "ipv4" in truncated
    # exactly-at-cap with no further distinct values does not trip
    exact = " ".join(["1.2.3.4"] * 50)
    found2, truncated2 = extract_security_entities(
        exact, max_per_kind=10, return_truncated=True)
    assert len(found2) == 1 and truncated2 == []


# ── crash containment: the batch flags, the caller never sees it ─────

def test_run_post_hook_crash_contained(tmp_path):
    j = Journal(tmp_path / "journal")
    ekd = EngagementDAG()
    ctx = _Ctx(j, {"ekd": ekd,
                   "extractor_failures": ekd_mod.new_extractor_failures()})
    # inject a parser that explodes
    import hypervisor.memory.extractors as ex
    original = ex._TIER_A_PARSERS.get("network_scan_nmap")
    ex._TIER_A_PARSERS["network_scan_nmap"] = \
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("parser boom"))
    try:
        out = run_post_hook(ctx, "network_scan_nmap", {}, NMAP_JSON)
    finally:
        if original is not None:
            ex._TIER_A_PARSERS["network_scan_nmap"] = original
        else:
            ex._TIER_A_PARSERS.pop("network_scan_nmap", None)
    assert out is None                       # flagged, not raised
    errs = [e for e in j.events_of_type("error")
            if e["data"].get("extractor") == "tier_a"]
    assert errs and "parser boom" in errs[0]["data"]["detail"]
    assert ctx.extra["extractor_failures"]["total"] >= 1
    # the graph rolled back to pre-batch state
    assert all(n.type != "entity" for n in ekd.nodes.values())


def test_run_post_ok_path_records_call_and_targets(tmp_path):
    j = Journal(tmp_path / "journal")
    ekd = EngagementDAG()
    obj = ensure_objective(ekd, "test the lab")
    ctx = _Ctx(j, {"ekd": ekd, "objective_id": obj,
                   "extractor_failures": ekd_mod.new_extractor_failures()})
    call_id = run_post_hook(ctx, "run_command",
                            {"command": "nmap -sV 10.10.11.23"},
                            FREE_TEXT, tool_call_id="tu_1")
    assert call_id
    muts = j.events_of_type("ekd_mutation")
    assert muts and muts[-1]["data"]["tool_call_id"] == "tu_1"
    # command-string target became a host entity (scope-engine parser)
    assert ekd.by_key("ip:10.10.11.23") is not None
    # free-text battery ran for the shell tool
    assert ekd.by_key("cve:CVE-2023-44487") is not None


def test_nuclei_sniff_through_shell_tool():
    ekd = EngagementDAG()
    call = ekd.add(DAGNode(id="", type="call", title="sh"))
    from hypervisor.memory.extractors import _looks_like_nuclei_jsonl
    assert _looks_like_nuclei_jsonl(NUCLEI_JSONL)
    added = extract_tool_result(ekd, "run_command", {}, NUCLEI_JSONL,
                                "main", _Ctx())
    assert added  # returns call id
    assert ekd.by_key(
        "finding:nuclei:CVE-2021-44228-log4shell:"
        + __import__("hashlib").sha256(
            b"http://10.10.11.23:8080/login").hexdigest()[:12]) is not None


# ── the fold auditor (MD-2 killer) ────────────────────────────────────

def test_audit_fold_force_adds_missing_tokens():
    ekd = EngagementDAG()
    # slice mentions tokens that were never extracted into the graph
    slice_texts = [
        "recon found 192.168.1.50 alive, https://old.example.com/admin "
        "exposed, token=Or4clePw! and CVE-2019-0708 relevant"]
    report = audit_fold(ekd, slice_texts)
    assert report["missing"] >= 4
    assert report["force_added"] == report["missing"]
    # every hard fact token is now a node — the guarantee holds BY
    # CONSTRUCTION
    assert ekd.by_key("ip:192.168.1.50") is not None
    assert ekd.by_key("url:https://old.example.com/admin") is not None
    assert ekd.by_key("cve:CVE-2019-0708") is not None
    # re-audit finds nothing missing
    report2 = audit_fold(ekd, slice_texts)
    assert report2["missing"] == 0


def test_audit_fold_soft_tokens_logged_not_enforced():
    ekd = EngagementDAG()
    hexblob = " ".join("%032x" % i for i in range(3))
    report = audit_fold(ekd, [f"hashes {hexblob}"])
    assert report["missing"] == 0       # hex tokens are soft


# ── todo sync (task mirror) ───────────────────────────────────────────

def test_sync_todos_creates_and_updates_task_nodes():
    ekd = EngagementDAG()
    n = sync_todos(ekd, [
        {"id": "1", "content": "recon the lab", "status": "in_progress"},
        {"id": "2", "content": "verify log4shell", "status": "pending"}])
    assert n == 2
    tasks = ekd.nodes_of_type("task")
    assert len(tasks) == 2
    # status change routes through add(): tracked-attr supersession
    sync_todos(ekd, [{"id": "2", "content": "verify log4shell",
                      "status": "completed"}])
    t2 = [t for t in ekd.nodes_of_type("task")
          if "verify" in t.title][0]
    assert t2.attrs["status"] == "completed"
    assert any(h.get("attr") == "status" for h in t2.attrs.get("history", []))


def test_todo_write_tool_syncs_graph(tmp_path):
    from hypervisor.tools.core import TodoWriteTool, build_registry
    from hypervisor.tools.base import ToolContext
    reg = build_registry()
    ekd = EngagementDAG()
    ctx = ToolContext(workspace=str(tmp_path), registry=reg,
                      journal=None, extra={"ekd": ekd})
    tool = reg.resolve("todo_write")
    import asyncio
    res = asyncio.run(tool.call({"todos": [
        {"id": "1", "content": "map the surface", "status": "pending"}]},
        ctx))
    assert not res.is_error
    assert len(ekd.nodes_of_type("task")) == 1


# ── memory_query tool (drilldown surface) ────────────────────────────

def test_memory_query_tool():
    from hypervisor.tools.core import build_registry
    from hypervisor.tools.base import ToolContext
    reg = build_registry()
    ekd = EngagementDAG()
    obj = ensure_objective(ekd, "own the lab")
    call = ekd.add(DAGNode(id="", type="call", title="nmap"))
    parse_nmap(ekd, NMAP_JSON, call, _Ctx())
    ctx = ToolContext(workspace="/tmp/x", registry=reg, journal=None,
                      extra={"ekd": ekd})
    tool = reg.resolve("memory_query")
    import asyncio
    res = asyncio.run(tool.call({"query": "10.10.11.23"}, ctx))
    assert not res.is_error
    assert "ip:10.10.11.23" in res.content or "10.10.11.23" in res.content
    assert "=== e" in res.content            # node detail rendered
    res2 = asyncio.run(tool.call({"query": "zzz-no-match"}, ctx))
    assert "No EKD match" in res2.content
    # id lookup
    host = ekd.by_key("ip:10.10.11.23")
    res3 = asyncio.run(tool.call({"query": host.id}, ctx))
    assert host.id in res3.content
