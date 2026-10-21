"""Acceptance tests for the brief renderer port (PORT-11).

Determinism (frozen triple -> frozen sha), the budget floor +
escalation + brief_overflow journaling, the cache (repeated rev+budget
-> single render, cache_hit marked), the degradation ladder, and the
Zone-T attachment shape.
"""
import hashlib
import json
from pathlib import Path

import pytest

from hypervisor.memory.brief import (
    BRIEF_ATTACHMENT_CLOSE, BRIEF_ATTACHMENT_OPEN, BriefRenderer,
    L2_DRILLDOWN_LINE, render_brief_l2, render_node_detail,
)
from hypervisor.memory.ekd import (
    DAGNode, EdgeKind, EngagementDAG,
)
from hypervisor.memory.extractors import ensure_objective, parse_nmap
from hypervisor.persist.journal import Journal

from test_extractors import NMAP_JSON, _Ctx


def _graph(n_findings=3, n_hosts=4, objective="own the lab") -> EngagementDAG:
    ekd = EngagementDAG()
    ensure_objective(ekd, objective)
    call = ekd.add(DAGNode(id="", type="call", title="recon"))
    parse_nmap(ekd, NMAP_JSON, call, _Ctx())
    for i in range(n_findings):
        sev = ("critical", "high", "medium", "low", "info")[i % 5]
        ekd.add(DAGNode(
            id="", type="finding",
            key=f"finding:test:{i}", title=f"finding number {i}",
            attrs={"severity": sev, "status": "open",
                   "class": "rce"}))
    for i in range(n_hosts):
        ekd.add(DAGNode(
            id="", type="entity", subtype="host",
            key=f"ip:10.10.12.{i}", title=f"10.10.12.{i}",
            attrs={"host": f"10.10.12.{i}", "in_scope": True}))
    ekd.add(DAGNode(
        id="", type="hypothesis", key="hyp:1",
        title="log4shell leads to RCE via jndi",
        attrs={"status": "active"}))
    ekd.add(DAGNode(
        id="", type="task", key="task:todo:1", title="verify log4shell",
        attrs={"status": "running", "agent": "main"}))
    return ekd


# ── 1. determinism: same (rev, budget, now) -> same bytes ────────────

def test_determinism_frozen_triple():
    import time as _time
    ekd = _graph()
    base = _time.time() + 60        # future clock: ages are non-degenerate
    a, ma = render_brief_l2(ekd, token_budget=700, now=base)
    b, mb = render_brief_l2(ekd, token_budget=700, now=base)
    assert a == b and ma == mb
    # a different pinned clock changes only the age string (freshness
    # is honest), never the content ordering
    c, _ = render_brief_l2(ekd, token_budget=700, now=base + 7200)
    assert c != a
    assert c.count("OBJECTIVE") == a.count("OBJECTIVE")


def test_contract_sections_present():
    ekd = _graph()
    brief, meta = render_brief_l2(ekd, token_budget=700)
    assert meta["contract"] == "l2"
    assert brief.startswith("=== ENGAGEMENT KNOWLEDGE (rev ")
    for section in ("OBJECTIVE", "TASKS", "FINDINGS", "ATTACK SURFACE",
                    "HYPOTHESES", "RESIDUAL NOTES"):
        assert section in brief, section
    assert L2_DRILLDOWN_LINE in brief
    assert "own the lab" in brief            # verbatim objective
    assert meta["sections"]["findings"]["total"] >= 3


def test_residual_states():
    ekd = _graph()
    _, m_full = render_brief_l2(ekd, residual="prose nuance here")
    assert m_full["sections"]["residual"]["state"] == "full"
    _, m_empty = render_brief_l2(ekd, residual="")
    assert m_empty["sections"]["residual"]["state"] == "empty"
    _, m_sentinel = render_brief_l2(ekd, residual="No previous summary.")
    assert m_sentinel["sections"]["residual"]["state"] == "empty"


# ── 2. degradation ladder + floor ─────────────────────────────────────

def test_degradation_ladder_shrinks_bottom_up():
    ekd = _graph()
    big, m_big = render_brief_l2(ekd, token_budget=700)
    small, m_small = render_brief_l2(ekd, token_budget=120)
    assert len(small) < len(big)
    # floor sections survive the squeeze
    assert "OBJECTIVE" in small and "TASKS" in small
    # residual dropped before findings lost entries
    assert m_small["sections"]["residual"]["state"] in ("elided", "absent")
    # bottom-up order visible: surface/hypotheses degraded, findings kept
    assert m_small["sections"]["attack_surface"]["dropped"] > \
        m_big["sections"]["attack_surface"]["dropped"]
    # monotone budget: never exceeds the ceiling (I4)
    assert m_small["tokens"] <= m_small["ceiling"]


def test_floor_overflow_escalates_and_journals(tmp_path):
    j = Journal(tmp_path / "journal")
    huge = "X" * 4000  # pathological single-line objective
    ekd = _graph(objective=huge)
    r = BriefRenderer(journal=j, token_budget=120, hard_ceiling=800)
    brief, facts = r.render(ekd, "")
    r.journal_render(facts)              # the J2 surface
    assert facts["escalated"] is True
    assert facts["overflow"]["objective_id"].startswith("O")
    assert "first line" in brief
    assert "objective continues in the journal" in brief
    overflows = j.events_of_type("brief_overflow")
    assert overflows and overflows[-1]["data"]["rev"] == facts["brief_rev"]


def test_ceiling_violation_raises_never_silent():
    ekd = _graph(objective="Y" * 3000)
    with pytest.raises(ValueError, match="hard ceiling"):
        render_brief_l2(ekd, token_budget=100, hard_ceiling=150)


# ── 3. cache: repeated (rev, budget) -> single render, hit marked ────

def test_render_cache_reuse_marks_hit(tmp_path):
    j = Journal(tmp_path / "journal")
    r = BriefRenderer(journal=j)
    ekd = _graph()
    b1, f1 = r.render(ekd, "residual text")
    b2, f2 = r.render(ekd, "residual text")
    assert b1 == b2
    assert f1["cache_hit"] is False and f2["cache_hit"] is True
    # same pinned now reused on the hit (replay reconstructs with it)
    assert f1["now"] == f2["now"]
    # a mutation (rev bump) invalidates
    ekd.add(DAGNode(id="", type="note", key="note:new", title="x"))
    b3, f3 = r.render(ekd, "residual text")
    assert f3["cache_hit"] is False and b3 != b1
    # a changed residual invalidates (documented refinement)
    b4, f4 = r.render(ekd, "different residual")
    assert f4["cache_hit"] is False


def test_journal_render_writes_j2(tmp_path):
    j = Journal(tmp_path / "journal")
    r = BriefRenderer(journal=j)
    ekd = _graph()
    brief, facts = r.render(ekd, "")
    r.journal_render(facts, prompt_hash="ph", window_msg_count=3,
                     window_hash="wh")
    evs = j.events_of_type("brief_render")
    assert evs
    e = evs[-1]["data"]
    assert e["hash"] == facts["brief_hash"]
    assert e["rev"] == facts["brief_rev"]
    assert e["budget"] == 700 and e["contract"] == "l2"
    assert e["prompt_hash"] == "ph" and e["window_hash"] == "wh"
    assert e["cache_hit"] is False
    # the brief text sidecar exists (prompt forensics)
    ref = e.get("brief_ref")
    if ref:
        assert (tmp_path / "journal" / ref).exists()


# ── 4. attachment shape (Zone T contract) ─────────────────────────────

def test_render_attachment_wraps_delimiters():
    ekd = _graph()
    r = BriefRenderer()
    msg, facts = r.render_attachment(ekd, "some residual")
    assert msg["role"] == "user"
    assert msg["content"].startswith(BRIEF_ATTACHMENT_OPEN + "\n")
    assert msg["content"].endswith("\n" + BRIEF_ATTACHMENT_CLOSE)
    assert facts["brief"] in msg["content"]


# ── 5. node detail (drilldown) ────────────────────────────────────────

def test_render_node_detail():
    ekd = _graph()
    host = ekd.by_key("ip:10.10.11.23")
    detail = render_node_detail(ekd, host.id)
    assert host.id in detail and "title:" in detail
    assert "out-edges" in detail or "in-edges" in detail
    assert "unknown" not in render_node_detail(ekd, host.id)[:40]
    missing = render_node_detail(ekd, "zzz")
    assert "No node" in missing


def test_scope_surface_lines():
    ekd = _graph()
    # an adjacent host: visible, never targeted
    ekd.add(DAGNode(
        id="", type="entity", subtype="host", key="ip:192.168.0.1",
        title="192.168.0.1",
        attrs={"host": "192.168.0.1", "in_scope": False,
               "scope_reason": "adjacent:no-match"}))
    brief, meta = render_brief_l2(ekd, token_budget=700)
    assert "mode=strict" in brief or "mode=expand" in brief
    assert "192.168.0.1" in brief          # adjacent stays visible
    assert "ADJACENT" in brief or meta["sections"]["attack_surface"]["dropped"] > 0
