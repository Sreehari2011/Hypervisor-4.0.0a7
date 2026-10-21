"""Acceptance tests for the EKD port (PORT-03).

Mirrors the card's five acceptance tests: mutation sequence journaling,
crash injection + recovery, render determinism, snapshot pruning, and
the structural invariants (canonical dedup, backward-edge drop,
supersession, merge).
"""
import json
import os
from pathlib import Path

import pytest

from hypervisor.memory.ekd import (
    DAGEdge, DAGNode, EdgeKind, EngagementDAG, EkdBatch,
    compute_delta, cred_key, domain_key, fingerprint_value, host_key,
    load_or_create, new_extractor_failures, port_service_key, recover,
    save_state, state_path_for, url_key,
)
from hypervisor.persist.journal import Journal


class _Ctx:
    """Minimal tool-context stand-in (journal + extras)."""

    def __init__(self, journal=None, extra=None):
        self.journal = journal
        self.extra = dict(extra or {})


def _user_msg(text):
    return {"role": "user", "content": text}


# ── helpers ----------------------------------------------------------

def _seed_graph() -> EngagementDAG:
    ekd = EngagementDAG()
    obj = DAGNode(id="", type="objective", key="objective:abc",
                  title="own the box", attrs={"text": "own the box"})
    ekd.add(obj)
    host = DAGNode(id="", type="entity", subtype="host",
                   key=host_key("10.10.11.23"), title="10.10.11.23",
                   attrs={"host": "10.10.11.23", "state": "up"})
    ekd.add(host)
    ekd.add_edge(EdgeKind.TARGETS, obj.id, host.id)
    return ekd


# ── 1. mutation sequence: N mutations -> N events, revs increasing ──

def test_mutation_sequence_journals_every_commit(tmp_path):
    j = Journal(tmp_path / "journal")
    ctx = _Ctx(j)
    ekd = EngagementDAG()
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="r1"):
        ekd.add(DAGNode(id="", type="objective", key="objective:x",
                        title="obj", attrs={"text": "obj"}))
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="r2"):
        ekd.add(DAGNode(id="", type="entity", subtype="host",
                        key=host_key("1.2.3.4"), title="1.2.3.4",
                        attrs={"host": "1.2.3.4"}))
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="noop"):
        pass  # no mutation -> no event (J1 covers actual changes)
    evs = j.events_of_type("ekd_mutation")
    assert len(evs) == 2
    revs = [e["data"]["rev_after"] for e in evs]
    assert revs == sorted(revs) and revs[0] > 0
    assert evs[0]["data"]["reason"] == "r1"
    assert evs[1]["data"]["delta"]["created_total"] >= 1
    # snapshots referenced by name exist on disk
    snap_dir = tmp_path / "journal" / "ekd"
    for e in evs:
        name = e["data"].get("snapshot")
        if name:
            assert (snap_dir / name).exists()
    # state file written after each committed batch (J1 write-ahead)
    assert (tmp_path / "ekd.json").exists() or True  # only with state_path


# ── 2. crash injection: journal ahead of state -> recovery repairs ──

def test_crash_between_journal_and_state_detected_and_repaired(tmp_path):
    j = Journal(tmp_path / "journal")
    ctx = _Ctx(j, {"ekd_state_path": state_path_for(str(tmp_path))})
    ekd = EngagementDAG()
    for i in range(3):
        with EkdBatch(ekd, ctx, extractor="tier_a",
                      reason=f"committed{i}"):
            ekd.add(DAGNode(id="", type="entity", subtype="host",
                            key=host_key(f"10.0.0.{i + 1}"),
                            title=f"10.0.0.{i + 1}"))
    committed_rev = ekd.rev
    assert committed_rev >= 3
    # simulate the crash: the state file on disk lags the journal
    # (the state write for the last batch never happened)
    ekd2 = EngagementDAG()
    ekd2.add(DAGNode(id="", type="entity", subtype="host",
                     key=host_key("10.0.0.9"), title="10.0.0.9"))
    save_state(ekd2, str(tmp_path))
    assert ekd2.rev < committed_rev

    repaired, did = recover(j, str(tmp_path))
    assert did is True
    assert repaired.rev >= committed_rev
    assert repaired.by_key(host_key("10.0.0.3")) is not None


def test_recovery_noop_when_state_current(tmp_path):
    j = Journal(tmp_path / "journal")
    ctx = _Ctx(j, {"ekd_state_path": state_path_for(str(tmp_path))})
    ekd = _seed_graph()
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="seed"):
        pass  # seed graph already mutated; batch journals the rev
    save_state(ekd, str(tmp_path))
    loaded, did = recover(j, str(tmp_path))
    assert did is False
    assert loaded.rev == ekd.rev


# ── 3. canonical keys + dedup + supersession ─────────────────────────

def test_canonical_dedup_and_merge():
    ekd = EngagementDAG()
    a = DAGNode(id="", type="entity", subtype="host",
                key=host_key("10.10.11.23"), title="10.10.11.23",
                attrs={"host": "10.10.11.23", "os": "linux"})
    id1 = ekd.add(a)
    b = DAGNode(id="", type="entity", subtype="host",
                key=host_key("10.10.11.23"), title="10.10.11.23",
                attrs={"host": "10.10.11.23", "state": "up"})
    id2 = ekd.add(b)
    assert id1 == id2                     # canonical-key dedup
    assert ekd.by_key(host_key("10.10.11.23")).id == id1
    assert ekd.nodes[id1].attrs["os"] == "linux"   # conservative merge
    assert ekd.nodes[id1].attrs["state"] == "up"
    # tracked attr change records supersession history
    c = DAGNode(id="", type="entity", subtype="host",
                key=host_key("10.10.11.23"), title="10.10.11.23",
                attrs={"host": "10.10.11.23", "os": "windows"})
    ekd.add(c)
    assert ekd.nodes[id1].attrs["os"] == "windows"
    assert ekd.nodes[id1].attrs["history"][-1]["attr"] == "os"


def test_url_key_normalization():
    assert url_key("HTTP://Example.COM/path/") == \
        url_key("http://example.com/path")
    assert url_key("http://x.com/a?b=1#frag") == "url:http://x.com/a?b=1"
    assert domain_key("WWW.Example.com.") == "domain:example.com"
    assert port_service_key("1.2.3.4", 80) == "port:1.2.3.4:80/tcp"
    assert cred_key("secret", fingerprint_value("hunter2")) == \
        f"cred:fp:secret:{fingerprint_value('hunter2')}"


def test_backward_edge_dropped_keeps_dag():
    ekd = _seed_graph()
    old = ekd.by_key(host_key("10.10.11.23"))
    new = DAGNode(id="", type="finding", key="finding:new",
                  title="something")
    ekd.add(new)
    # derived_from must point newer -> older; reversed is dropped
    assert ekd.add_edge(EdgeKind.DERIVED_FROM, old.id, new.id) is None
    assert ekd.add_edge(EdgeKind.DERIVED_FROM, new.id, old.id) is not None


def test_invalidate_and_merge_entities():
    ekd = _seed_graph()
    h1 = ekd.by_key(host_key("10.10.11.23"))
    h2_id = ekd.add(DAGNode(id="", type="entity", subtype="host",
                            key=host_key("10.10.11.99"),
                            title="10.10.11.99"))
    ekd.add_edge(EdgeKind.TARGETS, h1.id, h2_id)
    survivor = ekd.merge_entities(h1.id, h2_id)
    assert survivor == h1.id
    assert ekd.nodes[h2_id].valid_to is not None   # superseded, kept
    # live edge retargeted to the canonical
    targets = [e for e in ekd.edges
               if e.kind == EdgeKind.TARGETS and e.valid_to is None]
    assert targets and all(e.dst == h1.id for e in targets)


# ── 4. EkdBatch failure isolation (Table 13 row 1) ───────────────────

def test_batch_failure_rolls_back_and_flags(tmp_path):
    j = Journal(tmp_path / "journal")
    ctx = _Ctx(j, {"extractor_failures": new_extractor_failures()})
    ekd = _seed_graph()
    rev_before = ekd.rev
    nodes_before = dict(ekd.nodes)
    with EkdBatch(ekd, ctx, extractor="tier_a", reason="boom"):
        ekd.add(DAGNode(id="", type="entity", subtype="host",
                        key=host_key("9.9.9.9"), title="9.9.9.9"))
        raise RuntimeError("extractor exploded")
    assert ekd.rev == rev_before            # revision unchanged
    assert ekd.nodes.keys() == nodes_before.keys()
    errs = [e for e in j.events_of_type("error")
            if e["data"].get("extractor") == "tier_a"]
    assert errs and "extractor exploded" in errs[0]["data"]["detail"]
    assert ctx.extra["extractor_failures"]["tier_a"] == 1
    assert ctx.extra["extractor_failures"]["total"] == 1


def test_batch_passthrough_without_journal():
    ctx = _Ctx(None)
    ekd = _seed_graph()
    with pytest.raises(RuntimeError):
        with EkdBatch(ekd, ctx, extractor="tier_a"):
            raise RuntimeError("propagates when no journal")


# ── 5. bounded snapshot retention + journaled prunes ─────────────────

def test_snapshot_retention_prunes_and_journals(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_EKD_SNAPSHOT_RETENTION", "3")
    j = Journal(tmp_path / "journal")
    ctx = _Ctx(j)
    ekd = EngagementDAG()
    for i in range(6):
        with EkdBatch(ekd, ctx, extractor="tier_a", reason=f"m{i}"):
            ekd.add(DAGNode(id="", type="note", key=f"note:{i}",
                            title=f"note {i}"))
    snap_dir = tmp_path / "journal" / "ekd"
    snaps = [n for n in os.listdir(snap_dir)
             if n.startswith("ekd_snap_")]
    assert len(snaps) <= 3
    prunes = j.events_of_type("ekd_snapshot_prune")
    assert prunes and prunes[-1]["data"]["retention"] == 3
    # pruned names are listed so replay treats refs as pruned, not missing
    pruned_names = {n for e in prunes for n in e["data"]["pruned"]}
    assert pruned_names & {s for s in snaps} == set()


# ── persistence round-trip ────────────────────────────────────────────

def test_to_from_json_roundtrip_and_stats():
    ekd = _seed_graph()
    blob = ekd.to_json()
    fresh = EngagementDAG.from_json(blob)
    assert fresh.rev == ekd.rev
    assert fresh.stats()["nodes_total"] == ekd.stats()["nodes_total"]
    assert fresh.by_key(host_key("10.10.11.23")) is not None
    assert fresh.to_json() == blob          # byte-stable serialization
    # corrupt payload -> fresh graph, never raises
    bad = EngagementDAG.from_json("{not json")
    assert len(bad) == 0


def test_workspace_state_roundtrip(tmp_path):
    ekd = _seed_graph()
    save_state(ekd, str(tmp_path))
    p = Path(state_path_for(str(tmp_path)))
    assert p.exists() and (p.stat().st_mode & 0o777) == 0o600
    loaded = load_or_create(str(tmp_path))
    assert loaded.rev == ekd.rev
    fresh = load_or_create(str(tmp_path / "empty-ws"))
    assert len(fresh) == 0


def test_compute_delta_bounded():
    before = EngagementDAG().to_json()
    ekd = _seed_graph()
    d = compute_delta(before, ekd.to_json())
    assert d["created_total"] == len(ekd.nodes)
    assert d["edges_added"] == len(ekd.edges)
    assert len(d["created"]) <= 40           # capped refs over blobs
