"""P1 acceptance tests — persist/sessions.py (0o600 JSONL, parentUuid
chains, sidechains, resume continuation, torn tails)."""
import json
import os
import stat
from pathlib import Path

from hypervisor.persist.sessions import SessionStore


def test_chain_and_permissions(tmp_path):
    s = SessionStore(tmp_path / "eng")
    r1 = s.record_user("scan 10.0.0.5")
    r2 = s.record_assistant({"role": "assistant", "content": [
        {"type": "text", "text": "on it"}]})
    r3 = s.record_tool_results([
        {"type": "tool_result", "tool_use_id": "c1",
         "content": "open"}])[0]
    r4 = s.record_meta("boot", {"model": "cisai-ultra"})

    assert r1["parentUuid"] is None
    assert r2["parentUuid"] == r1["uuid"]
    assert r3["parentUuid"] == r2["uuid"]
    assert r4["parentUuid"] == r3["uuid"]
    assert s.chain_head() == r4["uuid"]

    f = tmp_path / "eng" / f"{s.session_id}.jsonl"
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(f.parent).st_mode) == 0o700

    rep = s.verify_chain()
    assert rep["records"] == 4 and rep["orphans"] == []


def test_resume_continues_chain_and_seq(tmp_path):
    s = SessionStore(tmp_path / "eng")
    rs = [s.record_user(f"m{i}") for i in range(3)]
    s2 = SessionStore.resume(tmp_path / "eng", s.session_id)
    r5 = s2.record_user("continue")
    assert r5["parentUuid"] == rs[-1]["uuid"]
    assert r5["seq"] == 4
    allr = s2.read_all()
    assert [x["seq"] for x in allr] == [1, 2, 3, 4]
    assert s2.verify_chain()["orphans"] == []


def test_summary_boundary_preserves_logical_parent(tmp_path):
    s = SessionStore(tmp_path / "eng")
    r1 = s.record_user("one")
    r2 = s.record_user("two")
    head = s.chain_head()
    r6 = s.append_summary("folded turns 1-2",
                          logical_parent=r1["uuid"])
    # physical parent chains to the last record; logical parent keeps
    # the pre-fold head (the CC boundary rule)
    assert r6["parentUuid"] == head
    assert r6["logicalParentUuid"] == r1["uuid"]
    r7 = s.record_user("after fold")
    assert r7["parentUuid"] == r6["uuid"]
    assert s.verify_chain()["orphans"] == []


def test_sidechain_has_own_chain_and_meta_sidecar(tmp_path):
    s = SessionStore(tmp_path / "eng")
    s.record_user("parent objective")
    sc = s.spawn_sidechain(label="recon-expert")
    assert sc.sidechain and sc.session_id != s.session_id
    m1 = sc.record_user("enumerate 10.0.0.5")
    assert m1["parentUuid"] is None        # own chain
    meta = json.loads(
        (tmp_path / "eng" / f"{sc.session_id}.meta.json").read_text())
    assert meta["parent_session"] == s.session_id
    assert meta["label"] == "recon-expert"
    assert meta["parent_record"] == s.chain_head()
    sf = tmp_path / "eng" / f"{sc.session_id}.jsonl"
    assert stat.S_IMODE(os.stat(sf).st_mode) == 0o600


def test_torn_tail_is_resume_safe(tmp_path):
    s = SessionStore(tmp_path / "eng")
    rs = [s.record_user(f"m{i}") for i in range(2)]
    f = tmp_path / "eng" / f"{s.session_id}.jsonl"
    with open(f, "a") as fh:
        fh.write('{"uuid": "torn')       # crash mid-write
    s2 = SessionStore.resume(tmp_path / "eng", s.session_id)
    r = s2.record_user("after crash")
    assert r["parentUuid"] == rs[-1]["uuid"]
    assert r["seq"] == 3


def test_append_assigns_and_overrides(tmp_path):
    s = SessionStore(tmp_path / "eng")
    r = s.append({"type": "meta", "kind": "note", "data": {"x": 1}})
    assert r["uuid"] and r["sessionId"] == s.session_id
    assert r["ts"] and r["seq"] == 1
    # explicit uuid is honored; an ABSENT parentUuid chains to the head
    explicit = s.append({"type": "meta", "uuid": "fixed"})
    assert explicit["uuid"] == "fixed"
    assert explicit["parentUuid"] == r["uuid"]
    # an explicit parentUuid (e.g. summary boundaries) is preserved
    detached = s.append({"type": "meta", "uuid": "d",
                          "parentUuid": None})
    assert detached["parentUuid"] is None


def test_session_ids_are_unique(tmp_path):
    a = SessionStore(tmp_path / "eng")
    b = SessionStore(tmp_path / "eng")
    assert a.session_id != b.session_id
