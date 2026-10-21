"""P3 acceptance — PORT-06: replay and integrity passes.

Oracle anchor: src/replay.py (815 ln) — three passes + the 4.0
deltas (v1/v2 acceptance, v2 surfaces in the report, session-store
cross-check, crash-boundary repair).

Acceptance (the card):
  1. Oracle journals replay clean: the two captured golden
     trajectories run the full pass with zero false positives.
  2. Mutation testing: each corruption class (seq gap, lying sidecar
     sha, broken rev chain, missing window message) is detected and
     named.
  3. Crash-boundary: journal-ahead-of-store repairs to a consistent
     state.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.persist.replay import JournalReplay  # noqa: E402

GOLDEN = HERE / "golden"


@pytest.fixture(scope="module")
def fold_dir(tmp_path_factory):
    """A mutable copy of the golden-fold trajectory."""
    dst = tmp_path_factory.mktemp("fold") / "golden-fold"
    shutil.copytree(GOLDEN / "golden-fold", dst)
    return dst


@pytest.fixture(scope="module")
def quiet_dir(tmp_path_factory):
    dst = tmp_path_factory.mktemp("quiet") / "golden-quiet"
    shutil.copytree(GOLDEN / "golden-quiet", dst)
    return dst


def _events(d: Path):
    return [json.loads(l) for l in
            (d / "journal.jsonl").read_text().splitlines() if l.strip()]


def _write(d: Path, evs):
    (d / "journal.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in evs))


# ─── acceptance 1: golden trajectories replay clean ────────────────────

def test_golden_fold_replays_clean(fold_dir):
    r = JournalReplay(fold_dir)
    rep = r.full_report()
    assert rep["ok"], json.dumps(rep["revision_chain"]["issues"][:3]
                                 + rep["renders"]["issues"][:3])
    assert rep["integrity"]["events"] >= 40
    c = rep["revision_chain"]
    assert c["mutations"] >= 3 and c["compactions"] >= 2
    assert c["subagent_spawns"] == 0     # no spawns in this trajectory
    # briefs byte-verified: every render carrying the J2 triplet
    v = rep["renders"]
    assert v["verified"] == v["total_render_events"] >= 4
    assert v["skipped"] == 0
    # Zone W: the window hashes reconstruct (skip = the empty first
    # window, explicit)
    w = v["window_checks"]
    assert w["verified"] >= 3 and w["skipped"] == 1
    # v2 surfaces counted
    assert c["loop_transitions"] >= 5
    assert c["permission_allows"] >= 3
    assert c["permission_denies"] == 0


def test_golden_quiet_replays_clean(quiet_dir):
    r = JournalReplay(quiet_dir)
    rep = r.full_report()
    assert rep["ok"]
    assert rep["renders"]["verified"] == 2
    assert rep["revision_chain"]["compactions"] == 0


def test_v1_oracle_journal_shape_accepted(tmp_path):
    """A synthesized 3.7.3-era v1 journal (no v field v2, langchain
    sig shapes) replays without version complaints."""
    d = tmp_path / "v1"
    d.mkdir()
    evs = []
    for i, (t, data) in enumerate([
            ("boot", {"resumed": False}),
            ("objective", {"text": "own the box", "chars": 11}),
            ("message", {"role": "human", "chars": 11, "sig_sha": "a",
                         "sig": "human||own the box"}),
            ("message", {"role": "ai", "chars": 2, "sig_sha": "b",
                         "sig": "ai||ok"}),
            ("message", {"role": "tool", "tool_call_id": "t1",
                         "chars": 3, "sig_sha": "c",
                         "sig": "tool|t1|out"}),
            ("ekd_mutation", {"rev_before": 0, "rev_after": 1,
                              "extractor": "tier_a", "nodes": 1,
                              "edges": 0, "reason": "r"}),
    ], start=1):
        evs.append({"v": 1, "seq": i, "ts": 1.0 + i, "type": t,
                    "turn": 1, "actor": "t", "rev": None, "data": data})
    _write(d, evs)
    r = JournalReplay(d)
    rep = r.full_report()
    assert rep["integrity"]["ok"]
    assert rep["integrity"]["versions"] == [1]
    assert rep["revision_chain"]["ok"]
    # the tool-role sig groups with its ai parent (oracle grouping)
    from hypervisor.persist.replay import _sig_groups
    groups = _sig_groups(["human||own the box", "ai||ok", "tool|t1|out"])
    assert groups == [[0], [1, 2]]


# ─── acceptance 2: mutation testing — each class detected and named ───

def test_mutation_seq_gap_detected_and_named(fold_dir, tmp_path):
    d = tmp_path / "gap"
    shutil.copytree(fold_dir, d)
    evs = _events(d)
    assert len(evs) > 10
    del evs[10]                       # a gap in the middle
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    assert not rep["integrity"]["ok"]
    gaps = rep["integrity"]["gaps"]
    assert gaps and gaps[0]["expected"] != gaps[0]["got"]


def test_mutation_lying_sidecar_sha_detected_and_named(fold_dir, tmp_path):
    """The chain pass names a compaction residual sidecar whose bytes
    do not hash to the event's claim."""
    d = tmp_path / "sha"
    shutil.copytree(fold_dir, d)
    # find a compaction event with a summary_ref and corrupt the file
    evs = _events(d)
    comp = next(e for e in evs if e["type"] == "compaction"
                and e["data"].get("summary_ref"))
    ref = comp["data"]["summary_ref"]
    path = d / "compaction" / ref
    assert path.exists()
    text = path.read_text()
    path.write_text(text + "\nTAMPERED")
    rep = JournalReplay(d).full_report()
    issues = rep["revision_chain"]["issues"]
    assert any("residual sidecar" in i["issue"]
               and "sha mismatch" in i["issue"] for i in issues)


def test_mutation_broken_rev_chain_detected_and_named(fold_dir, tmp_path):
    d = tmp_path / "rev"
    shutil.copytree(fold_dir, d)
    evs = _events(d)
    muts = [i for i, e in enumerate(evs)
            if e["type"] == "ekd_mutation"]
    assert len(muts) >= 2
    evs[muts[1]]["data"]["rev_before"] = \
        evs[muts[1]]["data"]["rev_after"]     # lying rev_before
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    issues = rep["revision_chain"]["issues"]
    assert any("chain discontinuity" in i["issue"] for i in issues)


def test_mutation_missing_window_message_detected(fold_dir, tmp_path):
    """A message event silently removed: named either as the unmatched
    surgery claim (when a fold later references the removed sig) or as
    a window hash/member mismatch (when it was still in-window)."""
    d = tmp_path / "win"
    shutil.copytree(fold_dir, d)
    evs = _events(d)
    # drop one tool-result carrier message event (mid-channel)
    idx = next(i for i, e in enumerate(evs)
               if e["type"] == "message"
               and e["data"].get("source") == "tool_results")
    del evs[idx]
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    issues = rep["renders"]["issues"]
    assert issues, "missing window member went undetected"
    assert any("not in the channel" in i["issue"]
               or "window" in i["issue"] for i in issues)


def test_mutation_lying_expansion_sha_detected(tmp_path):
    d = tmp_path / "exp"
    d.mkdir()
    evs = [{"v": 2, "seq": 1, "ts": 1.0, "type": "side_query",
            "turn": 1, "actor": None, "rev": 0,
            "data": {"trigger": "revision bump", "ekd_rev": 3,
                     "candidates": 2, "selected": ["e1"],
                     "expansions": [
                         {"id": "e1", "sha": "0" * 16, "chars": 5,
                          "text": "real text"}]}}]
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    issues = rep["revision_chain"]["issues"]
    assert any("expansion sha mismatch" in i["issue"] for i in issues)


def test_mutation_unsanctioned_spawn_mode_detected(tmp_path):
    d = tmp_path / "mode"
    d.mkdir()
    evs = [{"v": 2, "seq": 1, "ts": 1.0, "type": "subagent_spawn",
            "turn": 1, "actor": None, "rev": 0,
            "data": {"mode": "inherit-everything", "phase": "recon",
                     "task": "t"}}]
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    issues = rep["revision_chain"]["issues"]
    assert any("unsanctioned context mode" in i["issue"]
               and "rule C5" in i["issue"] for i in issues)


# ─── acceptance 3: crash-boundary repair ───────────────────────────────

def test_crash_boundary_detected_and_repaired(fold_dir, tmp_path):
    """Journal ahead of store (the J1 crash window): detected, then
    repaired explicitly from the verifiable snapshot chain."""
    d = tmp_path / "crash"
    shutil.copytree(fold_dir, d)
    # the golden run saved ekd.json at the FINAL rev; roll it BACK to
    # simulate a crash between the last journal write and the state
    # write (delete the state file entirely = store at rev 0/absent)
    state = d / "ekd.json"
    assert state.exists()
    final_rev = json.loads(state.read_text())["rev"]
    state.unlink()

    r = JournalReplay(d)
    boundary = r.crash_boundary()
    assert not boundary["ok"]
    assert boundary["journal_rev"] == final_rev
    assert boundary["store_rev"] is None

    rep = r.repair()
    assert rep["ok"]
    assert rep["repaired_to_rev"] == final_rev
    assert any("re-materialized" in a for a in rep["actions"])
    # the state is back and consistent
    assert json.loads(state.read_text())["rev"] == final_rev
    # a second repair is a no-op that says so
    rep2 = r.repair()
    assert rep2["ok"]
    assert any("no repair needed" in a for a in rep2["actions"])


def test_repair_refuses_without_verifiable_snapshot(fold_dir, tmp_path):
    d = tmp_path / "nosnap"
    shutil.copytree(fold_dir, d)
    (d / "ekd.json").unlink(missing_ok=True)
    # corrupt EVERY snapshot so none verifies
    for f in (d / "ekd").glob("*.json"):
        f.write_text('{"rev": -1, "tampered": true}')
    r = JournalReplay(d)
    rep = r.repair()
    assert not rep["ok"]
    assert any("no verifiable snapshot" in a for a in rep["actions"])


# ─── session linkage (the 4.0 delta) ───────────────────────────────────

def test_session_linkage_reports_missing_sidechain(tmp_path):
    """A spawn event with no sidechain transcript in the store is an
    issue (explicit, never silent)."""
    d = tmp_path / "link"
    d.mkdir()
    (d / "sessions").mkdir()
    evs = [{"v": 2, "seq": 1, "ts": 1.0, "type": "subagent_spawn",
            "turn": 1, "actor": None, "rev": 0,
            "data": {"mode": "contract", "phase": "recon",
                     "task": "t"}}]
    _write(d, evs)
    rep = JournalReplay(d).full_report()
    s = rep["session_linkage"]
    assert s["store_present"] is True
    assert not s["ok"]
    assert any("no sidechain transcript" in i["issue"]
               for i in s["issues"])


def test_session_linkage_headless_degrades_to_skipped(fold_dir):
    rep = JournalReplay(fold_dir).full_report()
    s = rep["session_linkage"]
    # the golden capture has no sessions dir next to the journal
    assert s["store_present"] is False
    assert s["ok"]


def test_session_linkage_with_real_sidechain(tmp_path):
    """A spawn + a matching sidechain meta sidecar -> linked."""
    from hypervisor.persist.sessions import SessionStore
    d = tmp_path / "link2"
    (d / ".aegis" / "journal").mkdir(parents=True)
    store = SessionStore(d / ".aegis" / "sessions")
    store.record_user("run the lab")          # the parent transcript
    side = store.spawn_sidechain(label="agent:recon")
    side.record_user("map the segment")
    side.record_meta("note", {"agent_report": True})
    evs = [{"v": 2, "seq": 1, "ts": 1.0, "type": "subagent_spawn",
            "turn": 1, "actor": None, "rev": 0,
            "data": {"mode": "contract", "phase": "recon",
                     "task": "map the segment"}}]
    _write(d / ".aegis" / "journal", evs)
    rep = JournalReplay(d / ".aegis" / "journal").full_report()
    s = rep["session_linkage"]
    assert s["store_present"] is True
    assert s["sidechains_linked"] == 1
    assert s["ok"], s["issues"]


# ─── the CLI surface ────────────────────────────────────────────────────

def test_replay_cli_exit_codes(fold_dir, capsys):
    from hypervisor.persist.replay import main
    assert main([str(fold_dir)]) == 0
    out = capsys.readouterr().out
    assert "OVERALL" in out and "OK" in out


def test_torn_tail_tolerated(fold_dir, tmp_path):
    """A torn final line (crash mid-write) is skipped, not fatal —
    identical to Journal.events tolerance."""
    d = tmp_path / "torn"
    shutil.copytree(fold_dir, d)
    with (d / "journal.jsonl").open("a") as f:
        f.write('{"v": 2, "seq": 9999, "ts": 1.0, "type": "boo')
    rep = JournalReplay(d).full_report()
    assert rep["integrity"]["ok"]      # the torn line never parsed
