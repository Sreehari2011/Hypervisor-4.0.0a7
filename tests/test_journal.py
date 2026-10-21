"""Acceptance tests for the journal port (PORT-05).

Mirrors the card's ten acceptance tests. Frozen vectors pin the
message_sig formula — the one surface where accidental drift breaks
every journal ever written.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from hypervisor.persist.journal import (
    EVENT_TYPES, MAX_DATA_CHARS, SCHEMA_VERSION, V2_EVENT_TYPES,
    Journal, iter_journal_events, message_sig, sig_sha,
)


class _Msg:
    """Minimal message shape (same duck-typing surface the 3.x journal
    consumed: .type, .tool_call_id, .content)."""

    def __init__(self, type_="ai", content="hello", tool_call_id=""):
        self.type = type_
        self.content = content
        self.tool_call_id = tool_call_id


# ── 7. frozen formula vectors ──────────────────────────────────────

def test_message_sig_frozen_vector():
    m = _Msg("ai", "hello world", "call_1")
    sig = message_sig(m)
    assert sig == "ai|call_1|hello world"
    # sha16 frozen vector — do not update when refactoring anything else
    assert sig_sha(m) == hashlib.sha256(
        b"ai|call_1|hello world").hexdigest()[:16]
    # content clamp at 4000, verbatim from 3.7.3
    big = _Msg("tool", "x" * 9000, "tc")
    assert len(message_sig(big)) == 4 + 1 + 2 + 1 + 4000
    # non-str content coerces
    assert message_sig(_Msg("tool", 123)).startswith("tool||123")


# ── 1/2. append + integrity + unknown types ────────────────────────

def test_seq_integrity_and_unknown_type(tmp_path):
    j = Journal(tmp_path)
    assert j.append("boot", {"mode": "scoped-full-auto"})["seq"] == 1
    assert j.append("objective", {"text": "assess x"})["seq"] == 2
    assert j.append("no_such_type", {}) is None
    ev = j.append("future_thing", {}, force=True)
    assert ev is not None and ev["type"] == "future_thing"
    r = j.verify_integrity()
    assert r["ok"] and r["count"] == 3 and not r["gaps"]


def test_schema_v2_and_event_vocabulary():
    assert SCHEMA_VERSION == 2
    for t in ("loop_transition", "permission_decision", "turn_watchdog"):
        assert t in EVENT_TYPES and t in V2_EVENT_TYPES
    # v1 vocabulary fully carried
    for t in ("boot", "objective", "ekd_mutation", "compaction",
              "brief_render", "message", "compaction_trim",
              "compaction_breaker", "side_query", "subagent_spawn",
              "subagent_report", "llm_prompt", "llm_call", "llm_retry",
              "llm_abandon", "llm_breaker", "scope_mode"):
        assert t in EVENT_TYPES


# ── 3. J4: write failure queues, never raises ─────────────────────

def test_j4_write_failure_queues_and_recovers(tmp_path, monkeypatch):
    j = Journal(tmp_path)
    original = Journal._write
    state = {"broken": True}

    def flaky(self, event):
        if state["broken"]:
            raise OSError("disk gone")
        original(self, event)

    monkeypatch.setattr(Journal, "_write", flaky)
    ev = j.append("boot", {"a": 1})
    assert ev is not None                 # append still returns the event
    h = j.health()
    assert h["degraded"] and h["queued"] == 1 and h["write_failures"] == 1
    state["broken"] = False
    assert j.flush_retry() == 0           # recovered, nothing queued
    monkeypatch.setattr(Journal, "_write", original)
    r = j.verify_integrity()
    assert r["ok"] and r["count"] == 1    # the queued event reached disk


def test_j4_nonserializable_clamps_instead_of_raising(tmp_path):
    j = Journal(tmp_path)
    ev = j.append("boot", {"bad": {"set"}})   # set() is not JSON-serializable
    assert ev is not None
    r = j.verify_integrity()
    assert r["ok"]


# ── 4/5. B1 resume continuation + M5 torn tail ─────────────────────

def test_b1_resume_continues_seq_turn_rev(tmp_path):
    j1 = Journal(tmp_path)
    j1.append("boot", {})
    j1.set_turn(3)
    j1.append("objective", {"text": "x"}, rev=7)
    assert j1.seq == 2
    j2 = Journal(tmp_path, turn=0, ekd_rev=0)      # fresh instance, same file
    assert j2.seq == 2
    assert j2.next_turn() == 4                      # continued, not restarted
    assert j2.rev == 7
    ev = j2.append("message", {"role": "ai"})
    assert ev["seq"] == 3 and ev["rev"] == 7
    assert j2.verify_integrity()["ok"]              # seam is clean


def test_m5_torn_tail_counted(tmp_path):
    j = Journal(tmp_path)
    j.append("boot", {})
    j.append("objective", {"text": "x"})
    with j.file.open("a", encoding="utf-8") as f:
        f.write('{"v": 2, "seq": 3, "ts": 1.0, "type": "me')  # torn write
    j2 = Journal(tmp_path)
    assert j2.health()["torn_tail_lines"] == 1
    assert j2.seq == 2                              # last parseable wins
    j2.append("message", {})
    assert j2.verify_integrity()["ok"]


# ── 6. sidecars ────────────────────────────────────────────────────

def test_message_sig_sidecar_0600(tmp_path):
    j = Journal(tmp_path)
    big = _Msg("tool", "y" * 5000, "tc9")
    ev = j.record_message(big, source="unit")
    assert "sig" not in ev["data"] and ev["data"]["sig_head"]
    side = tmp_path / "messages" / f"sig_{ev['data']['sig_sha']}.txt"
    assert side.exists()
    assert (stat.S_IMODE(side.stat().st_mode) & 0o777) == 0o600
    small = _Msg("ai", "ok")
    ev2 = j.record_message(small)
    assert ev2["data"]["sig"] == "ai||ok"           # inline when it fits


def test_compaction_residual_sidecar(tmp_path):
    j = Journal(tmp_path)
    ev = j.record_compaction("S" * 6000, messages_dropped=4,
                             summary_hash="ab" * 8, direction="base",
                             tier=3, dropped_sig_shas=["s1", "s2", "s3", "s4"])
    d = ev["data"]
    # ref is filename-only (3.7.3 frozen semantics); dir is the convention
    assert d["summary_ref"] == "summary_" + "ab" * 8 + ".md"
    assert (tmp_path / "compaction" / d["summary_ref"]).exists()
    assert d["drop_complete"] is True
    assert d["direction"] == "base" and d["tier"] == 3


def test_objective_sidecar_for_long_text(tmp_path):
    j = Journal(tmp_path)
    long_text = "z" * (MAX_DATA_CHARS + 500)
    ev = j.record_objective(long_text)
    assert ev["data"]["text_ref"].startswith("objective_")
    assert (tmp_path / "objective" / ev["data"]["text_ref"]).exists()
    short = j.record_objective("quick one")
    assert "text_ref" not in short["data"]


def test_llm_prompt_sidecar_and_shape(tmp_path):
    j = Journal(tmp_path)
    msgs = [_Msg("user", "find issues"), _Msg("ai", "on it")]
    ev = j.record_llm_prompt("SYSTEM TEXT", msgs, node="loop", model="cisai")
    d = ev["data"]
    assert d["system_chars"] == 11 and d["n_messages"] == 2
    assert d["est_tokens"] == (11 + 10 + 5) // 4
    ref = tmp_path / d["prompt_ref"]
    assert ref.exists() and "=== SYSTEM (11 chars) ===" in ref.read_text()


def test_brief_render_sidecar(tmp_path):
    j = Journal(tmp_path)
    ev = j.record_brief_render("BRIEF BODY", budget=2000, ekd_rev=4,
                               render_hash="ff" * 8)
    assert (tmp_path / "briefs" / ("brief_" + "ff" * 8 + ".md")).exists()
    assert ev["data"]["budget"] == 2000 and ev["rev"] == 4


# ── 8. v2 helper events ────────────────────────────────────────────

def test_v2_event_helpers_roundtrip(tmp_path):
    j = Journal(tmp_path)
    j.record_loop_transition("autocompact", frm="context_full",
                             to="folding", trigger="13k_buffer", turn=9)
    j.record_permission_decision("nmap_scan", allowed=True,
                                 rule="scope.targets.cidr:10.0.0.0/24",
                                 args_digest="ab" * 8,
                                 scope_ref="sha:cd" * 4)
    j.record_permission_decision("shell", allowed=False,
                                 rule="default-deny", reason="out of scope")
    j.record_turn_watchdog(turn=12, bound_s=300.0, elapsed_s=301.4,
                           action="tripped")
    lts = j.events_of_type("loop_transition")
    perms = j.events_of_type("permission_decision")
    wd = j.events_of_type("turn_watchdog")
    assert lts[0]["data"]["transition"] == "autocompact"
    assert perms[0]["data"]["allowed"] is True and perms[0]["data"]["rule"]
    assert perms[1]["data"]["allowed"] is False
    assert wd[0]["data"]["action"] == "tripped"
    assert j.verify_integrity()["ok"]


# ── 9. clamp ───────────────────────────────────────────────────────

def test_clamp_data_bounds():
    j = Journal("/tmp/never-created-dir-x")  # no writes happen below
    ev = j.append("boot", {"note": "n" * 10000}, force=True) if False else None
    # direct unit check instead
    from hypervisor.persist.journal import _clamp_data
    out = _clamp_data({"note": "n" * 10000, "ok": "short"})
    assert len(out["note"]) < len("n" * 10000)
    assert out["note"].endswith("...[10000 chars]")
    assert out["ok"] == "short"


# ── 10. standalone reader accepts v1 shape ─────────────────────────

def test_iter_journal_events_reads_v1_lines(tmp_path):
    p = tmp_path / "legacy.jsonl"
    lines = [
        {"v": 1, "seq": 1, "ts": 1.0, "type": "boot", "turn": 0,
         "actor": None, "rev": 0, "data": {}},
        {"v": 1, "seq": 2, "ts": 2.0, "type": "objective", "turn": 0,
         "actor": "operator", "rev": 0, "data": {"text": "legacy"}},
    ]
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    evs = list(iter_journal_events(p))
    assert [e["seq"] for e in evs] == [1, 2]
    assert evs[1]["data"]["text"] == "legacy"
