"""P4 acceptance — the SLO audit (hypervisor/debug/slo.py) + the
cutover doctor (hypervisor/doctor.py).

The audit is a PURE JOURNAL PASS: quantiles, verdicts, and the
overall gate from the same ground truth replay verifies. Acceptance:
  * profile reconstruction from a scripted journal (latencies, tools,
    permissions, watchdog, stop-hook runs);
  * quantile math (nearest-rank);
  * verdict computation + env-tunable bounds;
  * no-data planes never fail the overall;
  * the goldens audit PASS (frozen fixtures stay healthy);
  * the doctor renders and exits sanely.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from hypervisor.debug.slo import (_quantile, _load_events,  # noqa: E402
                                  slo_audit)
from hypervisor.persist.journal import Journal  # noqa: E402


def _seq_events():
    """A synthetic engagement journal: 3 turns, 2 model calls (1
    error), 3 tool results, 1 permission allow, 1 stop-hook block,
    1 fold, 1 side query."""
    return [
        {"v": 2, "seq": 1, "ts": 100.0, "type": "boot",
         "turn": None, "actor": "cli", "rev": 0, "data": {}},
        {"v": 2, "seq": 2, "ts": 100.1, "type": "loop_transition",
         "turn": 1, "actor": "loop", "rev": 0,
         "data": {"transition": "init"}},
        {"v": 2, "seq": 3, "ts": 100.2, "type": "llm_call",
         "turn": 1, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 0}},
        {"v": 2, "seq": 4, "ts": 101.2, "type": "llm_call_end",
         "turn": 1, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 0, "outcome": "ok"}},
        {"v": 2, "seq": 5, "ts": 101.3, "type": "tool_result",
         "turn": 1, "actor": "dispatcher", "rev": 0,
         "data": {"tool": "run_command", "is_error": False,
                  "elapsed_ms": 250.0}},
        {"v": 2, "seq": 6, "ts": 101.4, "type": "permission_decision",
         "turn": 1, "actor": "gate", "rev": 0,
         "data": {"allowed": True}},
        {"v": 2, "seq": 7, "ts": 102.0, "type": "loop_transition",
         "turn": 2, "actor": "loop", "rev": 0,
         "data": {"transition": "next_turn"}},
        {"v": 2, "seq": 8, "ts": 102.1, "type": "llm_call",
         "turn": 2, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 0}},
        {"v": 2, "seq": 9, "ts": 102.9, "type": "llm_call_end",
         "turn": 2, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 0,
                  "outcome": "timeout"}},
        {"v": 2, "seq": 10, "ts": 103.0, "type": "llm_retry",
         "turn": 2, "actor": "guard", "rev": 0, "data": {}},
        {"v": 2, "seq": 11, "ts": 103.1, "type": "llm_call",
         "turn": 2, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 1}},
        {"v": 2, "seq": 12, "ts": 104.0, "type": "llm_call_end",
         "turn": 2, "actor": "guard", "rev": 0,
         "data": {"purpose": "main", "attempt": 1, "outcome": "ok"}},
        {"v": 2, "seq": 13, "ts": 104.1, "type": "tool_result",
         "turn": 2, "actor": "dispatcher", "rev": 0,
         "data": {"tool": "network_scan_nmap", "is_error": True,
                  "elapsed_ms": 5000.0}},
        {"v": 2, "seq": 14, "ts": 104.2, "type": "stop_hook",
         "turn": 2, "actor": "hooks", "rev": 0,
         "data": {"decision": "block", "duration_ms": 120.0}},
        {"v": 2, "seq": 15, "ts": 104.5, "type": "compaction",
         "turn": 2, "actor": "engine", "rev": 0,
         "data": {"messages_dropped": 2}},
        {"v": 2, "seq": 16, "ts": 104.6, "type": "side_query",
         "turn": 2, "actor": "l3", "rev": 0, "data": {"skipped": False}},
        {"v": 2, "seq": 17, "ts": 105.0, "type": "loop_transition",
         "turn": 3, "actor": "loop", "rev": 0,
         "data": {"transition": "end_turn"}},
        {"v": 2, "seq": 18, "ts": 105.1, "type": "turn_end",
         "turn": 3, "actor": "loop", "rev": 0,
         "data": {"prompt_tokens": 1200, "completion_tokens": 340}},
    ]


def test_quantile_nearest_rank():
    assert _quantile([], 0.95) is None
    assert _quantile([5.0], 0.95) == 5.0
    vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert _quantile(vals, 0.50) == 5.0     # idx round(0.5*9)=4
    assert _quantile(vals, 0.95) == 10.0
    assert _quantile(vals, 0.0) == 1.0


def test_profile_reconstruction():
    rep = slo_audit(_seq_events())
    p = rep["profile"]
    assert p["turns"] == 3
    # turn 1: 100.1..101.4; turn 2: 102.0..104.6; turn 3: 105.0..105.0
    lat = p["turn_latency_ms"]
    assert lat["max"] == pytest.approx(2600.0, rel=0.01)
    m = p["model_calls"]
    assert m["count"] == 3          # 1 + the timeout + its retry
    assert m["ok"] == 2 and m["errors"] == 1
    assert m["retries"] == 1
    assert m["max_ms"] == pytest.approx(1000.0, rel=0.01)
    t = p["tools"]
    assert t["calls"] == 2 and t["errors"] == 1
    assert t["per_tool"]["run_command"]["calls"] == 1
    assert t["per_tool"]["network_scan_nmap"]["calls"] == 1
    assert p["permissions"] == {"allows": 1, "denies": 0}
    assert p["stop_hook"] == {"runs": 1, "blocks": 1,
                              "p95_ms": 120.0}
    assert p["memory_plane"]["folds"] == 1
    assert p["memory_plane"]["side_queries"] == 1
    assert p["tokens"] == {"prompt": 1200, "completion": 340}
    assert p["watchdog_events"] == 0


def test_verdicts_computed():
    rep = slo_audit(_seq_events())
    v = {x["slo"]: x for x in rep["slo_verdicts"]}
    assert v["watchdog_trips_max"]["verdict"] == "pass"
    assert v["guard_abandons_max"]["verdict"] == "pass"
    # model error rate 1/2 = 0.5 > 0.25 default bound -> fail
    assert v["llm_error_rate_max"]["verdict"] == "fail"
    assert rep["overall"] == "fail"


def test_env_tunable_bounds(monkeypatch):
    monkeypatch.setenv("AEGIS_SLO_LLM_ERROR_RATE_MAX", "0.6")
    rep = slo_audit(_seq_events())
    v = {x["slo"]: x for x in rep["slo_verdicts"]}
    assert v["llm_error_rate_max"]["verdict"] == "pass"
    assert rep["overall"] == "pass"


def test_no_data_planes_never_fail():
    rep = slo_audit([{"v": 2, "seq": 1, "ts": 1.0, "type": "boot",
                      "turn": None, "actor": None, "rev": 0,
                      "data": {}}])
    assert all(x["verdict"] in ("pass", "no-data")
               for x in rep["slo_verdicts"])
    assert rep["overall"] == "pass"


def test_goldens_audit_pass():
    base = HERE / "golden"
    for name in ("golden-fold", "golden-quiet"):
        events = _load_events(base / name)
        rep = slo_audit(events)
        assert rep["overall"] == "pass", (name, rep["slo_verdicts"])


def test_cli_render_and_exit_code(tmp_path, capsys):
    from hypervisor.debug.slo import main
    jf = tmp_path / "journal.jsonl"
    with open(jf, "w") as f:
        for e in _seq_events():
            f.write(json.dumps(e) + "\n")
    rc = main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "AEGIS SLO audit" in out
    assert "OVERALL: FAIL" in out          # the error-rate bound trips
    assert rc == 1
    rc = main([str(tmp_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["overall"] == "fail"
    assert rc == 1


# ─── the cutover doctor ─────────────────────────────────────────────────

def test_doctor_renders_and_exits(capsys, monkeypatch):
    monkeypatch.delenv("AEGIS_OPENAI_BASE_URL", raising=False)
    from hypervisor import doctor
    doctor.CHECKS.clear()
    rc = doctor.run_doctor()
    out = capsys.readouterr().out
    assert "AEGIS Hypervisor doctor" in out
    # without an endpoint configured the doctor still passes (the
    # endpoint is a soft check); blocking failures only for the hard
    # contract (imports, registry, declared deps + adapter transport)
    assert rc == 0
    assert "registry: operator attachments" in out
    assert "declared runtime deps" in out
    assert "[OK ] adapter transport: httpx" in out
