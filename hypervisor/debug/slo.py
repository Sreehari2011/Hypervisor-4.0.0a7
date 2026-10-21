"""hypervisor.debug.slo — the performance/SLO audit (P4, blueprint
Ch.14).

A PURE JOURNAL PASS: every latency, token count, tool duration and
control-plane decision the loop planes emit is already in the
engagement journal (PORT-05's v2 schema was designed for exactly
this). The audit therefore needs no live instrumentation — it
reconstructs the engagement's performance profile from the same
ground truth replay verifies, and stays honest for ANY journal,
including the frozen goldens.

SLO table (env-tunable via AEGIS_SLO_<NAME>, values in seconds /
counts / ratios; '' resets to default):

  turn_p95_s            wall-clock per loop turn (loop_transition
                        timestamps, turn-tagged)          default 120
  model_call_p95_s      llm_call -> llm_call_end pairing    default 90
  tool_dispatch_p95_s   tool_result.elapsed_ms distribution default 60
  watchdog_trips_max    turn_watchdog events                default 0
  guard_abandons_max    llm_abandon events                  default 0
  llm_error_rate_max    llm_call_end(ok)/total ratio        default 0.25
  stop_hook_p95_s       stop_hook duration_ms distribution  default 30

Output: per-plane quantiles, verdicts, and an overall SLO verdict.
python -m hypervisor.debug.slo <journal> [--json]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_SLOS = {
    "turn_p95_s": 120.0,
    "model_call_p95_s": 90.0,
    "tool_dispatch_p95_s": 60.0,
    "watchdog_trips_max": 0,
    "guard_abandons_max": 0,
    "llm_error_rate_max": 0.25,
    "stop_hook_p95_s": 30.0,
}


def _slo(name: str) -> float:
    raw = os.environ.get(f"AEGIS_SLO_{name.upper()}", "")
    if raw.strip():
        try:
            return float(raw)
        except ValueError:
            pass
    return float(DEFAULT_SLOS[name])


def _quantile(sorted_values: List[float], q: float) -> Optional[float]:
    """Nearest-rank quantile on a pre-sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    idx = min(len(sorted_values) - 1,
              max(0, int(round(q * (len(sorted_values) - 1)))))
    return sorted_values[idx]


def _fmt_ms(ms: Optional[float]) -> str:
    if ms is None:
        return "n/a"
    return f"{ms / 1000.0:.2f}s" if ms >= 1000 else f"{ms:.0f}ms"


# ─── the audit ──────────────────────────────────────────────────────────

def slo_audit(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the performance profile + SLO verdicts from one
    engagement journal's events (file order)."""
    turns: Dict[int, List[float]] = {}      # turn -> [t_init, t_end...]
    # W4 (a7): keyed (boot, turn) — turn numbers restart per boot; a
    # bare turn number merges turns across boots and the inter-boot
    # wall-clock gap surfaces as a phantom p95 (ENG-01: 7714s "turn"
    # spanning the 2.18h restart gap while every real metric passed).
    turn_bounds: Dict[Tuple[int, int], Tuple[float, float]] = {}
    boot_idx = 0
    boot_count = 0
    model_calls: List[float] = []           # ms
    model_errors = model_ok = 0
    llm_abandons = llm_retries = llm_breakers = 0
    tool_durations: Dict[str, List[float]] = {}
    tool_errors = tool_total = 0
    permission_allows = permission_denies = 0
    watchdog_events = 0
    stop_hook_runs: List[float] = []        # ms
    stop_hook_blocks = 0
    folds = trims = 0
    side_queries = side_query_skips = 0
    subagent_spawns = subagent_reports = 0
    prompt_tokens = completion_tokens = 0
    open_llm_calls: Dict[Any, float] = {}

    for e in events:
        t = e.get("type")
        d = e.get("data") or {}
        ts = float(e.get("ts") or 0.0)
        turn = e.get("turn")

        if t == "boot":
            if boot_count:
                boot_idx += 1
            boot_count += 1

        # per-turn wall-clock bounds come from EVERY turn-tagged event
        # (a quiet turn may emit only one loop_transition — the bounds
        # would collapse; llm/tool/hook events carry the turn too)
        if turn is not None:
            key = (boot_idx, int(turn))
            lo, hi = turn_bounds.get(key, (ts, ts))
            turn_bounds[key] = (min(lo, ts), max(hi, ts))

        if t == "loop_transition":
            name = str(d.get("name", d.get("to", "")))
            if name:
                pass                    # taxonomy surface (unused)
        elif t == "llm_call":
            # pair by (purpose, turn) — one in flight per purpose+turn
            key = (d.get("purpose"), turn, d.get("attempt", 0))
            open_llm_calls[key] = ts
        elif t == "llm_call_end":
            key = (d.get("purpose"), turn, d.get("attempt", 0))
            t0 = open_llm_calls.pop(key, None)
            if t0 is not None:
                model_calls.append(max(0.0, (ts - t0) * 1000))
            if str(d.get("outcome")) == "ok":
                model_ok += 1
            else:
                model_errors += 1
        elif t == "llm_abandon":
            llm_abandons += 1
        elif t == "llm_retry":
            llm_retries += 1
        elif t == "llm_breaker":
            llm_breakers += 1
        elif t == "tool_result":
            ms = float(d.get("elapsed_ms") or 0)
            tool = str(d.get("tool", "?"))
            tool_durations.setdefault(tool, []).append(ms)
            tool_total += 1
            if d.get("is_error"):
                tool_errors += 1
        elif t == "permission_decision":
            if d.get("allowed"):
                permission_allows += 1
            else:
                permission_denies += 1
        elif t == "turn_watchdog":
            watchdog_events += 1
        elif t == "stop_hook":
            stop_hook_runs.append(float(d.get("duration_ms") or 0))
            if d.get("decision") == "block":
                stop_hook_blocks += 1
        elif t == "compaction":
            folds += 1
        elif t == "compaction_trim":
            trims += 1
        elif t == "side_query":
            if d.get("skipped"):
                side_query_skips += 1
            else:
                side_queries += 1
        elif t == "subagent_spawn":
            subagent_spawns += 1
        elif t == "subagent_report":
            subagent_reports += 1
        elif t == "agent_message":
            pass
        elif t in ("brief_render",):
            pass

    # token accounting: the loop's turn_end / completed stats carry
    # cumulative counters in the oracle's shape; 4.0 journals them on
    # turn_end events (data.prompt_tokens / completion_tokens)
    for e in events:
        if e.get("type") == "turn_end":
            d = e.get("data") or {}
            pt = d.get("prompt_tokens")
            ct = d.get("completion_tokens")
            if pt is not None:
                prompt_tokens = max(prompt_tokens, int(pt))
            if ct is not None:
                completion_tokens = max(completion_tokens, int(ct))

    turn_latencies: List[float] = []
    for turn, (lo, hi) in sorted(turn_bounds.items()):
        if hi > lo:
            turn_latencies.append((hi - lo) * 1000)
    turn_latencies.sort()

    all_tools = sorted(v for vals in tool_durations.values()
                       for v in vals)
    model_calls_sorted = sorted(model_calls)
    stop_sorted = sorted(stop_hook_runs)

    profile = {
        "turns": len(turn_bounds),
        "boots": boot_count,
        "turn_latency_ms": {
            "p50": _quantile(turn_latencies, 0.50),
            "p95": _quantile(turn_latencies, 0.95),
            "max": turn_latencies[-1] if turn_latencies else None,
        },
        "model_calls": {
            "count": len(model_calls),
            "ok": model_ok, "errors": model_errors,
            "retries": llm_retries, "abandons": llm_abandons,
            "breakers": llm_breakers,
            "p50_ms": _quantile(model_calls_sorted, 0.50),
            "p95_ms": _quantile(model_calls_sorted, 0.95),
            "max_ms": model_calls_sorted[-1] if model_calls_sorted else None,
        },
        "tools": {
            "calls": tool_total, "errors": tool_errors,
            "p95_ms": _quantile(all_tools, 0.95),
            "max_ms": all_tools[-1] if all_tools else None,
            "per_tool": {
                tool: {"calls": len(vals),
                       "p95_ms": _quantile(sorted(vals), 0.95),
                       "max_ms": max(vals)}
                for tool, vals in sorted(tool_durations.items())},
        },
        "permissions": {"allows": permission_allows,
                        "denies": permission_denies},
        "watchdog_events": watchdog_events,
        "stop_hook": {"runs": len(stop_hook_runs),
                      "blocks": stop_hook_blocks,
                      "p95_ms": _quantile(stop_sorted, 0.95)},
        "memory_plane": {"folds": folds, "trims": trims,
                         "side_queries": side_queries,
                         "side_query_skips": side_query_skips},
        "subagents": {"spawns": subagent_spawns,
                      "reports": subagent_reports},
        "tokens": {"prompt": prompt_tokens,
                   "completion": completion_tokens},
    }

    # ── verdicts ────────────────────────────────────────────────────
    verdicts: List[Dict[str, Any]] = []

    def _v(name: str, value: Optional[float], bound: float,
           worse: str = "higher") -> None:
        if value is None:
            verdicts.append({"slo": name, "value": None, "bound": bound,
                             "verdict": "no-data"})
            return
        ok = (value <= bound) if worse == "higher" else (value >= bound)
        verdicts.append({"slo": name, "value": round(value, 3),
                         "bound": bound,
                         "verdict": "pass" if ok else "fail"})

    _v("turn_p95_s",
       (profile["turn_latency_ms"]["p95"] or 0) / 1000.0
       if profile["turn_latency_ms"]["p95"] is not None else None,
       _slo("turn_p95_s"))
    _v("model_call_p95_s",
       (profile["model_calls"]["p95_ms"] or 0) / 1000.0
       if profile["model_calls"]["p95_ms"] is not None else None,
       _slo("model_call_p95_s"))
    _v("tool_dispatch_p95_s",
       (profile["tools"]["p95_ms"] or 0) / 1000.0
       if profile["tools"]["p95_ms"] is not None else None,
       _slo("tool_dispatch_p95_s"))
    _v("stop_hook_p95_s",
       (profile["stop_hook"]["p95_ms"] or 0) / 1000.0
       if profile["stop_hook"]["p95_ms"] is not None else None,
       _slo("stop_hook_p95_s"))
    _v("watchdog_trips_max", float(watchdog_events),
       _slo("watchdog_trips_max"))
    _v("guard_abandons_max", float(llm_abandons),
       _slo("guard_abandons_max"))
    total_llm = model_ok + model_errors
    err_rate = (model_errors / total_llm) if total_llm else None
    if err_rate is None:
        verdicts.append({"slo": "llm_error_rate_max", "value": None,
                         "bound": _slo("llm_error_rate_max"),
                         "verdict": "no-data"})
    else:
        _v("llm_error_rate_max", err_rate, _slo("llm_error_rate_max"))

    overall = "pass" if all(
        v["verdict"] in ("pass", "no-data") for v in verdicts) else "fail"
    return {"profile": profile, "slo_verdicts": verdicts,
            "overall": overall}


# ─── CLI ────────────────────────────────────────────────────────────────

def _load_events(journal: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    target = journal
    if target.is_dir():
        target = target / "journal.jsonl"
    with open(target, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _render(report: Dict[str, Any]) -> str:
    p = report["profile"]
    m = p["model_calls"]
    t = p["tools"]
    lines = [
        "AEGIS SLO audit",
        f"  turns            : {p['turns']}"
        + (f" across {p['boots']} boots"
           if p.get("boots", 1) > 1 else ""),
        f"  turn latency     : p50 {_fmt_ms(p['turn_latency_ms']['p50'])}"
        f" / p95 {_fmt_ms(p['turn_latency_ms']['p95'])}"
        f" / max {_fmt_ms(p['turn_latency_ms']['max'])}",
        f"  model calls      : {m['count']} "
        f"(ok {m['ok']} / err {m['errors']}, retries {m['retries']}, "
        f"abandons {m['abandons']}, breakers {m['breakers']})",
        f"  model latency    : p50 {_fmt_ms(m['p50_ms'])}"
        f" / p95 {_fmt_ms(m['p95_ms'])}"
        f" / max {_fmt_ms(m['max_ms'])}",
        f"  tool calls       : {t['calls']} "
        f"(errors {t['errors']}) p95 {_fmt_ms(t['p95_ms'])}"
        f" max {_fmt_ms(t['max_ms'])}",
        f"  permissions      : {p['permissions']['allows']} allows / "
        f"{p['permissions']['denies']} denies",
        f"  watchdog         : {p['watchdog_events']} trips",
        f"  stop-hook        : {p['stop_hook']['runs']} runs "
        f"({p['stop_hook']['blocks']} blocks) "
        f"p95 {_fmt_ms(p['stop_hook']['p95_ms'])}",
        f"  memory plane     : {p['memory_plane']['folds']} folds, "
        f"{p['memory_plane']['trims']} trims, "
        f"{p['memory_plane']['side_queries']} side queries "
        f"({p['memory_plane']['side_query_skips']} skipped)",
        f"  subagents        : {p['subagents']['spawns']} spawns / "
        f"{p['subagents']['reports']} reports",
        f"  tokens           : {p['tokens']['prompt']} prompt / "
        f"{p['tokens']['completion']} completion",
        "",
        "SLO verdicts:",
    ]
    for v in report["slo_verdicts"]:
        val = "n/a" if v["value"] is None else v["value"]
        lines.append(f"  [{'PASS' if v['verdict'] == 'pass' else 'FAIL' if v['verdict'] == 'fail' else '----'}] "
                     f"{v['slo']}: {val} (bound {v['bound']})")
    lines.append(f"OVERALL: {report['overall'].upper()}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if not argv:
        print("usage: python -m hypervisor.debug.slo <journal-dir-or-file>"
              " [--json]", file=sys.stderr)
        return 2
    journal = Path(argv[0])
    if not journal.exists():
        print(f"journal not found: {journal}", file=sys.stderr)
        return 2
    report = slo_audit(_load_events(journal))
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render(report))
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
