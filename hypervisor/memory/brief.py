"""hypervisor.memory.brief — the EKD brief renderer (P2).

PORT-11: the budgeted engagement brief, carried from 3.7.3's
engagement_dag.render_brief_l2 (the Table 8 contract) and
render_node_detail. The semantic STORE it used to live beside is
DELETE-04 — the EKD supersedes it; the RENDERER ports and now renders
FROM the EKD directly.

Invariants (3.7 spec Part 5, carried verbatim):
  I1 determinism      same (graph revision, budget, pinned now, inputs)
                      renders byte-identical output
  I2 completeness     truncation drops whole entries and always leaves
                      a queryable seed id visible — degradation costs
                      depth, never discoverability
  I3 monotonic        sections fill in strict priority order; a section
                      renders within its cap or degrades to an explicit
                      count line, never a silent mid-entry cut
  I4 bounded          the brief never exceeds the hard ceiling
                      (asserted — a build/config defect raises, never a
                      silent over-budget brief)

Degradation ladder: P6 residual shrinks first, then P5 hypotheses, P4
attack surface, P3 findings; P1 objective, P2 tasks and the drilldown
pointer are floor-guaranteed. A pathological objective splits to a
verbatim first line + a journal pointer (brief_overflow journaled).

4.0 deltas: render functions take the EKD as first arg (the renderer
is not the store); the BriefRenderer adds the (revision, budget)-keyed
render cache with byte-for-byte reuse (the journaled `now` for a cache
hit is the ORIGINAL render's pinned clock — replay reconstructs with
it), journaling through record_brief_render (J2) and the Zone-T
attachment wrapping (<aegis-brief> delimiter pair — the fixed contract
text downstream tooling parses).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from .ekd import (
    EdgeKind, EngagementDAG, FINDING_SEVERITIES, NodeType,
)

# The Zone T injection seam (spec 5.5): the rendered brief is injected
# as a single user-context attachment immediately before the current
# turn, wrapped in this FIXED delimiter pair. The delimiter text is
# part of the contract — never written into the system prompt, never
# interleaved into Zone W.
BRIEF_ATTACHMENT_OPEN = "<aegis-brief>"
BRIEF_ATTACHMENT_CLOSE = "</aegis-brief>"

# Table 8 fixed facts carried: section set, priority order, degradation
# ladder direction, and the default caps. Cap VALUES are
# deployment-tunable (env at the renderer); the order and ladder are
# fixed by the 3.7 specification (Part 5.2/5.3).
L2_SECTION_ORDER = ("objective", "tasks", "findings",
                    "attack_surface", "hypotheses", "residual")
L2_LADDER = ("residual", "hypotheses", "attack_surface", "findings")
L2_FLOOR = ("objective", "tasks", "drilldown")
L2_DEFAULT_CAPS = {"objective": 120, "tasks": 100, "findings": 180,
                   "attack_surface": 200, "hypotheses": 120,
                   "residual": 80, "drilldown": 25}
L2_DRILLDOWN_LINE = "DRILLDOWN: every id above is queryable via memory_query."

DEFAULT_TOTAL = 700
DEFAULT_CEILING = 800
DEFAULT_TOPN = 12


def _is_adjacent(entity) -> bool:
    """SD-1 §2.1 carried: a host-like entity discovered during the
    engagement that matches no scope entry — visible in the brief
    (ADJACENT), never targeted (in_scope stays False)."""
    if entity.attrs.get("in_scope") is True:
        return False
    reason = str(entity.attrs.get("scope_reason", ""))
    return reason.startswith("adjacent")


def _age_string(now: float, latest: float) -> str:
    if not latest:
        return ""
    age_s = max(0, int(now - latest))
    if age_s < 60:
        return f" · updated {age_s}s ago"
    if age_s < 3600:
        return f" · updated {age_s // 60}m ago"
    return f" · updated {age_s // 3600}h ago"


def render_brief_l2(ekd: EngagementDAG,
                    token_budget: int = DEFAULT_TOTAL,
                    section_budgets: Optional[Dict[str, int]] = None,
                    topn_entities: int = DEFAULT_TOPN,
                    residual: str = "",
                    now: Optional[float] = None,
                    updated_by: str = "",
                    hard_ceiling: int = DEFAULT_CEILING,
                    scope_mode: str = "") -> Tuple[str, Dict[str, Any]]:
    """The L2 Zone-T brief (the Table 8 contract).

    Returns (brief_text, meta). meta carries the render facts the
    renderer journals: tokens used, per-section shown/dropped counts,
    escalation flag and the overflow payload.
    """
    now = now if now is not None else time.time()
    caps = dict(L2_DEFAULT_CAPS)
    caps.update({k: int(v) for k, v in (section_budgets or {}).items()
                 if k in caps})
    budget = max(int(token_budget), 1)
    ceiling = max(int(hard_ceiling), budget)

    def _est(text: str) -> int:
        return max(1, len(text) // 4)

    # ── P1 OBJECTIVE (verbatim; never truncated, follow-ups drop) ──
    objectives = list(ekd.nodes_of_type(NodeType.OBJECTIVE))
    obj_entries: List[str] = []
    obj_dropped = 0
    escalated = False
    overflow: Optional[Dict[str, Any]] = None
    primary = objectives[-1] if objectives else None
    follow_shown_source: List = []   # follow-ups, newest-first order
    if primary is not None:
        text = str(primary.attrs.get("text", primary.title))
        obj_entries.append(f"{primary.id} (verbatim): \"{text}\"")
        follow_shown_source = list(reversed(objectives[:-1]))
        cap = caps["objective"]
        for o in follow_shown_source:  # newest follow-up first
            line = f"{o.id} (follow-up): \"{o.attrs.get('text', o.title)}\""
            if _est("\n".join(obj_entries)) + _est(line) > cap \
                    and len(obj_entries) > 1:
                obj_dropped += 1
            else:
                obj_entries.append(line)
    else:
        obj_entries.append("(no objective recorded)")

    # ── P2 ACTIVE TASKS (running/blocked lines; done by count) ────
    tasks = list(ekd.nodes_of_type(NodeType.TASK))
    running = [t for t in tasks
               if t.attrs.get("status") in ("running", "pending", "blocked")]
    done = len(tasks) - len(running)
    blocked = sum(1 for t in running
                  if t.attrs.get("status") == "blocked")
    running.sort(key=lambda t: (0 if t.attrs.get("status") == "running"
                                else 1, -t.rev))
    task_entries: List[str] = []
    task_dropped = 0
    cap2 = caps["tasks"]
    for t in running:
        deps = ekd.neighbors(t.id, kinds=(EdgeKind.DEPENDS_ON,),
                              direction="out")
        line = (f"{t.id} {t.attrs.get('status', 'pending')} "
                f"{t.attrs.get('agent', '?')} \"{t.title[:80]}\""
                + (f" · after {', '.join(d.id for d in deps[:3])}"
                   if deps else ""))
        if task_entries and \
                _est("\n".join(task_entries)) + _est(line) > cap2:
            task_dropped += 1
        else:
            task_entries.append(line)

    # ── P3 FINDINGS (severity then recency; forced ledger floor) ──
    findings = [f for f in ekd.nodes_of_type(NodeType.FINDING)
                if f.valid_to is None]
    sev_rank = {s: i for i, s in enumerate(FINDING_SEVERITIES)}
    findings.sort(key=lambda f: (sev_rank.get(
        str(f.attrs.get("severity", "info")).lower(), 9), -f.rev))
    counts: Dict[str, int] = {}
    for f in findings:
        s = str(f.attrs.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1
    exploited = sum(1 for f in findings
                    if f.attrs.get("status") == "exploited")
    find_header = (f"FINDINGS ({len(findings)} total"
                   + (f" · {exploited} exploited" if exploited else "")
                   + " · " + " ".join(
                       f"{v} {k}" for k, v in sorted(
                           counts.items(),
                           key=lambda kv: sev_rank.get(kv[0], 9)) if v)
                   + ")")
    find_entries: List[str] = []
    find_dropped = 0
    cap3 = caps["findings"]
    for f in findings:
        obs = ekd.neighbors(f.id, kinds=(EdgeKind.OBSERVED_ON,),
                            direction="out")
        enables = ekd.neighbors(f.id, kinds=(EdgeKind.ENABLES,),
                                direction="out")
        # class if the extractor set one (rce, sqli, ...), else the
        # title capped — a classless finding is never mute in the brief
        fclass = str(f.attrs.get("class") or f.attrs.get("kind")
                     or (f.title[:60] or "finding"))
        line = (f"{f.id} {str(f.attrs.get('severity', 'info')).upper()} "
                f"{fclass}"
                + (f" on {obs[0].id}" if obs else "")
                + f" · {str(f.attrs.get('status', 'open')).upper()}"
                + (f" · enables {', '.join(e.id for e in enables[:3])}"
                   if enables else "")
                + (f" · needs {f.attrs['needs']}"
                   if f.attrs.get("needs") else ""))
        if find_entries and \
                _est("\n".join(find_entries)) + _est(line) > cap3:
            find_dropped += 1
        else:
            find_entries.append(line)

    # ── P4 ATTACK SURFACE (adjacency-aware, scope mode surface) ──
    entities = [e for e in ekd.nodes_of_type(NodeType.ENTITY)
                if e.subtype != "port_service" and e.valid_to is None]
    entities.sort(key=lambda e: (-len(ekd.calls_on(e.id)), -e.rev))
    host_ports: Dict[str, List[str]] = {}
    for ps in ekd.nodes_of_type(NodeType.ENTITY):
        if ps.subtype == "port_service" and ps.valid_to is None:
            hip = str(ps.attrs.get("host", ""))
            label = str(ps.attrs.get("service") or "")
            port_no = str(ps.attrs.get("port", "?"))
            host_ports.setdefault(hip, []).append(
                f"{label}:{port_no}" if label else port_no)
    in_scope = sum(1 for e in entities
                   if e.attrs.get("in_scope") is True)
    adjacent = sum(1 for e in entities
                   if _is_adjacent(e))
    auto_admitted = sum(
        1 for e in entities
        if str(e.attrs.get("scope_reason", "")).startswith(
            "subdomain-of:"))
    mode = str(scope_mode or "").strip().lower()
    if not mode:
        # pure-attrs fallback (deterministic; mirrors the P0-B rule)
        mode = "expand" if auto_admitted else "strict"
    surf_header = (f"ATTACK SURFACE ({len(entities)} entities"
                   + (f" · {in_scope} in scope" if in_scope else "")
                   + (f" · {adjacent} adjacent" if adjacent else "")
                   + f" · mode={mode}"
                   + (f", {auto_admitted} auto-admitted"
                      if mode == "expand" and auto_admitted else "")
                   + ")")
    surf_entries: List[str] = []
    surf_dropped = 0
    cap4 = caps["attack_surface"]
    for e in entities[:max(1, int(topn_entities))]:
        ports = host_ports.get(str(e.attrs.get("host", "")) or e.title,
                               [])
        port_str = (" · " + "/".join(str(p) for p in ports[:6])
                    + (f" +{len(ports) - 6}" if len(ports) > 6 else "")
                    ) if ports else ""
        calls = ekd.calls_on(e.id)
        line = (f"  {e.id} {e.subtype} {e.title[:70]}{port_str}"
                + (f" · {len(calls)} calls" if calls else ""))
        if _is_adjacent(e):
            line += " · ADJACENT (visible, never targeted)"
        elif e.attrs.get("in_scope") is False:
            line += " · OUT-OF-SCOPE"
        if surf_entries and \
                _est("\n".join(surf_entries)) + _est(line) > cap4:
            surf_dropped += 1
        else:
            surf_entries.append(line)
    if len(entities) > int(topn_entities):
        surf_dropped += len(entities) - int(topn_entities)

    # ── P5 HYPOTHESES (active/blocked lines; parked by count) ─────
    hyps = [h for h in ekd.nodes_of_type(NodeType.HYPOTHESIS)
            if h.valid_to is None]
    active = [h for h in hyps if h.attrs.get("status") not in
              ("parked", "refuted")]
    parked = len(hyps) - len(active)
    active.sort(key=lambda h: (0 if h.attrs.get("status") != "blocked"
                               else 1, -h.rev))
    hyp_entries: List[str] = []
    hyp_dropped = 0
    cap5 = caps["hypotheses"]
    for h in active:
        sup = ekd.neighbors(h.id, kinds=(EdgeKind.SUPPORTS,),
                            direction="in")
        contra = ekd.neighbors(h.id, kinds=(EdgeKind.CONTRADICTS,),
                               direction="in")
        line = (f"{h.id} "
                f"{str(h.attrs.get('status', 'active')).upper()} "
                f"\"{h.title[:90]}\""
                + (f" · supports: {', '.join(s.id for s in sup[:4])}"
                   if sup else "")
                + (f" · contradicts: {', '.join(c.id for c in contra[:3])}"
                   if contra else ""))
        if hyp_entries and \
                _est("\n".join(hyp_entries)) + _est(line) > cap5:
            hyp_dropped += 1
        else:
            hyp_entries.append(line)

    # ── P6 RESIDUAL (prose; shrinks first) ─────────────────────────
    residual = (residual or "").strip()
    if residual == "No previous summary.":
        residual = ""
    # Table 8: the section set is fixed — an empty residual renders an
    # explicit "none recorded" line (state "empty"), so the seven
    # sections are always present and the absence of a compaction
    # history is itself stated, never implied by omission.
    res_state = "full" if residual else "empty"
    res_text = ""
    if residual:
        rcap = caps["residual"] * 4
        if len(residual) <= rcap:
            res_text = residual
        else:
            res_state = "elided"

    # ── assembly + the degradation ladder ──────────────────────────
    def _count_line(dropped: int, seed: str, what: str) -> str:
        if seed:
            return f"+{dropped} more {what} — memory_query('{seed}')"
        return f"+{dropped} more {what}"

    def _seed(source: List, shown: List[str]) -> str:
        """I2: the first not-shown entry's id — truncation degrades
        depth, never discoverability."""
        return source[len(shown)].id if len(source) > len(shown) else ""

    def _blocks() -> List[str]:
        out: List[str] = []
        if obj_entries:
            out.append("OBJECTIVE\n  " + "\n  ".join(obj_entries)
                       + (("\n  " + _count_line(
                           obj_dropped, _seed(follow_shown_source,
                                              obj_entries[1:]),
                           "follow-ups"))
                          if obj_dropped else ""))
        if tasks or done:
            if task_entries:
                out.append("TASKS" + (f" ({done} done)" if done else "")
                           + "\n  " + "\n  ".join(task_entries)
                           + (("\n  " + _count_line(
                               task_dropped, _seed(running, task_entries),
                               "tasks"))
                              if task_dropped else ""))
            else:
                out.append(
                    f"TASKS: {len(running) - blocked} running · "
                    f"{blocked} blocked · {done} done"
                    + (f" — memory_query('{running[0].id}')"
                       if running else ""))
        if findings:
            if find_entries:
                out.append(find_header + "\n  " + "\n  ".join(find_entries)
                           + (("\n  " + _count_line(
                               find_dropped, _seed(findings, find_entries),
                               "findings"))
                              if find_dropped else ""))
            else:
                # forced severity ledger (never silently dropped)
                out.append(find_header
                           + f" — memory_query('{findings[0].id}')")
        if entities:
            if surf_entries:
                out.append(surf_header + "\n" + "\n".join(surf_entries)
                           + (("\n  " + _count_line(
                               surf_dropped, _seed(entities, surf_entries),
                               "entities"))
                              if surf_dropped else ""))
            else:
                out.append(surf_header
                           + " — memory_query('<ip|url|key>')")
        if hyps:
            if hyp_entries:
                out.append("HYPOTHESES / CHAINS"
                           + (f" ({parked} parked)" if parked else "")
                           + "\n  " + "\n  ".join(hyp_entries)
                           + (("\n  " + _count_line(
                               hyp_dropped, _seed(active, hyp_entries),
                               "hypotheses"))
                              if hyp_dropped else ""))
            else:
                out.append(f"HYPOTHESES: {len(active)} active · "
                           f"{parked} parked"
                           + (f" — memory_query('{active[0].id}')"
                              if active else ""))
        if res_state == "full" and res_text:
            out.append("RESIDUAL NOTES (prose):\n  "
                       + res_text.replace("\n", "\n  "))
        elif res_state == "elided":
            out.append(f"RESIDUAL NOTES: elided ({len(residual)} chars)"
                       f" — full text in the compaction record.")
        elif res_state == "empty":
            out.append("RESIDUAL NOTES: none recorded.")
        out.append(L2_DRILLDOWN_LINE)
        return out

    latest = max((n.ts for n in ekd.nodes.values()), default=0.0)
    header = (f"=== ENGAGEMENT KNOWLEDGE (rev {ekd.rev}"
              + _age_string(now, latest)
              + (f" by {updated_by}" if updated_by else "")
              + f" · budget {int(budget)}) ===")

    def _total(blocks: List[str]) -> int:
        body = sum(_est(b) for b in blocks)
        return body + _est(header)

    blocks = _blocks()
    # ladder: P6 -> P5 -> P4 -> P3 (floor sections never shrink).
    # The empty placeholder is a P6 rung too — it drops before any real
    # section loses an entry.
    while _total(blocks) > budget:
        if res_state == "full" and res_text:
            res_state = "elided"          # P6 shrinks first
        elif res_state in ("elided", "empty"):
            res_state = "absent"
        elif hyp_entries:
            hyp_entries.pop()             # then P5 ...
            hyp_dropped += 1
        elif surf_entries:
            surf_entries.pop()            # ... then P4 ...
            surf_dropped += 1
        elif find_entries:
            find_entries.pop()            # ... then P3 (ledger floor)
            find_dropped += 1
        else:
            break  # ladder exhausted at the floor
        blocks = _blocks()

    # floor overflow (5.3): split the objective, journal the anomaly
    if _total(blocks) > budget and primary is not None:
        text = str(primary.attrs.get("text", primary.title))
        first_line = text.split("\n", 1)[0]
        # A pathological single-line objective must not defeat the
        # split: hard-cap the verbatim line at the objective cap's
        # character width; the journal pointer carries the remainder.
        _line_cap = max(160, caps["objective"] * 4)
        if len(first_line) > _line_cap:
            first_line = first_line[:_line_cap].rstrip()
        obj_entries = [f"{primary.id} (verbatim, first line): "
                       f"\"{first_line}\"",
                       f"…objective continues in the journal — "
                       f"memory_query('{primary.id}') "
                       f"[{len(text)} chars]"]
        obj_dropped = 0
        follow_shown_source = []
        escalated = True
        overflow = {"objective_id": primary.id,
                    "objective_chars": len(text),
                    "first_line_chars": len(first_line),
                    "budget": budget, "ceiling": ceiling}
        blocks = _blocks()

    total = _total(blocks)
    if total > ceiling:
        # I4 is absolute: never ship an over-ceiling brief. This is a
        # build/config-level defect — fail loudly, never silently.
        raise ValueError(
            f"L2 brief cannot fit the hard ceiling: {total} > "
            f"{ceiling} tokens after full degradation + objective "
            f"escalation (floor guarantee exceeds the ceiling — "
            f"raise AEGIS_BRIEF_CEILING or AEGIS_BRIEF_TOTAL)")

    meta = {
        "tokens": int(total), "budget": int(budget),
        "ceiling": int(ceiling), "escalated": escalated,
        "overflow": overflow, "contract": "l2",
        "sections": {
            "objective": {"shown": len(obj_entries),
                          "dropped": obj_dropped},
            "tasks": {"shown": len(task_entries),
                      "dropped": task_dropped, "done": done},
            "findings": {"shown": len(find_entries),
                         "dropped": find_dropped,
                         "total": len(findings)},
            "attack_surface": {"shown": len(surf_entries),
                               "dropped": surf_dropped,
                               "total": len(entities)},
            "hypotheses": {"shown": len(hyp_entries),
                           "dropped": hyp_dropped, "parked": parked},
            "residual": {"state": res_state,
                         "chars": len(residual)},
        },
    }
    return header + "\n\n" + "\n\n".join(blocks), meta


# ─── detail rendering (drilldown for memory_query) ───────────────────


def render_node_detail(ekd: EngagementDAG, node_id: str,
                       max_chars: int = 4000) -> str:
    node = ekd.nodes.get(node_id)
    if node is None:
        return f"No node '{node_id}' in the engagement graph."
    lines = [
        f"=== {node.id} · {node.type}"
        + (f"/{node.subtype}" if node.subtype else "") + " ===",
        f"title: {node.title}",
        f"key: {node.key or '-'} · conf {node.conf:.2f} · rev {node.rev}"
        + (" · CURRENT" if node.valid_to is None
           else f" · invalid since r{node.valid_to}"),
    ]
    if node.attrs:
        attrs_json = json.dumps(node.attrs, default=str, indent=1,
                                ensure_ascii=False)
        lines.append("attrs: " + (attrs_json[:1200] + "…"
                                  if len(attrs_json) > 1200
                                  else attrs_json))
    nb_out = ekd.neighbors(node_id, direction="out")
    if nb_out:
        lines.append("out-edges: " + ", ".join(
            f"{n.id}({n.type})" for n in nb_out[:15])
            + (f" +{len(nb_out) - 15}" if len(nb_out) > 15 else ""))
    nb_in = ekd.neighbors(node_id, direction="in")
    if nb_in:
        lines.append("in-edges: " + ", ".join(
            f"{n.id}({n.type})" for n in nb_in[:15])
            + (f" +{len(nb_in) - 15}" if len(nb_in) > 15 else ""))
    if node.type == NodeType.ENTITY:
        calls = ekd.calls_on(node_id)
        if calls:
            summary: Dict[str, int] = {}
            for c in calls:
                t = str(c.attrs.get("tool", "?"))
                summary[t] = summary.get(t, 0) + 1
            lines.append("calls_on: " + ", ".join(
                f"{v}x {k}" for k, v in sorted(summary.items(),
                                               key=lambda kv: -kv[1])))
            lines.append("call ids: " + ", ".join(
                c.id for c in calls[-10:]))
        hist = ekd.entity_history(node_id)
        if hist:
            lines.append("history: " + " → ".join(
                f"{e['id']}@r{e['rev']}" for e in hist[:12]))
    chain = ekd.provenance_chain(node_id)
    if chain:
        lines.append("provenance: " + " ← ".join(
            f"{n.id}({n.type})" for n in reversed(chain[:8])))
    out = "\n".join(lines)
    return out[:max_chars] + "\n…[truncated]" if len(out) > max_chars \
        else out


# ─── the renderer (cache + journal + Zone T attachment) ──────────────


class BriefRenderer:
    """Renders the engagement brief with the (revision, budget)-keyed
    cache and J2 journaling.

    Cache key (5.6 carried): (phase, revision, budget triplet, topn,
    residual identity, scope mode). An unchanged revision reuses the
    previous payload byte-for-byte — the journaled `now` for a cache hit
    is the ORIGINAL render's pinned clock. One payload per engagement
    is the steady state; the cache stays O(1).
    """

    def __init__(self, *, journal: Any = None,
                 token_budget: int = DEFAULT_TOTAL,
                 hard_ceiling: int = DEFAULT_CEILING,
                 topn_entities: int = DEFAULT_TOPN,
                 section_budgets: Optional[Dict[str, int]] = None,
                 phase: str = "main"):
        self.journal = journal
        self.budget = int(token_budget)
        self.ceiling = int(hard_ceiling)
        self.topn = int(topn_entities)
        self.sections = dict(section_budgets or {})
        self.phase = str(phase)
        self._cache_key: Optional[tuple] = None
        self._cache: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------ render
    def render(self, ekd: EngagementDAG, residual: str = "", *,
               now: Optional[float] = None,
               updated_by: str = "",
               scope_mode: str = "",
               phase: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
        """Render (or reuse) the brief for the graph's current revision.
        Returns (brief_text, render_facts) — the facts carry everything
        the caller journals: brief_hash, cache_hit, pinned now, meta."""
        phase = str(phase or self.phase)
        cache_key = (
            phase, int(ekd.rev), self.budget, self.ceiling,
            tuple(sorted(self.sections.items())), self.topn,
            hashlib.sha256(residual.encode("utf-8", "ignore")
                           ).hexdigest()[:16],
            str(scope_mode or ""),
        )
        cache_hit = False
        if cache_key == self._cache_key and self._cache is not None:
            cached = self._cache
            brief, meta = cached["brief"], dict(cached["meta"])
            render_now = float(cached["now"])
            cache_hit = True
        else:
            render_now = time.time() if now is None else float(now)
            brief, meta = render_brief_l2(
                ekd,
                token_budget=self.budget,
                section_budgets=self.sections or None,
                topn_entities=self.topn,
                residual=residual,
                now=render_now,
                updated_by=updated_by,
                hard_ceiling=self.ceiling,
                scope_mode=scope_mode)
            meta["now"] = render_now
            # one payload per engagement is the steady state (O(1))
            self._cache_key = cache_key
            self._cache = {"brief": brief, "meta": meta, "now": render_now}
        facts = {
            "brief": brief, "brief_rev": int(ekd.rev),
            "budget": self.budget, "ceiling": self.ceiling,
            "now": float(render_now), "cache_hit": cache_hit,
            "escalated": bool(meta.get("escalated")),
            "overflow": meta.get("overflow"), "meta": meta,
            "phase": phase,
            "brief_hash": hashlib.sha256(
                brief.encode("utf-8", "ignore")).hexdigest()[:16],
        }
        return brief, facts

    # ----------------------------------------------------------- journal
    def journal_render(self, facts: Dict[str, Any], *,
                       prompt_hash: Optional[str] = None,
                       window_msg_count: Optional[int] = None,
                       window_hash: Optional[str] = None) -> None:
        """J2: the render is reconstructible from (rev, budget, pinned
        now); the hash pins byte-identity for the audit trail. An
        escalated floor-split also writes brief_overflow."""
        j = self.journal
        if j is None:
            return
        try:
            j.record_brief_render(
                facts["brief"], budget=facts["budget"],
                ekd_rev=facts["brief_rev"],
                render_hash=facts["brief_hash"],
                now=facts["now"],
                brief_hash=facts["brief_hash"],
                prompt_hash=prompt_hash,
                actor_hint=str(facts.get("meta", {}).get("updated_by", "")),
                contract="l2", ceiling=facts["ceiling"],
                window_msg_count=window_msg_count,
                window_hash=window_hash,
                cache_hit=facts["cache_hit"],
                phase=facts.get("phase"),
                escalation=facts["escalated"])
            ov = facts.get("overflow")
            if ov:
                j.record_brief_overflow(
                    ekd_rev=facts["brief_rev"], budget=facts["budget"],
                    ceiling=facts["ceiling"],
                    objective_id=str(ov.get("objective_id", "")),
                    objective_chars=int(ov.get("objective_chars", 0)),
                    first_line_chars=int(
                        ov.get("first_line_chars", 0)))
        except Exception:
            pass  # J4: the recorder never gates the render

    # -------------------------------------------------------- attachment
    def render_attachment(self, ekd: EngagementDAG, residual: str = "", *,
                          updated_by: str = "",
                          scope_mode: str = "") -> Tuple[
                              Dict[str, Any], Dict[str, Any]]:
        """The Zone T user-context message: the brief wrapped in the
        fixed <aegis-brief> delimiter pair. Returns (message, facts)."""
        brief, facts = self.render(ekd, residual, updated_by=updated_by,
                                   scope_mode=scope_mode)
        msg = {"role": "user",
               "content": f"{BRIEF_ATTACHMENT_OPEN}\n{brief}\n"
                          f"{BRIEF_ATTACHMENT_CLOSE}"}
        return msg, facts
