"""hypervisor.agents.task — the Task tool + run_agent (P3, REFACTOR-03).

The 3.7.3 contract subagent (core/subagents.py run_contract_subagent,
L507-666) generalized into the full Claude-Code Task tool: the SAME
query loop runs at depth+1 as a nested async generator — never a graph
node, never a mesh. The child receives a contract, never histories
(rule C5):

  contract mode  a one-paragraph mission contract per Table 11 + the
                 registry experts (defs.py): skeleton + hygiene notes +
                 evidence-citation clause + phase-scoped brief slice at
                 the spawn revision + memory_query scopes + the explicit
                 no-inheritance statement. `messages` is exactly [task].

Fork mode (cache-safe verbatim history inheritance) ships as
build_fork_context for callers that legitimately need it (the P2 fold
already constructs its summarizer fork inline; nothing else may).

Discipline carried verbatim from 3.7:
  * J1-style write-ahead — subagent_spawn is journaled BEFORE the child
    runs (mode, agent, contract hash, brief-slice rev + hash, scopes,
    ceiling), so the contract any child received is reconstructible from
    the journal alone even on a child crash;
  * the report lands linked — subagent_report carries the spawn seq +
    the sha of the FULL report text, and a message event with
    source='subagent:<agent>' rides the channel (replay's linkage pass
    verifies the pair end-to-end);
  * turn ceiling with done-so-far — at the ceiling the child is forced
    to ONE final no-tools call with the done-so-far instruction: a
    partial report, never a silent drop (Table 13);
  * scopes inherited are a SUBSET — same scope manager (network
    authorization identical), a REDUCED tool registry (the def's
    allowlist; the Task tool itself is structurally absent), and a
    result-filtered memory_query (the child cannot read around its
    scope by phrasing — the filter is on the RESULT);
  * spawn depth is capped at 2 (main -> expert -> expert): deeper
    spawns get a clear error result, not recursion.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..memory.brief import render_brief_l2, render_node_detail
from ..memory.ekd import EngagementDAG
from ..permissions import SafetyClass
from ..tools.base import (Tool, ToolContext, ToolRegistry, ToolResult,
                          dispatch_tools)
from .defs import AGENT_ORDER, AgentDef, get_agent, system_prompt_for

MAX_SPAWN_DEPTH = 2

_DONE_SO_FAR = (
    "You have reached your turn budget. STOP calling tools now and "
    "produce your final report from what you have done so far. State "
    "explicitly which part of the task remains incomplete (done-so-far "
    "clause) — a partial report is expected, do not apologize and do "
    "not retry tools.")

# env-tuned knobs (boot-once; the oracle defaults carried)
try:
    AGENT_TIMEOUT_S = max(60.0, float(os.environ.get(
        "AEGIS_AGENT_TIMEOUT_S", "") or 1800.0))
except ValueError:
    AGENT_TIMEOUT_S = 1800.0
try:
    AGENT_MAX_TURNS = max(2, int(os.environ.get(
        "AEGIS_SUBAGENT_MAX_TURNS", "") or 8))
except ValueError:
    AGENT_MAX_TURNS = 8
try:
    AGENT_BRIEF_BUDGET = max(100, int(os.environ.get(
        "AEGIS_BRIEF_TOTAL", "") or 700))
except ValueError:
    AGENT_BRIEF_BUDGET = 700
try:
    AGENT_BRIEF_CEILING = max(AGENT_BRIEF_BUDGET, int(os.environ.get(
        "AEGIS_BRIEF_CEILING", "") or 800))
except ValueError:
    AGENT_BRIEF_CEILING = 800
try:
    AGENT_BRIEF_TOPN = max(1, int(os.environ.get(
        "AEGIS_BRIEF_TOPN", "") or 12))
except ValueError:
    AGENT_BRIEF_TOPN = 12


def _sha16(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", "ignore")).hexdigest()[:16]


# ─── fork mode (C5 cache-safe inheritance) ────────────────────────────

def build_fork_context(history: Sequence[Dict[str, Any]],
                       instruction: Dict[str, Any],
                       system_prompt: Optional[str] = None
                       ) -> List[Dict[str, Any]]:
    """Fork mode: byte-verbatim copy of EXACTLY the message range the
    child must read, with its instruction at the tail. No re-rendering,
    no re-ordering, no slicing mid-range — the copy is what makes the
    fork cache-safe (a prefix that differs by a byte is a cache write)."""
    msgs: List[Dict[str, Any]] = [dict(m) for m in history]
    msgs.append(dict(instruction))
    if system_prompt is None:
        return msgs
    return [{"role": "system", "content": system_prompt}] + msgs


# ─── the phase-scoped brief slice (spec 3.7, 4.0 block headers) ──────

_SLICE_SECTION_PREFIXES = (
    # render_brief_l2's fixed block headers (memory/brief.py)
    ("objective", ("OBJECTIVE",)),
    ("tasks", ("TASKS",)),
    ("findings", ("FINDINGS",)),
    ("attack_surface", ("ATTACK SURFACE",)),
    ("hypotheses", ("HYPOTHESES",)),
    ("residual", ("RESIDUAL NOTES",)),
)
_DRILLDOWN_PREFIX = "DRILLDOWN:"


def slice_brief(brief: str, sections: Sequence[str]) -> str:
    """Keep only the agent-relevant section blocks of a rendered L2
    brief. The header line (the revision the slice rendered at) and the
    drilldown pointer ALWAYS ride along — the pointer is
    floor-guaranteed (5.2), the header carries the revision (5.4).
    Section blocks are separated by blank lines and identified by their
    fixed header prefixes; an unmatched block is dropped
    (conservative)."""
    lines = brief.split("\n")
    header = lines[0] if lines else ""
    blocks: List[List[str]] = []
    cur: Optional[List[str]] = None
    for ln in lines[1:]:
        if not ln.strip():
            if cur is not None:
                blocks.append(cur)
                cur = None
            continue
        if cur is None:
            cur = [ln]
        else:
            cur.append(ln)
    if cur is not None:
        blocks.append(cur)

    kept: List[str] = [header]
    wanted = set(sections)
    drilldown = ""
    for blk in blocks:
        first = blk[0]
        if first.startswith(_DRILLDOWN_PREFIX):
            drilldown = "\n".join(blk)
            continue
        for key, prefixes in _SLICE_SECTION_PREFIXES:
            if any(first.startswith(p) for p in prefixes):
                if key in wanted:
                    kept.append("\n".join(blk))
                break
    if drilldown:
        kept.append(drilldown)
    return "\n\n".join(kept)


def brief_slice_for_agent(ekd: EngagementDAG, defn: AgentDef, *,
                          residual: str = "",
                          now: Optional[float] = None,
                          ) -> Tuple[str, Dict[str, Any]]:
    """Render the phase-scoped brief slice at the CURRENT revision:
    render_brief_l2 under the Table 8 budgets (the deterministic I1-I4
    contract), then keep the agent-relevant sections + header +
    drilldown pointer. Derived from the same deterministic render the
    main loop's Zone T brief comes from, so a subagent and the main
    loop can never disagree about the world at a given revision (G3)."""
    brief, meta = render_brief_l2(
        ekd,
        token_budget=AGENT_BRIEF_BUDGET,
        topn_entities=AGENT_BRIEF_TOPN,
        residual=residual or "",
        now=(now if now is not None else time.time()),
        updated_by=f"agent:{defn.name}",
        hard_ceiling=AGENT_BRIEF_CEILING)
    sliced = slice_brief(brief, defn.brief_sections)
    slice_meta = dict(meta)
    slice_meta["rev"] = int(getattr(ekd, "rev", 0) or 0)
    slice_meta["sections_kept"] = list(defn.brief_sections)
    slice_meta["brief_chars"] = len(brief)
    slice_meta["slice_chars"] = len(sliced)
    return sliced, slice_meta


# ─── scoped L1 access (Table 12: the filter is on the RESULT) ─────────

def scoped_query(ekd: EngagementDAG, query: str, defn: AgentDef,
                 limit: int = 5) -> List[Any]:
    """memory_query with the agent scope enforced server-side: results
    are filtered to the allowed node types, entities additionally to
    the allowed subtypes. The child cannot read around its scope by
    phrasing."""
    types = set(defn.query_types)
    subtypes = set(defn.query_subtypes)
    out = []
    for n in ekd.query(query, limit=max(int(limit) * 4, 20)):
        if types and n.type not in types:
            continue
        if n.type == "entity" and subtypes and n.subtype not in subtypes:
            continue
        out.append(n)
        if len(out) >= int(limit):
            break
    return out


class ScopedMemoryQueryTool(Tool):
    """The child's memory_query — same wire surface as the parent's
    (tools/memory.py) with the def's result filter applied. Ids the
    child's own contract brief surfaced stay queryable (they are in its
    query_types); everything else returns a scoped-miss line."""

    name = "memory_query"
    aliases = ("dag_query",)
    input_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string", "minLength": 1,
                "description": "An EKD node id (e15, F7, T4...), a "
                               "canonical key, or a search substring.",
            },
            "detail": {"type": "boolean", "default": True},
        },
        "required": ["query"],
        "additionalProperties": False,
    }
    timeout_s = 10.0

    def __init__(self, defn: AgentDef, ekd: EngagementDAG):
        self.defn = defn
        self.ekd = ekd

    def prompt(self) -> str:
        return ("Query the engagement knowledge graph (EKD), scoped "
                "for your role. Pass a node id from your brief slice, "
                "a canonical key (ip/domain/url/cve), or a search "
                "substring. Returns matches plus full detail: attrs, "
                "edges, evidence calls, provenance.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def call(self, args: Dict[str, Any], ctx: ToolContext) -> ToolResult:
        q = str(args.get("query", ""))
        nodes = scoped_query(self.ekd, q, self.defn, limit=5)
        if not nodes:
            return ToolResult(content=(
                f"No in-scope knowledge-graph match for {q!r} (role "
                f"scope: {', '.join(self.defn.query_types)})."))
        out = [render_node_detail(self.ekd, n.id, max_chars=2000)
               for n in nodes]
        return ToolResult(content="\n".join(out))


def build_child_registry(parent: ToolRegistry, defn: AgentDef,
                         ekd: EngagementDAG) -> ToolRegistry:
    """The child's registry: the def's allowlist resolved against the
    PARENT registry (same tool objects — freeze discipline preserved),
    with the scoped memory_query substituted for the parent's. The Task
    tool is structurally absent — recursion is impossible through the
    tool plane; the depth gate in TaskTool.call is the belt to these
    braces. Unknown allowlist names are refused (a def naming a tool
    the parent does not carry is a definition defect, not a
    silent drop)."""
    child = ToolRegistry()
    allowed = defn.tools or tuple(parent.names())
    for name in allowed:
        if name == "task":
            continue                      # structural no-recursion
        tool = parent.resolve(name)
        if tool is None:
            raise ValueError(
                f"agent {defn.name!r} allowlists unknown tool {name!r}")
        if tool.name == "memory_query":
            continue                      # substituted below
        child.register(tool)
    child.register(ScopedMemoryQueryTool(defn, ekd))
    return child


# ─── the report ───────────────────────────────────────────────────────

@dataclass
class AgentReport:
    """The child's report-back (Table 12: it lands as a linked channel
    message). `partial` flags the turn-budget ceiling case (Table 13
    done-so-far clause)."""
    agent: str
    report: str
    turns_used: int
    partial: bool
    tool_calls: int
    sidechain_id: str = ""
    spawn_seq: int = 0
    report_sha: str = ""

    def tool_result_content(self) -> str:
        head = (f"[{self.agent}] turns={self.turns_used} "
                f"tool_calls={self.tool_calls}"
                + (" · PARTIAL (turn budget ceiling)" if self.partial
                   else ""))
        return f"{head}\n{self.report}"


# ─── the forced final call (Table 13 done-so-far) ─────────────────────

async def _forced_final(system_prompt: str, messages: List[Dict[str, Any]],
                        adapter: Any, guard: Any, purpose: str,
                        max_tokens: int = 2048) -> str:
    """One bounded no-tools call appending the done-so-far instruction
    (the guard owns the bounds; failure degrades to the standing
    placeholder, never an exception out of the agent path)."""
    prompt = ([{"role": "system", "content": system_prompt}]
              + list(messages)
              + [{"role": "user", "content": _DONE_SO_FAR}])
    try:
        async def _factory():
            async for c in adapter.stream_chat(
                    messages=prompt, tools=None, max_tokens=max_tokens):
                yield c

        parts: List[str] = []
        stream = (guard.call_stream(_factory, purpose=purpose,
                                    model=getattr(adapter, "model", ""),
                                    turn=-1, messages=prompt)
                  if guard is not None else _factory())
        async for c in stream:
            if c.kind == "text" and c.text:
                parts.append(c.text)
        return "".join(parts).strip()
    except Exception:
        return ""


def _channel_from_sidechain(sidechain: Any) -> List[Dict[str, Any]]:
    """Rebuild the child's message channel from its sidechain
    transcript (record.message fields, in seq order). The forced final
    call needs the child's live channel; the loop owned it, the
    sidechain mirrored it."""
    out: List[Dict[str, Any]] = []
    if sidechain is None:
        return out
    try:
        for rec in sidechain.read_all():
            m = rec.get("message")
            if isinstance(m, dict) and m.get("role"):
                out.append(m)
    except Exception:
        return []
    return out


# ─── the child journal proxy (per-channel discipline, PORT-06) ─────

class ChildJournal:
    """Wraps the engagement journal for a subagent's sidechain loop:
    message events and fold surgery carry the subagent channel, so
    replay's Zone W simulation applies surgery PER CHANNEL (the
    child's channel never pollutes the main window reconstruction,
    and the child's own fold stays journaled + reconstructible — J3
    for sidechains). Everything else (ekd_mutation, tool calls,
    permission decisions...) delegates untouched: the EKD revision
    chain is global."""

    def __init__(self, parent: Any, agent: str):
        self._parent = parent
        self._agent = str(agent)

    def record_message(self, m, *, source: str = "",
                       replaces: Optional[str] = None,
                       **kw):
        return self._parent.record_message(
            m, source=f"subagent:{self._agent}:{source}",
            replaces=replaces, **kw)

    def record_compaction(self, *a, **kw):
        kw.setdefault("channel", f"subagent:{self._agent}")
        return self._parent.record_compaction(*a, **kw)

    def record_compaction_trim(self, *a, **kw):
        kw.setdefault("channel", f"subagent:{self._agent}")
        return self._parent.record_compaction_trim(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._parent, name)


# ─── run_agent: the child loop at depth+1 ─────────────────────────────

async def run_agent(agent_name: str, task: str, ctx: ToolContext, *,
                    ceiling: Optional[int] = None,
                    ) -> AgentReport:
    """Spawn one contract child and run it to its report under the turn
    ceiling (the 3.7 run_contract_subagent generalized onto THE loop).

    Everything the child needs rides ctx.extra["agent_runtime"]:
    {"adapter", "guard", "budget", "summarizer"} (the CLI boot and the
    test fakes inject it). The child shares the adapter/guard/scope/EKD
    (the world), and gets its own registry, session sidechain, compact
    engine and fingerprint monitor (its own actor identity)."""
    from ..context.compact import CompactEngine
    from ..context.fingerprint import FingerprintMonitor
    from ..query import LoopEvent, ProductionDeps, QueryParams, query_loop

    defn = get_agent(agent_name)
    runtime = (ctx.extra or {}).get("agent_runtime") or {}
    adapter = runtime.get("adapter")
    guard = runtime.get("guard")
    budget = runtime.get("budget")
    summarizer = runtime.get("summarizer")
    if adapter is None:
        raise RuntimeError(
            "agent runtime not injected (ctx.extra['agent_runtime'] "
            "needs adapter/guard/budget/summarizer — CLI boot or test "
            "fakes provide it)")

    ekd = (ctx.extra or {}).get("ekd")
    journal = getattr(ctx, "journal", None)
    parent_session = (ctx.extra or {}).get("session")
    residual = (ctx.extra or {}).get("episodic_residual", "") or ""

    # ── the contract (write-ahead journal BEFORE the child runs) ──
    slice_text, slice_meta = ("", {}) if ekd is None else \
        brief_slice_for_agent(ekd, defn, residual=residual)
    slice_rev = int(slice_meta.get("rev", 0) or getattr(ekd, "rev", 0))
    system_prompt = system_prompt_for(
        defn, slice_text=slice_text, slice_rev=slice_rev,
        workspace=ctx.workspace,
        model_name=str(getattr(adapter, "model", "")))
    contract_hash = _sha16(system_prompt)
    slice_hash = _sha16(slice_text) if slice_text else ""
    turn_ceiling = int(ceiling if ceiling is not None else defn.ceiling)

    spawn_seq = 0
    if journal is not None:
        ev = journal.record_subagent_spawn(
            "contract", defn.name, task=str(task or ""),
            contract_hash=contract_hash, brief_rev=slice_rev,
            brief_slice_hash=slice_hash,
            scopes=list(defn.query_types), ceiling=turn_ceiling)
        spawn_seq = int((ev or {}).get("seq") or 0)

    # ── the sidechain transcript ──────────────────────────────────
    sidechain = None
    if parent_session is not None:
        try:
            sidechain = parent_session.spawn_sidechain(
                label=f"agent:{defn.name}")
        except Exception:
            sidechain = None

    # ── the child context: scopes inherited ⊆ parent scope ───────
    child_registry = build_child_registry(ctx.registry, defn, ekd)
    child_extra: Dict[str, Any] = {
        "ekd": ekd,
        "ekd_state_path": (ctx.extra or {}).get("ekd_state_path"),
        "objective_id": (ctx.extra or {}).get("objective_id"),
        "extractor_failures": (ctx.extra or {}).get(
            "extractor_failures") if ekd is not None else None,
        "episodic_residual": "",
        "tail_attachments": {},
        "model": str(getattr(adapter, "model", "")),
        "tool_names": [t.name for t in child_registry],
        "fingerprint_monitor": FingerprintMonitor(
            journal, label=f"agent:{defn.name}"),
        "agent": defn.name,
        "agent_runtime": runtime,
    }
    if sidechain is not None:
        child_extra["session"] = sidechain
    child_journal = ChildJournal(journal, defn.name) \
        if journal is not None else None
    child_ctx = ctx.child(registry=child_registry,
                          label=f"agent:{defn.name}",
                          journal=child_journal,
                          extra=child_extra)

    child_engine = None
    if budget is not None:
        child_engine = CompactEngine(budget, summarizer=summarizer)
    deps = ProductionDeps(adapter=adapter, guard=guard, budget=budget,
                          engine=child_engine)

    params = QueryParams(
        system_prompt=system_prompt,
        tools=list(child_registry),
        initial_messages=[{"role": "user",
                           "content": str(task or "").strip()}],
        ctx=child_ctx, max_turns=turn_ceiling,
        purpose=f"subagent:{defn.name}")

    # ── run THE loop at depth+1, tracking the report surface ──────
    cur_text = ""
    saw_tools_since_text = False
    turns_used = 0
    tool_calls = 0
    partial = False
    report = ""
    end_reason = ""

    async def _drive():
        nonlocal cur_text, saw_tools_since_text, turns_used, tool_calls
        nonlocal report, end_reason
        async for ev in query_loop(params, deps):
            if ev.kind == "text_delta":
                cur_text += ev.text
            elif ev.kind == "tool_result":
                saw_tools_since_text = True
                tool_calls += len(ev.tool_results or [])
                cur_text = ""       # text before tools belongs to that turn
            elif ev.kind == "completed":
                end_reason = str(ev.reason)
                d = ev.detail or {}
                turns_used = int(d.get("turns") or 0)
                if ev.reply is not None and ev.reply.text:
                    report = ev.reply.text.strip()
                elif cur_text.strip():
                    report = cur_text.strip()
        # after the stream: report holds the final-turn text if any

    try:
        await asyncio.wait_for(_drive(), timeout=AGENT_TIMEOUT_S)
    except asyncio.TimeoutError:
        end_reason = "agent_timeout"
        partial = True
        report = ""

    # ── Table 13: the ceiling / empty-final cases ─────────────────
    if end_reason in ("max_turns", "agent_timeout"):
        partial = True
        if not report:
            forced = await _forced_final(
                system_prompt,
                _channel_from_sidechain(sidechain) or
                [{"role": "user", "content": str(task or "")}],
                adapter, guard, f"subagent-final:{defn.name}")
            report = forced or "(turn budget exhausted before a report)"
    elif end_reason == "end_turn" and not report:
        # empty final: force the done-so-far shape
        partial = True
        forced = await _forced_final(
            system_prompt,
            _channel_from_sidechain(sidechain) or
            [{"role": "user", "content": str(task or "")}],
            adapter, guard, f"subagent-final:{defn.name}")
        report = forced or "(subagent returned an empty report)"
    elif end_reason not in ("end_turn",):
        # aborted / watchdog / model_error / prompt_too_long
        partial = True
        if not report:
            report = (f"(subagent ended early: {end_reason or 'unknown'}"
                      f" — see the sidechain transcript"
                      + (f" {sidechain.session_id}"
                         if sidechain is not None else "") + ")")

    # ── the SubagentStop seam (P4, CC parity): the operator's veto on
    #    the child's report. One bounded re-entry on block (the block
    #    reason rides the channel as an isMeta continuation); a second
    #    block or a failed re-entry leaves the report standing, marked
    #    partial + journaled — the child's turn ceiling is never blown.
    sub_stop = (ctx.extra or {}).get("subagent_stop_hook")
    if sub_stop is not None and end_reason == "end_turn" and report:
        try:
            from ..hooks import (block_feedback_message, journal_hook_run,
                                 run_subagent_stop_hook,
                                 subagent_stop_payload)
            payload = subagent_stop_payload(
                agent_type=defn.name,
                agent_id=(sidechain.session_id
                          if sidechain is not None else ""),
                last_assistant_message=report[:8000],
                stop_hook_active=False)
            decision = await run_subagent_stop_hook(sub_stop, payload)
            journal_hook_run(
                journal, decision, payload,
                event="stop_hook")  # rides the shared v2 surface
            if decision.blocks:
                channel = _channel_from_sidechain(sidechain) or \
                    [{"role": "user", "content": str(task or "")}]
                reentry_msgs = channel + [block_feedback_message(
                    decision.reason)]
                re_params = QueryParams(
                    system_prompt=system_prompt,
                    tools=list(child_registry),
                    initial_messages=reentry_msgs,
                    ctx=child_ctx, max_turns=turn_ceiling,
                    purpose=f"subagent:{defn.name}:stop_hook_reentry")
                re_report = ""
                re_reason = ""

                async def _redrive():
                    nonlocal re_report, re_reason
                    rtext = ""
                    async for ev in query_loop(re_params, deps):
                        if ev.kind == "text_delta":
                            rtext += ev.text
                        elif ev.kind == "completed":
                            re_reason = str(ev.reason)
                            if ev.reply is not None and ev.reply.text:
                                re_report = ev.reply.text.strip()
                            elif rtext.strip():
                                re_report = rtext.strip()
                    # rtext intentionally local: the report surface is
                    # the final reply, matching _drive()'s contract

                try:
                    await asyncio.wait_for(_redrive(),
                                           timeout=AGENT_TIMEOUT_S)
                except asyncio.TimeoutError:
                    re_reason = "agent_timeout"
                if re_report:
                    report = re_report
                    turns_used += 1        # the re-entry consumed a turn
                else:
                    partial = True
                    report = (report + "\n[stop-hook block could not be "
                              "resolved: "
                              + (re_reason
                                 or "no report from the re-entry") + "]")
        except Exception:
            # the seam never breaks the agent path — journaled upstream
            pass

    rep = AgentReport(
        agent=defn.name, report=report, turns_used=turns_used,
        partial=partial, tool_calls=tool_calls,
        sidechain_id=(sidechain.session_id if sidechain is not None
                      else ""),
        spawn_seq=spawn_seq,
        report_sha=_sha16(report))

    # ── the linked report-back (spawn seq + full-text sha + the
    #    channel message event replay verifies) ───────────────────
    if journal is not None:
        journal.record_subagent_report(
            spawn_seq, defn.name, report_sha=rep.report_sha,
            report_chars=len(rep.report), turns_used=rep.turns_used,
            partial=rep.partial)

        class _ReportMsg:
            """The message-event carrier for record_message (the
            frozen attribute surface: type / content / tool_call_id)."""
            type = "user"
            tool_call_id = ""

            def __init__(self, text: str):
                self.content = text

        journal.record_message(
            _ReportMsg(rep.report), source=f"subagent:{defn.name}")
    if sidechain is not None:
        try:
            sidechain.record_meta("note", {
                "agent_report": True, "agent": defn.name,
                "spawn_seq": spawn_seq, "partial": rep.partial,
                "report_sha": rep.report_sha,
                "turns_used": rep.turns_used,
                "tool_calls": rep.tool_calls})
        except Exception:
            pass

    return rep


# ─── the Task tool ────────────────────────────────────────────────────

class TaskTool(Tool):
    """CC's Task tool, VAPT-shaped (REFACTOR-03). The model names an
    agent and hands it a task; the tool runs the child to its report
    and returns the report as its result — the caller relays it."""

    name = "task"
    aliases = ("subagent", "spawn_agent")
    input_schema = {
        "type": "object",
        "properties": {
            "agent": {
                "type": "string", "minLength": 2,
                "description": "Agent to spawn (e.g. recon, web-exploit, "
                               "verification, reporting, sast, dfir, "
                               "general-purpose).",
            },
            "task": {
                "type": "string", "minLength": 8, "maxLength": 12000,
                "description": "The mission for the agent: self-"
                               "contained, one paragraph, with the "
                               "completion expectation. The agent has "
                               "no other context than this and its "
                               "brief slice.",
            },
            "ceiling": {
                "type": "integer", "minimum": 1, "maximum": 50,
                "description": "Optional turn-ceiling override for this "
                               "spawn (default: the agent's definition).",
            },
        },
        "required": ["agent", "task"],
        "additionalProperties": False,
    }
    timeout_s = AGENT_TIMEOUT_S
    cancel_siblings_on_error = False

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False            # a spawn is heavy: it serializes its batch

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        # The tool itself is local orchestration; the CHILD's tools gate
        # their own targets through the same scope engine. Class WRITE
        # (it causes state changes through the child), no targets —
        # in-scope engagements allow it, the audit trail names the agent.
        return SafetyClass.WRITE

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        return False            # a spawn installs nothing on the estate

    def prompt(self) -> str:
        agents = ", ".join(AGENT_ORDER)
        return (
            "Launch a subagent to handle a self-contained task. The "
            "agent runs autonomously with a scoped toolset and its own "
            "turn budget, then reports back exactly what it did and "
            "found — its report is this tool's result. Give the agent a "
            "mission it can complete independently: it does NOT see "
            "this conversation, only its task and the engagement brief "
            "slice. Use agents for parallelizable or specialized work "
            "(scanning, verification, analysis, reporting); do the "
            "orchestration yourself. Spawnable agents: " + agents + ".")

    def validate_input(self, args: Dict[str, Any]) -> Optional[str]:
        try:
            get_agent(str(args.get("agent", "")))
        except KeyError as exc:
            return str(exc)
        c = args.get("ceiling")
        if c is not None and not 1 <= int(c) <= 50:
            return "ceiling must be 1..50"
        return None

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        if ctx.depth >= MAX_SPAWN_DEPTH:
            return ToolResult.error(
                f"spawn depth ceiling ({MAX_SPAWN_DEPTH}) reached — "
                f"depth {ctx.depth} agents cannot spawn children; "
                f"complete the work yourself")
        agent = str(args.get("agent", ""))
        task = str(args.get("task", ""))
        ceiling = args.get("ceiling")
        try:
            rep = await run_agent(agent, task, ctx,
                                  ceiling=int(ceiling)
                                  if ceiling is not None else None)
        except KeyError as exc:
            return ToolResult.error(str(exc))
        except RuntimeError as exc:
            return ToolResult.error(str(exc))
        meta = {"agent": rep.agent, "turns": rep.turns_used,
                "tool_calls": rep.tool_calls, "partial": rep.partial,
                "sidechain": rep.sidechain_id, "spawn_seq": rep.spawn_seq,
                "report_sha": rep.report_sha}
        return ToolResult(content=rep.tool_result_content(),
                          metadata=meta)
