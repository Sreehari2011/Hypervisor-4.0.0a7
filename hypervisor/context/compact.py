"""hypervisor.context.compact — the compaction ladder (P2).

PORT-02 (3.7.3 src/core/compaction.py) + REFACTOR-01 (the Memory_Manager
graph node and its budget plumbing dissolve into this pre-flight step).
The ladder, cheap-first (spec 6.1):

  Tier 0, always on   attachment hygiene — drop stale drilldown
                      expansions from Zone T at each boundary.
  Tier 1, deterministic  window trim — drop the oldest whole turn
                      groups beyond a reduced K (never splitting a
                      tool pair). messages[0] (the objective) is never
                      trimmed.
  Tier 2, deterministic  microcompact — heavy tool-result bodies older
                      than the protected window replaced by a one-line
                      stub keeping the EKD artifact + journal refs.
  Tier 3, LLM         the fold under the verbatim prompt family
                      (compact_prompts.py, PORT-01) with a cache-aware
                      direction and the 3-failure breaker.

Tier-3 anatomy (6.2-6.6 carried): the summarization prompt is the
no-tools preamble + the template (base | from | up_to) + exactly ONE
Additional-Instructions block (the AEGIS adaptation: Table 10 content
mapping + the binding id-preservation rule) + the no-tools trailer;
the summarizer is a single-turn no-tools call through the guard
(purpose='compact' — its own breaker lane) inheriting precisely the
message range being summarized; the output is drafted in <analysis>
and delivered in <summary>, which format_compact_summary strips
deterministically (fallback: raw text kept, malformation journaled,
breaker counts it, the fold still lands); the continued channel opens
with the verbatim continuation message whose transcript pointer aims
at the L0 journal offset of the compaction event — a query, not a
path.

Before any message leaves the channel, the fold auditor
(memory.extractors.audit_fold) force-nodeifies every hard fact token
in the slice — the MD-2 killer: nothing can be silently forgotten
(SLO: 0 hard-fact folding loss).

The engine exposes the loop's deps slots (apply_tool_result_budget /
microcompact / autocompact); the loop NEVER changes when this module
does. The summarizer is injectable: production wires the adapter
through the guard; tests wire fakes.
"""
from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..memory.ekd import EkdBatch
from .assemble import group_message_indices, protected_boundary_of, \
    sig_sha_of
from .budget import (BudgetManager, blocks_of, chunk_messages, counter_of,
                     head_tail_truncate, is_tool_result_msg, text_of,
                     tool_result_ids)
from .compact_prompts import (
    ADDITIONAL_INSTRUCTIONS_PREFIX, BASE_COMPACT_TEMPLATE,
    CONTINUATION_AUTONOMOUS_GUARD, CONTINUATION_HEADER,
    CONTINUATION_RECENT_PRESERVED, CONTINUATION_RESUME_GUARD,
    CONTINUATION_TRANSCRIPT_POINTER, NO_TOOLS_PREAMBLE, NO_TOOLS_TRAILER,
    PARTIAL_COMPACT_TEMPLATE_FROM, PARTIAL_COMPACT_TEMPLATE_UP_TO,
)

# ─── 6.3 The assembly contract: exactly one injection seam ───────────


def _assemble(template: str, custom_instructions: str = "") -> str:
    """PREAMBLE + template + [Additional Instructions] + TRAILER, exactly
    the source assembly. The seam is the ONLY place engagement-specific
    text may enter."""
    prompt = NO_TOOLS_PREAMBLE + template
    if custom_instructions:
        prompt += (ADDITIONAL_INSTRUCTIONS_PREFIX + custom_instructions)
    return prompt + NO_TOOLS_TRAILER


def get_compact_prompt(custom_instructions: str = "") -> str:
    """The full-compaction assembly (direction base)."""
    return _assemble(BASE_COMPACT_TEMPLATE, custom_instructions)


def get_partial_compact_prompt(custom_instructions: str = "",
                               direction: str = "from") -> str:
    """The partial-compaction assembly. direction 'from': the earlier
    context is retained verbatim and only the recent tail is summarized.
    direction 'up_to': the prefix is summarized; newer messages follow."""
    if direction == "from":
        template = PARTIAL_COMPACT_TEMPLATE_FROM
    elif direction == "up_to":
        template = PARTIAL_COMPACT_TEMPLATE_UP_TO
    else:
        raise ValueError(f"unknown partial direction: {direction!r}")
    return _assemble(template, custom_instructions)


# The fixed AEGIS adaptation set (spec 6.8 + Table 10, UX-02 refresh): the
# templates are engagement-native as of UX-02, so the seam now REINFORCES
# the section population and carries the binding id-preservation rule.
# This text rides the Additional-Instructions seam on EVERY tier-3 call;
# operator focus (manual /compact) is appended after it — still the same
# single seam.
AEGIS_ADDITIONAL_INSTRUCTIONS = (
    "This is an AEGIS autonomous black-box VAPT engagement, not a coding "
    "session. Keep the summary sections populated with engagement "
    "content: section 1 carries the verbatim operator objective, scope "
    "bounds, rules of engagement and follow-up directives; section 2 the "
    "engagement technology stack, attack classes in play and tooling "
    "constraints; section 3 hosts, services, endpoints, credentials and "
    "artifacts; section 4 tool failures and recoveries plus operator "
    "feedback and course corrections; section 5 hypothesis status, "
    "exploit attempt outcomes and contradiction resolutions; section 7 "
    "the task state (running, blocked, dependencies); section 8 the "
    "active phase, active task and most recent tool actions and results."
    "\n"
    "ID PRESERVATION (binding): wherever sections 3, 5, 7 or 9 mention "
    "an engagement entity, host, service, endpoint, credential, "
    "artifact, finding, hypothesis or task, include its EKD node id "
    "next to the mention so the summary stays joinable to the knowledge "
    "graph and drilldown survives compaction. A summary that mentions a "
    "finding without its id is a review defect."
)


def engagement_focus(operator_focus: str = "") -> str:
    """The seam payload: the fixed AEGIS adaptation set, optionally with
    operator focus directives appended (manual compaction only)."""
    focus = str(operator_focus or "").strip()
    if focus:
        return AEGIS_ADDITIONAL_INSTRUCTIONS + "\nOperator focus: " + focus
    return AEGIS_ADDITIONAL_INSTRUCTIONS


# ─── 6.4 The deterministic stripper (formatCompactSummary) ───────────

_SUMMARY_BLOCK_RE = re.compile(
    r"<summary>\s*(.*?)\s*</summary>", re.DOTALL | re.IGNORECASE)
_ANALYSIS_BLOCK_RE = re.compile(
    r"<analysis>.*?</analysis>\s*", re.DOTALL | re.IGNORECASE)


def format_compact_summary(text: str) -> Tuple[str, bool]:
    """Strip the <analysis> scratchpad, rewrite the <summary> tag as a
    plain 'Summary:' header, collapse blank-line runs.

    Returns (formatted, ok). Fallback (Table 13 'summary missing the
    summary block'): when no <summary> block is present the RAW text is
    kept and ok=False — the caller journals the malformation and the
    breaker counts it; the compaction still lands (quality flagged)."""
    raw = str(text or "")
    match = _SUMMARY_BLOCK_RE.search(raw)
    if not match:
        return raw, False
    body = match.group(1)
    body = _ANALYSIS_BLOCK_RE.sub("", body)   # stray scratchpad drafts
    body = re.sub(r"\n{3,}", "\n\n", body)    # collapse blank lines
    body = body.strip("\n")
    return f"Summary:\n{body}", True


# ─── 6.5 The direction planner ────────────────────────────────────────


def plan_direction(*, window_excess: bool = False) -> str:
    """Choose 'from' vs 'up_to' at trigger time from the cache-zone
    state: 'from' when the retained prefix is the valuable cacheable
    half — the budget excess localizes INSIDE the protected window
    (recent heavy tool output), so the older window prefix survives
    byte-identical and the cache is preserved up to the summarized
    region; 'up_to' when the working window is the value and the older
    history is compressible — the normal growth fold."""
    return "from" if window_excess else "up_to"


def chunk_directions(n_chunks: int, direction: str,
                     *, prefer_base: bool = False) -> List[str]:
    """Per-chunk template selection. The fold inherits precisely the
    message range being summarized, so every chunk of a chunked fold
    runs the partial template matching the fold's structural direction;
    a single-chunk fold may run the full 'base' template (manual
    compaction — the operator asked for one consolidated summary)."""
    if n_chunks <= 0:
        return []
    if n_chunks == 1 and prefer_base:
        return ["base"]
    if n_chunks == 1:
        return [direction]
    return [direction] * n_chunks


# ─── 6.6 The continuation message (Appendix B.3, verbatim) ───────────


def build_continuation_message(formatted_summary: str, *,
                               transcript_pointer: Optional[str] = None,
                               recent_preserved: bool = True,
                               suppress_questions: bool = True,
                               autonomous: bool = True) -> str:
    """The post-compaction user-role message: the fixed header, the
    formatted summary, then the conditional blocks in template order.
    AEGIS is an autonomous engagement agent, so the resume guard and
    the autonomous variant are fixed on; the pointer is always supplied
    (the journal offset of this compaction event)."""
    parts: List[str] = [CONTINUATION_HEADER, str(formatted_summary)]
    if transcript_pointer:
        parts.append(CONTINUATION_TRANSCRIPT_POINTER.format(
            transcriptPath=transcript_pointer))
    if recent_preserved:
        parts.append(CONTINUATION_RECENT_PRESERVED)
    if suppress_questions:
        parts.append(CONTINUATION_RESUME_GUARD)
    if autonomous:
        parts.append(CONTINUATION_AUTONOMOUS_GUARD)
    return "\n\n".join(parts)


def journal_transcript_pointer(journal_dir: str, seq: int) -> str:
    """Spec 6.6: the transcript pointer aims at the L0 journal offset of
    the compaction event rather than a file path — 'the journal is
    indexed by revision, so the pointer is a query, not a path'."""
    return (f"{journal_dir} (L0 journal, compaction event seq {seq}; "
            f"query with: python3 -m hypervisor.replay {journal_dir})")


CONTINUATION_MARKER = CONTINUATION_HEADER
"""Recognition marker for prior continuation messages in the channel
(the fold replaces the previous continuation message with the new
one)."""


# ─── 6.1 The deterministic tiers ──────────────────────────────────────


def tier0_attachment_hygiene(ctx: Any) -> int:
    """Tier 0, always on: drop stale drilldown expansions from Zone T at
    each boundary. Zone T is rebuilt every turn by design (volatile
    tail), so the boundary hygiene clears the expansion store outright;
    the count is journaled when non-zero."""
    att = (ctx.extra or {}).get("tail_attachments") if ctx.extra else None
    if not isinstance(att, dict) or not att:
        return 0
    dropped = len(att)
    att.clear()
    return dropped


def tier1_trim_plan(messages: Sequence[Dict[str, Any]], *, k_reduced: int
                    ) -> Tuple[List[int], int]:
    """Deterministic window trim (tier 1): drop the oldest whole turn
    groups BEYOND THE REDUCED K — one modest reduction, never splitting
    a tool pair. messages[0] (the round objective) is never trimmed.

    Returns (drop_indices, k_final). The ladder re-checks the
    projection after the trim and escalates when the reduction alone
    did not suffice — the deterministic tiers are relief valves, not
    replacements for the fold."""
    msgs = list(messages)
    if len(msgs) < 2:
        return [], max(0, int(k_reduced))
    groups = group_message_indices(msgs)
    if len(groups) <= 1:
        return [], max(0, int(k_reduced))
    body_groups = groups[1:]          # the objective group is protected
    k = max(0, int(k_reduced))
    if len(body_groups) <= k:
        return [], min(k, len(body_groups))
    drop_groups = body_groups[:len(body_groups) - k]
    drop = [i for g in drop_groups for i in g]
    return drop, k


def tier2_stub_targets(messages: Sequence[Dict[str, Any]], *,
                       protect_from: int,
                       char_threshold: int) -> List[int]:
    """Microcompact candidates: heavy tool-result bodies strictly before
    `protect_from` (older than the protected window). Only id-bearing
    tool results can be replaced in place (same tool_use_id upserts);
    others are left for the fold. Never touches the protected window
    (C3: Zone W is append-only)."""
    out: List[int] = []
    for i, m in enumerate(messages[:max(0, int(protect_from))]):
        if not is_tool_result_msg(m):
            continue
        if not tool_result_ids(m):
            continue
        if len(text_of(m)) > int(char_threshold):
            out.append(i)
    return out


MICROCOMPACT_STUB = ("[aegis-microcompact: {tool} result, {chars} chars — "
                     "full body preserved in the EKD ({ids}) and the L0 "
                     "journal (message seq {seq})]")


def stub_body(message: Dict[str, Any], *, tool_name: str = "tool",
              ekd_ids: Sequence[str] = (),
              journal_seq: Optional[int] = None,
              template: str = MICROCOMPACT_STUB) -> str:
    """The one-line replacement body: keeps the EKD artifact refs and
    the L0 journal message seq so drilldown survives the stub."""
    ids = ", ".join(ekd_ids) if ekd_ids else "nodes for this tool_call"
    seq = journal_seq if journal_seq is not None else "see journal"
    return template.format(tool=tool_name, chars=len(text_of(message)),
                           ids=ids, seq=seq)


def stub_message(message: Dict[str, Any], stub_text: str
                 ) -> Dict[str, Any]:
    """The in-place replacement message: same tool_use ids (the upsert
    keeps pairing intact on the wire), content swapped for the stub."""
    blocks = []
    for b in blocks_of(message):
        if isinstance(b, dict) and b.get("type") == "tool_result":
            blocks.append({"type": "tool_result",
                           "tool_use_id": b.get("tool_use_id", ""),
                           "content": stub_text})
        else:
            blocks.append(b)
    out = dict(message)
    out["content"] = blocks
    return out


# ─── 6.8 The id-preservation review gate ─────────────────────────────

# Sections 3, 5, 7, 9 cover entities/artifacts, hypotheses/outcomes,
# tasks and next steps — the node types whose mentions must stay
# joinable to the EKD (spec 6.8).
ID_CHECKED_TYPES = (
    "entity", "finding", "hypothesis", "task", "artifact", "credential",
    "note",
)


def verify_id_preservation(summary: str, ekd: Any) -> List[Dict[str, str]]:
    """Review-gate check: every mention of a live EKD node of an
    id-checked type must carry the node's id somewhere in the summary.
    Returns one violation per (node, mention-without-id). Conservative
    by design: a title shorter than 4 chars is noise; titles that never
    appear are not mentions."""
    text = str(summary or "")
    low = text.lower()
    violations: List[Dict[str, str]] = []
    nodes = getattr(ekd, "nodes", None) or {}
    for node in nodes.values():
        if getattr(node, "valid_to", None) is not None:
            continue  # invalidated nodes are not part of the live graph
        if str(getattr(node, "type", "")) not in ID_CHECKED_TYPES:
            continue
        title = str(getattr(node, "title", "") or "").strip()
        if len(title) < 4:
            continue
        if title.lower() in low and str(node.id) not in text:
            violations.append({"id": str(node.id), "type": str(node.type),
                               "title": title[:80]})
    return violations


# ─── Zone W surgery record (C3: replay checks hash continuity) ──────

DROP_SIG_CAP = 40


def dropped_sig_shas(dropped: Sequence[Dict[str, Any]],
                     cap: int = DROP_SIG_CAP) -> List[str]:
    """The bounded sig-identity list the trim/compaction events carry
    (replay removes exactly these messages; drop_complete tells it
    whether the list was exhaustive or positional fallback applies)."""
    return [sig_sha_of(m) for m in list(dropped)[:max(0, int(cap))]]


# ─── the 3-failure breaker ────────────────────────────────────────────


def _env_int(name: str, default: int, floor: int = 1) -> int:
    try:
        return max(floor, int(os.environ.get(name, "") or default))
    except (TypeError, ValueError):
        return default


def breaker_threshold() -> int:
    """The consecutive-failure count that opens the breaker (spec 6.1:
    three, mirroring the verified Claude Code breaker)."""
    return _env_int("AEGIS_COMPACT_BREAKER_THRESHOLD", 3)


@dataclass
class CompactState:
    """The breaker bookkeeping the engine owns (3.7.3 rode it on the
    engagement context; 4.0 keeps it with the engine, journaled)."""
    failures: int = 0
    breaker_open: bool = False

    def record_failure(self, journal: Any, detail: str = ""
                       ) -> Dict[str, Any]:
        """Count one compaction failure; at the threshold, open the
        breaker (auto-compaction disabled, deterministic tiers carry
        the load)."""
        self.failures += 1
        threshold = breaker_threshold()
        action = "counted"
        if self.failures >= threshold and not self.breaker_open:
            self.breaker_open = True
            action = "open"
        self._journal(journal, action, detail)
        return {"action": action, "failures": self.failures,
                "open": self.breaker_open}

    def record_success(self, journal: Any, *, actor: str = "system"
                       ) -> None:
        """A compaction success clears the failure streak and re-closes
        an open breaker (three CONSECUTIVE failures open it)."""
        had = self.failures
        self.failures = 0
        if self.breaker_open or had:
            self.breaker_open = False
            self._journal(journal, "reset", "", actor=actor)

    def note_override(self, journal: Any) -> None:
        """Manual compaction on operator command bypasses the breaker
        but journals the override."""
        self._journal(journal, "override",
                      "manual compaction bypassed the breaker",
                      actor="operator")

    def _journal(self, journal: Any, action: str, detail: str,
                 *, actor: str = "system") -> None:
        if journal is None:
            return
        try:
            journal.record_compaction_breaker(
                action, failures=self.failures,
                detail=detail[:200], actor=actor)
        except Exception:
            pass  # J4


# ─── the engine (the loop's deps slots) ───────────────────────────────

Summarizer = Callable[[List[Dict[str, Any]], int], Any]
# async (messages, max_tokens) -> str ; production routes through the
# guard on the adapter (purpose='compact'); tests inject fakes.


class CompactEngine:
    """The pre-flight compaction engine. The loop calls:

        msgs = deps.apply_tool_result_budget(msgs)     # step 2 (B2 cap)
        msgs = await deps.microcompact(msgs, ctx)      # step 3 (tier 2)
        msgs, folded = await deps.autocompact(msgs, ctx)  # steps 4-5

    Every method is a no-op pass-through when the thresholds say so;
    every sanctioned rewrite is journaled (compaction_trim /
    compaction events with dropped_sig_shas + replaces pairing)."""

    def __init__(self, budget: BudgetManager, *,
                 summarizer: Optional[Summarizer] = None,
                 k_pairs: int = 8,
                 protect_groups: Optional[int] = None,
                 compact_max_tokens: Optional[int] = None):
        self.budget = budget
        self.summarizer = summarizer
        self.k_pairs = max(2, int(k_pairs))
        # The protected recent window (whole conversation groups).
        # Degrades automatically inside the fold when the channel is too
        # short to fold anything at full protection (the E2E lesson: a
        # blanket protection with a short channel leaves the ladder
        # nothing to shrink and the loop walks into the blocking limit).
        self.protect_groups = max(1, int(
            protect_groups if protect_groups is not None else
            _env_int("AEGIS_PROTECT_GROUPS", 6, floor=1)))
        self.state = CompactState()
        self.compact_max_tokens = compact_max_tokens or min(
            16384, max(1024, budget.window // 8))
        self._counter = counter_of(budget)

    # ------------------------------------------------------ step 2 (B2)
    def apply_tool_result_budget(self, messages: List[Dict[str, Any]],
                                 ctx: Any = None
                                 ) -> List[Dict[str, Any]]:
        """The always-on per-tool-result cap cascade: tool-result bodies
        older than the protected window are char-capped head+tail (the
        tail is where evidence, hashes and session tokens live). P1's
        render_capped already bounds FRESH results at tool time; this
        step bounds the accumulated history the loop carries."""
        msgs = list(messages)
        if len(msgs) < 3:
            return msgs
        cap = self.budget.per_message_char_cap()
        protect_from = protected_boundary_of(
            msgs, protect_groups=self.protect_groups)
        stubbed = 0
        replaces: List[str] = []
        stub_pairs: List[tuple] = []
        out: List[Dict[str, Any]] = []
        for i, m in enumerate(msgs):
            if i >= protect_from or not is_tool_result_msg(m):
                out.append(m)
                continue
            blocks = blocks_of(m)
            heavy = any(isinstance(b, dict) and b.get("type") == "tool_result"
                        and len(str(b.get("content", ""))) > cap
                        for b in blocks)
            if not heavy:
                out.append(m)
                continue
            orig_sha = sig_sha_of(m)
            replaces.append(orig_sha)
            new_blocks = []
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "tool_result" \
                        and len(str(b.get("content", ""))) > cap:
                    new_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": b.get("tool_use_id", ""),
                        "content": head_tail_truncate(
                            str(b.get("content", "")), cap)})
                else:
                    new_blocks.append(b)
            nm = dict(m)
            nm["content"] = new_blocks
            out.append(nm)
            stub_pairs.append((orig_sha, nm))
            stubbed += 1
        if stubbed and ctx is not None and getattr(ctx, "journal", None):
            try:
                ctx.journal.record_compaction_trim(
                    2, stubbed=stubbed, replaces=replaces,
                    tokens_before=self._counter(msgs),
                    tokens_after=self._counter(out),
                    reason="tool_result_budget")
                # PORT-06: the stub message events Zone W replay swaps
                # in place (replaces = the original sig sha)
                from ..context.assemble import journal_channel_message
                for orig_sha, nm in stub_pairs:
                    journal_channel_message(
                        ctx.journal, nm, source="microcompact",
                        replaces=orig_sha)
            except Exception:
                pass
        return out

    # ------------------------------------------------------ step 3 (t2)
    async def microcompact(self, messages: List[Dict[str, Any]], ctx: Any
                           ) -> List[Dict[str, Any]]:
        """Tier 2: replace heavy pre-window tool-result bodies with the
        one-line EKD-ref stub (fires below the fold trigger — cheap
        relief before the expensive fold)."""
        msgs = list(messages)
        if not self.budget.should_microcompact(msgs):
            return msgs
        protect_from = protected_boundary_of(
            msgs, protect_groups=self.protect_groups)
        targets = tier2_stub_targets(
            msgs, protect_from=protect_from,
            char_threshold=self.budget.per_message_char_cap())
        if not targets:
            return msgs
        call_map = (ctx.extra or {}).get("ekd_call_ids") if ctx.extra \
            else None
        replaces: List[str] = []
        stub_pairs: List[tuple] = []
        out = list(msgs)
        for i in targets:
            m = msgs[i]
            orig_sha = sig_sha_of(m)
            replaces.append(orig_sha)
            ekd_refs = []
            for tid in tool_result_ids(m):
                if isinstance(call_map, dict) and tid in call_map:
                    ekd_refs.append(str(call_map[tid]))
            # the producing tool's name: from the paired tool_use block
            tool_name = "tool"
            for b in blocks_of(m):
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tool_name = str(b.get("name", tool_name))
                    break
            out[i] = stub_message(
                m, stub_body(m, tool_name=tool_name, ekd_ids=ekd_refs))
            stub_pairs.append((orig_sha, out[i]))
        if getattr(ctx, "journal", None) is not None:
            try:
                ctx.journal.record_compaction_trim(
                    2, stubbed=len(targets), replaces=replaces,
                    tokens_before=self._counter(msgs),
                    tokens_after=self._counter(out),
                    reason="microcompact")
                # PORT-06: stub message events (replaces = orig sha)
                from ..context.assemble import journal_channel_message
                for orig_sha, nm in stub_pairs:
                    journal_channel_message(
                        ctx.journal, nm, source="microcompact",
                        replaces=orig_sha)
            except Exception:
                pass
        return out

    # ------------------------------------------------- steps 4-5 (fold)
    async def autocompact(self, messages: List[Dict[str, Any]], ctx: Any
                          ) -> Tuple[List[Dict[str, Any]], bool]:
        """The ladder proper. Returns (messages, folded) — folded=True
        when a sanctioned state rewrite happened (the loop journals the
        autocompact transition)."""
        msgs = list(messages)
        if not self.budget.should_compress(msgs):
            return msgs, False

        # ── tier 0: attachment hygiene (always, before anything) ──
        dropped_att = tier0_attachment_hygiene(ctx)
        if dropped_att and getattr(ctx, "journal", None) is not None:
            try:
                ctx.journal.record_compaction_trim(
                    0, dropped=dropped_att, reason="attachment_hygiene")
            except Exception:
                pass

        # ── tier 1: window trim beyond the reduced K ──────────────
        msgs, trimmed = self._tier1_trim(msgs, ctx)
        folded = trimmed or dropped_att > 0

        if not self.budget.should_compress(msgs):
            return msgs, folded

        # ── breaker open: deterministic tiers carry the load ──────
        if self.state.breaker_open or self.summarizer is None:
            msgs2, trimmed2 = self._tier1_trim(
                msgs, ctx, k_reduced=max(2, self.k_pairs // 4),
                reason="breaker_open_deterministic_relief")
            return msgs2, folded or trimmed2

        # ── tier 3: the fold ──────────────────────────────────────
        try:
            folded_msgs, ok = await self._fold(msgs, ctx)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {str(exc)[:180]}"
            self.state.record_failure(getattr(ctx, "journal", None), detail)
            # deterministic relief so the channel still shrinks
            msgs2, trimmed2 = self._tier1_trim(
                msgs, ctx, k_reduced=max(2, self.k_pairs // 4),
                reason="fold_failed_deterministic_relief")
            return msgs2, folded or trimmed2
        if ok:
            self.state.record_success(getattr(ctx, "journal", None))
            return folded_msgs, True
        return folded_msgs if folded_msgs is not msgs else msgs, folded

    # ------------------------------------------------------ tier 1
    def _tier1_trim(self, msgs: List[Dict[str, Any]], ctx: Any,
                    *, k_reduced: Optional[int] = None,
                    reason: str = "window_trim"
                    ) -> Tuple[List[Dict[str, Any]], bool]:
        k = k_reduced if k_reduced is not None else \
            max(2, self.k_pairs // 2)
        drop, _k = tier1_trim_plan(msgs, k_reduced=k)
        if not drop:
            return msgs, False
        drop_set = set(drop)
        dropped_msgs = [msgs[i] for i in drop]
        out = [m for i, m in enumerate(msgs) if i not in drop_set]
        if getattr(ctx, "journal", None) is not None:
            try:
                ctx.journal.record_compaction_trim(
                    1, dropped=len(drop),
                    sig_shas=dropped_sig_shas(dropped_msgs),
                    tokens_before=self._counter(msgs),
                    tokens_after=self._counter(out),
                    reason=reason)
            except Exception:
                pass
        return out, True

    # ------------------------------------------------------ tier 3
    async def _fold(self, msgs: List[Dict[str, Any]],
                    ctx: Any) -> Tuple[List[Dict[str, Any]], bool]:
        journal = getattr(ctx, "journal", None)
        ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
        session = (ctx.extra or {}).get("session") if ctx.extra else None

        # protection degradation: with a short channel, full protection
        # leaves nothing foldable (boundary <= 1) — halve the protected
        # window until a fold range exists. The most recent group is
        # ALWAYS protected (the turn the model is answering into).
        pg = self.protect_groups
        boundary = protected_boundary_of(msgs, protect_groups=pg)
        while boundary <= 1 and pg > 1:
            pg = max(1, pg // 2)
            boundary = protected_boundary_of(msgs, protect_groups=pg)

        # direction planning (6.5): does the excess live INSIDE the
        # protected window (recent heavy tool output) or in the older
        # history (normal growth)?
        prot_tokens = self._counter(msgs[boundary:])
        window_excess = prot_tokens > self.budget.target
        direction = plan_direction(window_excess=window_excess)

        if direction == "up_to":
            fold_slice = msgs[1:boundary]
            kept_head = [msgs[0]]
            tail = msgs[boundary:]
        else:  # "from": summarize the older half of the protected
            # window; the newest groups stay verbatim
            half = max(1, pg // 2)
            from_split = protected_boundary_of(msgs, protect_groups=half)
            fold_slice = msgs[boundary:from_split] or msgs[1:boundary]
            if fold_slice and fold_slice[0] is msgs[boundary] \
                    and boundary > 1:
                kept_head = msgs[:boundary]
                tail = msgs[from_split:]
                direction = "from"
            else:
                fold_slice = msgs[1:boundary]
                kept_head = [msgs[0]]
                tail = msgs[boundary:]
                direction = "up_to"
        if not fold_slice:
            return msgs, False

        # the fold auditor (MD-2 killer): every hard fact token in the
        # slice becomes a graph node BEFORE the slice may be dropped
        if ekd is not None:
            with EkdBatch(ekd, ctx, extractor="fold_audit",
                          reason="tier3_fold"):
                from ..memory.extractors import audit_fold
                audit_report = audit_fold(
                    ekd, [text_of(m) for m in fold_slice],
                    provenance=[(ctx.extra or {}).get("objective_id")]
                    if ctx.extra else None)

        # chunking so each summarizer call fits the window
        chunks = chunk_messages(fold_slice, self.budget.chunk_budget,
                                self._counter)
        if not chunks:
            return msgs, False
        directions = chunk_directions(len(chunks), direction)

        prev_summary = ((ctx.extra or {}).get("episodic_residual")
                        if ctx.extra else "") or ""

        # progressive summarization: chunk i inherits the running
        # summary; the raw text lands in <analysis>/<summary>
        summary_raw = prev_summary
        ok_all = True
        for chunk, chunk_dir in zip(chunks, directions):
            if chunk_dir == "base":
                system = get_compact_prompt(engagement_focus())
            else:
                system = get_partial_compact_prompt(engagement_focus(),
                                                    direction=chunk_dir)
            call_messages: List[Dict[str, Any]] = [
                {"role": "system", "content": system}]
            if summary_raw and summary_raw != "No previous summary.":
                call_messages.append({
                    "role": "user",
                    "content": "[Summary of the earlier context so far — "
                               "carry its facts forward into your "
                               "summary]\n" + summary_raw})
            call_messages.extend(self._cap_for_call(chunk))
            summary_raw = await self.summarizer(call_messages,
                                                self.compact_max_tokens)
            if not str(summary_raw or "").strip():
                raise RuntimeError("summarizer returned empty output")

        formatted, ok = format_compact_summary(str(summary_raw))
        ok_all = ok
        if not ok:
            # malformation: breaker counts it, the fold still lands
            self.state.record_failure(
                journal, "summary missing the <summary> block "
                         "(raw text kept, quality flagged)")

        # id-preservation review gate
        id_violations: Optional[int] = None
        if ekd is not None:
            id_violations = len(verify_id_preservation(formatted, ekd))

        # the new channel: kept head + continuation + protected tail
        ev = None
        if journal is not None:
            try:
                import hashlib as _hl
                summary_hash = _hl.sha256(
                    formatted.encode("utf-8", "ignore")).hexdigest()[:16]
                ev = journal.record_compaction(
                    formatted,
                    messages_dropped=len(fold_slice),
                    summary_hash=summary_hash,
                    rev=getattr(ekd, "rev", None),
                    direction=direction,
                    tier=3,
                    chunks=len(chunks),
                    dropped_sig_shas=dropped_sig_shas(fold_slice),
                    drop_position="head_after_objective"
                    if direction == "up_to" else "mid_before_newest",
                    recent_preserved=bool(tail),
                    id_violations=id_violations,
                    breaker_open=self.state.breaker_open)
            except Exception:
                pass

        seq = int((ev or {}).get("seq", 0)) if ev else 0
        pointer = None
        if journal is not None:
            jdir = str(getattr(journal, "path", "") or "journal")
            pointer = journal_transcript_pointer(jdir, seq)
        continuation = {
            "role": "user",
            "content": build_continuation_message(formatted,
                                                  transcript_pointer=pointer)}
        new_msgs = list(kept_head) + [continuation] + list(tail)

        # PORT-06: the continuation message event — replay inserts it
        # at the fold's first-drop position, reconstructing
        # [head, continuation, tail] exactly as the fold built it
        if journal is not None:
            try:
                from ..context.assemble import journal_channel_message
                journal_channel_message(journal, continuation,
                                        source="compaction")
            except Exception:
                pass

        # the residual feeds the brief (PORT-11's RESIDUAL NOTES)
        if ctx.extra is not None:
            ctx.extra["episodic_residual"] = formatted
        if session is not None:
            try:
                # logical parent: the chain head BEFORE the summary
                # record — the transcript's logical order survives the
                # fold (physical parent stays the last record)
                logical = session.chain_head() \
                    if hasattr(session, "chain_head") else None
                session.append_summary(formatted,
                                       logical_parent=logical)
            except Exception:
                pass
        return new_msgs, True

    def _cap_for_call(self, chunk: List[Dict[str, Any]]
                      ) -> List[Dict[str, Any]]:
        """Call-side (never state-side) cap: giant tool-result bodies in
        the summarizer input are head+tail truncated so a single
        oversized message cannot blow the fold call."""
        cap = self.budget.per_message_char_cap() * 4
        out = []
        for m in chunk:
            if not is_tool_result_msg(m):
                out.append(m)
                continue
            if len(text_of(m)) <= cap:
                out.append(m)
                continue
            blocks = []
            for b in blocks_of(m):
                if isinstance(b, dict) and b.get("type") == "tool_result" \
                        and len(str(b.get("content", ""))) > cap:
                    blocks.append({
                        "type": "tool_result",
                        "tool_use_id": b.get("tool_use_id", ""),
                        "content": head_tail_truncate(
                            str(b.get("content", "")), cap)})
                else:
                    blocks.append(b)
            nm = dict(m)
            nm["content"] = blocks
            out.append(nm)
        return out


# ─── production summarizer (adapter + guard, purpose='compact') ──────


def make_summarizer(adapter: Any, guard: Any = None) -> Summarizer:
    """Route fold calls through the guard (no call site may bypass it)
    on the OpenAI-compatible adapter: single-turn, NO tools, own
    breaker lane ('compact')."""

    async def _summarizer(messages: List[Dict[str, Any]],
                          max_tokens: int) -> str:
        async def _factory():
            async for c in adapter.stream_chat(
                    messages=messages, tools=None, max_tokens=max_tokens):
                yield c

        parts: List[str] = []

        async def _collect(aiter):
            async for c in aiter:
                if c.kind == "text" and c.text:
                    parts.append(c.text)
            return "".join(parts)

        if guard is not None:
            # stream through the guard; collect the visible text
            async def _run():
                async for c in guard.call_stream(
                        _factory, purpose="compact",
                        model=getattr(adapter, "model", ""),
                        turn=-1, messages=messages):
                    if c.kind == "text" and c.text:
                        parts.append(c.text)
                return "".join(parts)
            return await _run()
        return await _collect(_factory())

    return _summarizer
