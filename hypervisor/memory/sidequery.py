"""hypervisor.memory.sidequery — the L3 pre-expansion selector (P3,
REFACTOR-04).

The 3.7.3 side_query (src/core/side_query.py, 429 ln) re-hosted as a
loop-owned PRE-ASSEMBLY step: at turn assembly, when the brief alone is
judged insufficient, one cheap guard-bounded model side call receives
the current turn text, the brief section index (ids + one-line
descriptions) and the already-surfaced set, and returns at most five
entity ids to pre-expand into Zone T tail attachments — an explicit,
journaled side call instead of 3.7's hidden mesh path.

Contract bullets (the CC findRelevantMemories adaptation, verbatim in
intent):
  * be selective and discerning — only ids that will clearly help;
  * return empty when unsure (an empty selection is valid);
  * never re-pick already-surfaced entities — the candidate list is
    filtered BEFORE the call (the selector spends its 5-slot budget on
    fresh candidates) and a deterministic post-filter drops
    surfaced/unknown ids whatever the model answered.

Prompt position (the measured 2.79% lesson): the no-tools constraint
LEADS the selector prompt and states its failure consequence; a trailer
reinforces it — a constrained single-shot side-call exactly like the
summarizer.

Budget-gated and skippable (spec 3.5): NOT run when the brief revision
is unchanged AND the current turn introduces no new entities; skipped
entirely on any selector failure with a journaled health flag. L3 is a
strict optimization layer: engagement correctness never depends on it —
the model can always call memory_query itself within a turn (J4
discipline: the selector NEVER gates assembly).
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ─── the selector prompt (preamble-first, consequence-explicit) ──────
# Verbatim from 3.7.3 core/side_query.py L48-86 (a direct adaptation of
# the CC source selector; the texts are frozen anchor material).

SELECTOR_NO_TOOLS_PREAMBLE = (
    "CRITICAL: Respond with TEXT ONLY. Do NOT call any tools.\n"
    "\n"
    "- Do NOT use any tool. This is a single side-call, not a task.\n"
    "- Tool calls will be REJECTED and will waste your only turn — you "
    "will fail the task.\n"
    "- Your entire response must be plain text: entity ids, one per "
    "line, nothing else.\n"
    "\n"
)

SELECTOR_SYSTEM_PROMPT = (
    SELECTOR_NO_TOOLS_PREAMBLE
    + "You are selecting engagement-knowledge entries that will be "
    "useful to the AEGIS main loop as it processes the current turn. "
    "You will be given the current turn text, an index of engagement "
    "entries (ids with one-line descriptions), and the set of ids "
    "already surfaced to the model in earlier turns.\n"
    "\n"
    "Return a list of ids for the entries that will clearly be useful "
    "to the main loop as it processes the current turn (up to 5). Only "
    "include entries that you are certain will be helpful based on "
    "their id and description.\n"
    "- If you are unsure whether an entry will be useful in processing "
    "the current turn, then do not include it in your list. Be "
    "selective and discerning.\n"
    "- If there are no entries in the index that would clearly be "
    "useful, feel free to return an empty list.\n"
    "- Do not re-pick entries from the already-surfaced set: the model "
    "has already seen their full detail; re-expanding them wastes the "
    "budget.\n"
    "\n"
    "Output format: one id per line, at most 5 lines, no prose. An "
    "empty response (zero lines) is a valid, expected answer.\n"
    "\n"
    "REMINDER: Do NOT call any tools. Respond with plain text only — "
    "one id per line, at most 5, or nothing. Tool calls will be "
    "rejected and you will fail the task."
)

SELECTOR_MAX_TURN_CHARS = 2000

try:
    SIDEQUERY_TIMEOUT_S = max(1.0, float(os.environ.get(
        "AEGIS_SIDEQUERY_TIMEOUT_S", "") or 30.0))
except ValueError:
    SIDEQUERY_TIMEOUT_S = 30.0
try:
    SIDEQUERY_MAX_ENTITIES = max(1, int(os.environ.get(
        "AEGIS_SIDEQUERY_MAX_ENTITIES", "") or 5))
except ValueError:
    SIDEQUERY_MAX_ENTITIES = 5
try:
    EXPANSION_CHAR_CAP = max(200, int(os.environ.get(
        "AEGIS_EXPANSION_CHAR_CAP", "") or 3990))
except ValueError:
    EXPANSION_CHAR_CAP = 3990
try:
    SIDEQUERY_INDEX_CAP = max(1, int(os.environ.get(
        "AEGIS_SIDEQUERY_INDEX_CAP", "") or 40))
except ValueError:
    SIDEQUERY_INDEX_CAP = 40


def selector_user_message(current_turn_text: str,
                          index_lines: Sequence[str],
                          surfaced_lines: Sequence[str]) -> str:
    """The selector's single user message (the source's shape:
    `Current turn:` + the index manifest + the surfaced list)."""
    turn = (current_turn_text or "").strip()
    if len(turn) > SELECTOR_MAX_TURN_CHARS:
        turn = turn[:SELECTOR_MAX_TURN_CHARS]
    parts = [f"Current turn:\n{turn}" if turn else "Current turn: (empty)"]
    parts.append("Engagement entry index:\n"
                 + ("\n".join(index_lines) if index_lines else "(empty)"))
    parts.append("Already surfaced (do not re-pick):\n"
                 + ("\n".join(surfaced_lines) if surfaced_lines
                    else "(none)"))
    return "\n\n".join(parts)


# ─── the brief section index (ids + one-line descriptions) ────────────

def brief_section_index(ekd: Any, cap: int = SIDEQUERY_INDEX_CAP
                        ) -> List[Dict[str, str]]:
    """The selector's candidate index: the ids the brief can surface —
    current entities, findings and hypotheses — one line each, ordered
    by insertion, capped to bound the side-call size. Already-surfaced
    ids are EXCLUDED by the caller (the source filters before the
    call)."""
    out: List[Dict[str, str]] = []
    for ntype in ("entity", "finding", "hypothesis"):
        for n in ekd.nodes_of_type(ntype):
            out.append({"id": n.id, "type": n.type,
                        "line": _index_line(n)})
    return out[:max(1, int(cap))]


def _index_line(n: Any) -> str:
    desc = str(n.title or "")[:100]
    sub = f"/{n.subtype}" if getattr(n, "subtype", "") else ""
    return f"{n.id} ({n.type}{sub}): {desc}"


# ─── deterministic new-entity detection (the gate's second input) ────

_ID_RE = re.compile(r"\b([a-zA-Z]{1,3}\d{1,5})\b")


def detect_new_entities(current_turn_text: str, ekd: Any,
                        surfaced: Optional[Dict[str, Any]] = None
                        ) -> List[str]:
    """Deterministically detect EKD entities the current turn
    INTRODUCES (mentions that are not already surfaced): id mentions
    (h1, F3), canonical-key values (10.10.5.14, target.example.com)
    and title mentions, resolved to node ids. This feeds the spec-3.5
    gate ("the current turn introduces no new entities") without an
    LLM call."""
    text = str(current_turn_text or "")
    surfaced = surfaced or {}
    mentioned: List[Any] = []
    # 1. direct id mentions
    id_mentions = {m.group(1) for m in _ID_RE.finditer(text)}
    for n in ekd.nodes_of_type("entity"):
        if n.id in id_mentions and n.id not in surfaced:
            mentioned.append(n)
    # 2. key-value / title mentions (hosts, domains, endpoints...)
    for n in ekd.nodes_of_type("entity"):
        if n.id in surfaced or any(m.id == n.id for m in mentioned):
            continue
        probes = []
        if getattr(n, "key", ""):
            probes.append(str(n.key).split(":", 1)[-1])
        if n.title:
            probes.append(str(n.title))
        for p in probes:
            if len(p) >= 4 and p in text:
                mentioned.append(n)
                break
    return [n.id for n in mentioned]


# ─── the gate (spec 3.5: budget-gated and skippable) ──────────────────

def selector_gate(*, revision_changed: bool,
                  new_entities: Sequence[str],
                  candidates: int) -> Tuple[bool, str]:
    """Run the selector only when it can add information: NOT run when
    the brief revision is unchanged AND the current turn introduces no
    new entities; not run with no fresh candidates (the surfaced set
    covers the index). Returns (run, reason) — `reason` names the skip
    for the journal/health surface."""
    if not (revision_changed or new_entities):
        return False, "revision unchanged and no new entities"
    if candidates <= 0:
        return False, "no unsurfaced candidates in the index"
    return True, ("revision bump" if revision_changed
                  else "new entities in the current turn")


# ─── output parsing (trust but enforce — the source's post-filter) ───

def parse_selector_output(text: str, valid_ids: Sequence[str],
                          surfaced: Optional[Dict[str, Any]] = None,
                          cap: int = SIDEQUERY_MAX_ENTITIES
                          ) -> List[str]:
    """Deterministically post-filter the selector's answer: keep only
    ids that exist in the offered index, drop already-surfaced ids and
    duplicates, preserve order, cap at `cap` (the hard 5). The model's
    raw list is advisory; the contract is enforced here."""
    valid = list(valid_ids)
    seen_surfaced = set((surfaced or {}).keys())
    out: List[str] = []
    for tok in re.findall(r"[A-Za-z]{1,3}\d{1,5}", str(text or "")):
        if tok in valid and tok not in seen_surfaced and tok not in out:
            out.append(tok)
            if len(out) >= max(1, int(cap)):
                break
    return out


# ─── expansion building (Zone T attachments, capped AT INJECTION) ────

def expand_entities(ekd: Any, ids: Sequence[str],
                    char_cap: int = EXPANSION_CHAR_CAP
                    ) -> List[Dict[str, Any]]:
    """Pre-expand selected ids into Zone T attachment payloads: the
    node detail render, hard-capped AT INJECTION (the cap is part of
    the contract, deterministic — the journal records the sha of the
    capped text, so replay sees exactly what the model received)."""
    from .brief import render_node_detail
    out: List[Dict[str, Any]] = []
    for eid in ids:
        node = ekd.get(str(eid))
        if node is None:
            continue
        text = render_node_detail(ekd, node.id, max_chars=int(char_cap))
        if len(text) > int(char_cap):
            text = text[:int(char_cap)]
        out.append({"id": node.id, "text": text,
                    "sha": _sha16(text), "chars": len(text)})
    return out


def _sha16(text: str) -> str:
    import hashlib
    return hashlib.sha256(
        text.encode("utf-8", "ignore")).hexdigest()[:16]


def write_expansions(ctx: Any, expansions: Sequence[Dict[str, Any]],
                     ts: Optional[float] = None) -> int:
    """Land the expansions in the Zone T tail-attachment store and mark
    them surfaced for the engagement (CC session-lifetime
    already-surfaced semantics: the volatile STORE is cleared at
    compaction boundaries by tier-0 hygiene, the SET never re-picks)."""
    att = ((ctx.extra or {}).get("tail_attachments")
           if getattr(ctx, "extra", None) else None)
    surfaced = ((ctx.extra or {}).get("side_query_surfaced")
                if getattr(ctx, "extra", None) else None)
    now = float(ts if ts is not None else time.time())
    n = 0
    for e in expansions:
        if isinstance(att, dict):
            att[e["id"]] = {"id": e["id"], "text": e["text"],
                            "sha": e["sha"], "chars": e["chars"],
                            "ts": now}
        if isinstance(surfaced, dict):
            surfaced.setdefault(e["id"], now)
        n += 1
    return n


# ─── the engine (loop pre-assembly step; never gates assembly) ────────

def current_turn_text(messages: Sequence[Dict[str, Any]]) -> str:
    """The current turn's text for the selector: the last user-role
    message content in the channel (tool-result carriers and meta
    continuations excluded — the selector reads what the model is about
    to answer, not the machinery)."""
    for m in reversed(list(messages)):
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, str):
            if c.startswith("This session is being continued"):
                continue        # the fold's continuation marker
            return c
        if isinstance(c, list):
            texts = [str(b.get("text", "")) for b in c
                     if isinstance(b, dict) and b.get("type") == "text"]
            if texts:
                return "\n".join(texts)
    return ""


class SideQueryEngine:
    """One pre-expansion evaluation per turn assembly (Table 4 step 4).
    Holds the adapter/guard (the side call routes through the guard —
    no call site bypasses it) and the last-seen revision (the gate's
    first input). Injected as ProductionDeps.side_query; the loop calls
    it between the blocking gate and zone assembly, and ANY failure
    degrades to 'brief alone' — journaled, never raised (J4)."""

    def __init__(self, adapter: Any, guard: Any = None, *,
                 journal: Any = None):
        self.adapter = adapter
        self.guard = guard
        self.journal = journal
        self.last_rev: Optional[int] = None
        self.runs = 0
        self.skips = 0
        self.failures = 0
        self.expansions_written = 0

    # ------------------------------------------------------------ main

    async def __call__(self, messages: List[Dict[str, Any]],
                       ctx: Any) -> List[str]:
        try:
            return await self._run(messages, ctx)
        except Exception as exc:
            # the outer net: NOTHING here may gate assembly
            self.failures += 1
            if self.journal is not None:
                try:
                    self.journal.record_side_query(
                        failed=f"orchestration error: {str(exc)[:150]}")
                except Exception:
                    pass
            return []

    async def _run(self, messages: List[Dict[str, Any]],
                   ctx: Any) -> List[str]:
        ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
        if ekd is None:
            return []
        extra = ctx.extra or {}
        surfaced = extra.get("side_query_surfaced") or {}
        rev = int(getattr(ekd, "rev", 0) or 0)
        revision_changed = (self.last_rev is None
                            or rev != self.last_rev)
        self.last_rev = rev

        turn_text = current_turn_text(messages)
        index = [e for e in brief_section_index(ekd)
                 if e["id"] not in surfaced]
        new_entities = detect_new_entities(turn_text, ekd, surfaced)
        run, reason = selector_gate(
            revision_changed=revision_changed,
            new_entities=new_entities,
            candidates=len(index))
        if not run:
            self.skips += 1
            if self.journal is not None:
                self.journal.record_side_query(
                    trigger=reason, ekd_rev=rev,
                    candidates=len(index), skipped=reason,
                    surfaced=list(surfaced.keys())[:40])
            return []

        user_msg = selector_user_message(
            turn_text, [e["line"] for e in index],
            list(surfaced.keys())[:40])
        prompt = [
            {"role": "system", "content": SELECTOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]
        raw = await self._selector_call(prompt)
        if raw is None:
            # failure already journaled by _selector_call
            return []

        selected = parse_selector_output(
            raw, [e["id"] for e in index], surfaced)
        expansions = expand_entities(ekd, selected)
        written = write_expansions(ctx, expansions)
        self.runs += 1
        self.expansions_written += written
        if self.journal is not None:
            self.journal.record_side_query(
                trigger=reason, ekd_rev=rev, candidates=len(index),
                model=str(getattr(self.adapter, "model", "")),
                selected=selected, expansions=expansions,
                surfaced=list((extra.get("side_query_surfaced")
                               or {}).keys())[:40])
        return [e["id"] for e in expansions]

    async def _selector_call(self, prompt: List[Dict[str, Any]]
                             ) -> Optional[str]:
        """One bounded no-tools side call through the guard. Returns
        the visible text, or None on any failure (journaled — the
        Table-13 health flag)."""
        async def _factory():
            async for c in self.adapter.stream_chat(
                    messages=prompt, tools=None, max_tokens=256):
                yield c

        async def _collect() -> str:
            parts: List[str] = []
            stream: Any = _factory()
            if self.guard is not None:
                stream = self.guard.call_stream(
                    _factory, purpose="sidequery",
                    model=str(getattr(self.adapter, "model", "")),
                    turn=-1, messages=prompt)
            async for c in stream:
                if c.kind == "text" and c.text:
                    parts.append(c.text)
            return "".join(parts)

        try:
            try:
                return await asyncio.wait_for(
                    _collect(), timeout=SIDEQUERY_TIMEOUT_S)
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"selector exceeded {SIDEQUERY_TIMEOUT_S:.0f}s")
            # NOTE: CancelledError (BaseException) propagates — the
            # abort path stays clean; only failures degrade to None.
        except Exception as exc:
            # 2026-10-06 hardening: name the failure class explicitly —
            # a bare str() of a TimeoutError is '' and the live run
            # logged "selector failed ()" five times with no clue.
            name = type(exc).__name__
            detail = str(exc).strip()
            reason = name + (f": {detail}" if detail else "")
            self.failures += 1
            if self.journal is not None:
                self.journal.record_side_query(
                    failed=f"selector error: {reason[:150]}")
            return None
