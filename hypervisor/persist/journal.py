"""Hypervisor-4.0 engagement journal — PORT of 3.7.3 src/journal.py (P0).

Port card: docs/port-cards/PORT-05-journal.md.

Append-only JSONL event stream, the lossless ground truth every working
context is derived from. Contracts preserved verbatim from 3.7.3:

  J1 write-ahead: journal entries precede the durable state change they
     describe. Callers append BEFORE the state write (ekd_mutation carries
     the rev the write will carry); a crash between journal and state is
     detectable by replay (journal rev N with no state rev N) and repairable.
  J2 revision carriage: entries carry the revision they produced or
     observed, so any brief ever rendered is reconstructible from the
     journal alone (rev + budget + pinned now -> byte-identical brief).
  J3 never compacted: disk is cheaper than silent loss; export tooling
     owns external compression.
  J4 never a gate: journal write failure must never block the loop —
     failed entries queue for retry, a health flag surfaces the gap, and
     the recorder stays a recorder.

Carried forward byte-for-byte in behavior (frozen by years of journaled
production data — changing any of these silently breaks replay):
  * message_sig formula (window hashes were computed with exactly it)
  * event field order and clamp semantics (_clamp_data / MAX_DATA_CHARS)
  * B1 resume continuation (_scan_tail: seq/turn/rev continue, not restart)
  * M5 torn-tail visibility (health().torn_tail_lines)
  * H8 opportunistic retry drain at append() head
  * sidecar discipline: content-derived names, sidecar-then-event ordering,
    0o600 + fsync, refs over blobs (messages/ compaction/ objective/
    prompts/ briefs/)

4.0 deltas (schema v2):
  * SCHEMA_VERSION 2; readers accept v1 and v2. Every v1 event type keeps
    its name and shape — 3.7.3 journals replay unchanged.
  * New event types for the loop control plane: loop_transition (explicit
    query-loop state machine moves), permission_decision (scope-gate audit
    record — in 4.0 every allow is journaled; deny-by-default), and
    turn_watchdog (the duration bound on one loop iteration).
  * config accesses that reached into the 3.x flat `config` module are now
    env-driven module constants (AEGIS_JOURNAL_PROMPTS / _PROMPT_CAP) —
    stdlib-only, no app-config import, same defaults.
  * the 3.7.3 self-import `from journal import sig_sha` inside
    record_llm_prompt was dead code (imported, never called) — dropped.

Importable with zero dependencies beyond stdlib, exactly like the 3.7.3
original. The aegis_debug journal tap (hypervisor/debug/patcher.py) mirrors
every append into the unified timeline, same as 3.7.

Event schema (v2), one JSON object per line:
  {"v": 2, "seq": <int, monotonic per journal>, "ts": <unix float>,
   "type": <one of EVENT_TYPES>, "turn": <int or null>,
   "actor": <str or null>, "rev": <ekd revision or null>,
   "data": {...}}
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

SCHEMA_VERSION = 2

# The Phase-0 event vocabulary, verbatim from 3.7.3 (names are frozen —
# oracle replay and export tooling match on them).
EVENT_TYPES = (
    "boot",                    # engagement start: flags, scope mode, model cfg
    "objective",               # verbatim operator objective (turn open)
    "operator_input",          # any operator interaction mid-run
    "turn_end",                # one loop invocation finished
    "agent_message",           # agent output (finals, not streaming)
    "tool_call",               # validated tool/shell invocation
    "tool_result",             # tool/shell outcome incl. exit code
    "ekd_mutation",            # write-ahead: batch applied -> memory store
    "ekd_reset",               # operator /reset: graph dropped to rev 0
    "ekd_snapshot_prune",      # bounded ekd/ retention — listed snapshots
                               # were deleted AFTER this event; replay treats
                               # their references as pruned, not missing
    "compaction",              # episodic fold: summary hash + message range
    "brief_render",            # assembly-side render: rev, budget, hash
    "cache_fingerprint",       # assembly prefix fingerprint (+ drift)
    "scope_mode",              # boot mode + live tightenings
    "scope_expansion",         # auto-admission candidate + outcome
    "scope_cap",               # expansion cap reached (once per engagement)
    "phase_transition",        # engagement phase change (re-freeze,
                               # brief re-render trigger)
    "brief_overflow",          # brief over budget at floor — objective
                               # split, anomaly for operator review
    "message",                 # one message landed in the channel (window
                               # reconstruction: sig + sha + optional
                               # sidecar for oversized sigs)
    "compaction_trim",         # deterministic ladder tier applied
                               # (tier 1 window trim / tier 2 microcompact)
    "compaction_breaker",      # breaker counted/open/reset/override
    "side_query",              # pre-expansion selector run/skip
    "subagent_spawn",          # Task-tool child spawned (mode, phase,
                               # contract hash, brief-slice rev, scopes)
    "subagent_report",         # child report landed (spawn link,
                               # report sha, turns used, partial flag)
    "error",                   # harness-level error worth the audit trail
    "llm_prompt",              # what the model ACTUALLY received: full
                               # system prompt + per-message roles/chars +
                               # est_tokens, with the complete assembled
                               # prompt text as a prompts/ sidecar
    "llm_call",                # guard: attempt started (purpose, model,
                               # n_messages, bounds)
    "llm_call_end",            # guard: attempt outcome (ok / error /
                               # timeout / late_error_after_cancel)
    "llm_retry",               # guard: backing off before next attempt
    "llm_abandon",             # guard: child task abandoned after the
                               # total bound (cancellation did not
                               # complete — transport timeouts reclaim)
    "llm_breaker",             # guard: consecutive-failure breaker state
    # ── 4.0 schema v2 additions (loop control plane) ──────────────────
    "loop_transition",         # the query loop's explicit state-machine
                               # move (from -> to, trigger, turn) — the
                               # 4.0 equivalent of the CC transition table
    "permission_decision",     # scope-gate audit: EVERY allow writes one
                               # (tool, args digest, rule that allowed,
                               # scope ref); denies write one too —
                               # deny-by-default must be auditable
    "turn_watchdog",           # one loop iteration exceeded its duration
                               # bound (the 24-minute-hang lesson as a
                               # first-class journal surface)
    "stop_hook",               # P4: the stop-hook consultation at the
                               # end_turn decision (decision/reason/
                               # duration/exit code — every run audited,
                               # hook failure never gates the stop)
)

# 4.0 helper so replay can distinguish vocabulary generations without
# guessing from event presence.
V2_EVENT_TYPES = frozenset({
    "loop_transition", "permission_decision", "turn_watchdog",
    "stop_hook"})

# Payload size guard: journal is lossless for EVENTS, not a blob store —
# tool outputs live in workspace artifacts; the journal keeps refs.
MAX_DATA_CHARS = 4000

# Inline safety margin for message sigs: a sig at or below this length
# survives _clamp_data untouched, so replay can use it directly for
# window hash reconstruction; longer sigs go to a sidecar (sig_ref).
MAX_INLINE_SIG_CHARS = 3990

# Prompt-forensics sidecar switches (3.7.3 read these from the flat app
# config module; 4.0 keeps them env-driven and stdlib-local, same
# defaults).
PROMPTS_ENABLED = os.environ.get(
    "AEGIS_JOURNAL_PROMPTS", "1").strip().lower() in ("1", "true", "yes", "on")
PROMPT_CAP = int(os.environ.get("AEGIS_JOURNAL_PROMPT_CAP", str(256 * 1024)))


def message_sig(m) -> str:
    """The canonical per-message signature (window audit surface, window
    reconstruction).

    THE formula is frozen — verbatim from 3.7.3: window hashes journaled by
    prior phases were computed with exactly this clamp, so any change here
    silently breaks window-hash verification for every journal ever
    written, including the frozen oracle's. Do not touch.
    """
    content = getattr(m, "content", "")
    if not isinstance(content, str):
        content = str(content)
    return "|".join((
        str(getattr(m, "type", type(m).__name__)),
        str(getattr(m, "tool_call_id", "") or ""),
        content[:4000],
    ))


def sig_sha(m) -> str:
    """sha16 of the canonical message_sig (stable identity for the
    dropped/replaced sig lists the trim/compaction events carry)."""
    return hashlib.sha256(
        message_sig(m).encode("utf-8", "ignore")).hexdigest()[:16]


class Journal:
    """Append-only JSONL journal for one engagement.

    Thread-safe (tools run on worker executors); failures queue (J4) and
    surface through health().
    """

    def __init__(self, journal_dir: Path | str, *,
                 filename: str = "journal.jsonl",
                 turn: int = 0,
                 ekd_rev: int = 0,
                 on_event: Any = None):
        self.path = Path(journal_dir)
        self.path.mkdir(parents=True, exist_ok=True)
        self.file = self.path / filename
        self._lock = threading.Lock()
        # Resume continuation (B1 fix carried from 2026-10-06): a fresh
        # Journal on an EXISTING file continues seq/turn/rev from the
        # file's last event — the next append is last_seq + 1. A restart
        # instead of a continuation puts two 1..N runs in one file and
        # fails replay's strict +1 integrity check at the seam.
        self._seq = 0
        self._turn = turn
        self._rev = ekd_rev
        # Torn-tail visibility (M5): how many non-empty unparseable tail
        # lines _scan_tail skipped (crash mid-write). Surfaced through
        # health() so recovery sees the boundary instead of starting
        # silently as-new.
        self._tail_torn_lines = 0
        if self.file.exists():
            try:
                _last = self._scan_tail()
                if _last is not None:
                    self._seq = int(_last.get("seq") or 0)
                    self._turn = max(turn, int(_last.get("turn") or 0))
                    self._rev = max(ekd_rev, int(_last.get("rev") or 0))
            except Exception:
                pass  # unreadable tail: start as-new (append still safe)
        self._started = time.time()
        # J4 retry queue: events whose disk write failed, in order.
        self._retry: List[Dict[str, Any]] = []
        self._write_failures = 0
        self._on_event = on_event
        # Header event (type boot is reserved for the caller; we do not
        # auto-emit so tests control determinism).

    # ------------------------------------------------------------- state

    def set_turn(self, turn: int) -> None:
        with self._lock:
            self._turn = int(turn)

    def next_turn(self) -> int:
        with self._lock:
            self._turn += 1
            return self._turn

    def set_rev(self, rev: int) -> None:
        """Track the memory-store revision this journal has recorded
        through."""
        with self._lock:
            self._rev = int(rev)

    @property
    def rev(self) -> int:
        with self._lock:
            return self._rev

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    # -------------------------------------------------------------- read-tail

    def _scan_tail(self, max_bytes: int = 262144):
        """Read the LAST parseable event of an existing journal file.
        Reads only the tail (bounded) — a multi-GB journal costs one seek,
        not a full scan. Torn tail lines (crash mid-write) are skipped
        backwards AND counted (M5): the count lands in
        health().torn_tail_lines. None for an empty/unreadable file."""
        import json as _json
        size = self.file.stat().st_size
        with self.file.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # drop the partial line at the window head
            data = f.read()
        torn = 0
        for _line in reversed(data.split(b"\n")):
            _line = _line.strip()
            if not _line:
                continue
            try:
                _ev = _json.loads(_line.decode("utf-8", "replace"))
                if isinstance(_ev, dict):
                    self._tail_torn_lines = torn
                    return _ev
            except Exception:
                torn += 1
                continue
        self._tail_torn_lines = torn
        return None

    # -------------------------------------------------------------- write

    def append(self, event_type: str, data: Optional[Dict[str, Any]] = None,
               *, actor: Optional[str] = None, rev: Optional[int] = None,
               turn: Optional[int] = None, ts: Optional[float] = None,
               force: bool = False) -> Optional[Dict[str, Any]]:
        """Append one event. Returns the event dict, or None if the type
        is unknown (unless force=True — used by not-yet-landed phases)."""
        if event_type not in EVENT_TYPES and not force:
            return None
        # Opportunistic retry drain (H8): a transient OSError no longer
        # strands events until process exit.
        if self._retry:
            try:
                self.flush_retry()
            except Exception:
                pass
        with self._lock:
            self._seq += 1
            event = {
                "v": SCHEMA_VERSION,
                "seq": self._seq,
                "ts": ts if ts is not None else round(time.time(), 3),
                "type": event_type,
                "turn": self._turn if turn is None else int(turn),
                "actor": actor,
                "rev": self._rev if rev is None else int(rev),
                "data": _clamp_data(data or {}),
            }
            if rev is not None:
                self._rev = int(rev)
            try:
                self._write(event)
            except OSError:
                # J4: never raise, never block. Queue in order, surface
                # through health(); flush_retry() re-attempts.
                self._write_failures += 1
                self._retry.append(event)
            except (TypeError, ValueError) as exc:
                # A non-serializable payload must not escape the
                # never-raise contract (3.7.3 H8 fix, carried): count it,
                # clamp to a safe repr, and retry once inline.
                self._write_failures += 1
                try:
                    event = dict(event)
                    event["data"] = {"_clamp_error": str(exc)[:200]}
                    self._write(event)
                except Exception:
                    self._retry.append(event)
            if self._on_event is not None:
                try:
                    self._on_event(event)
                except Exception:
                    pass
            return event

    def _write(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=True, sort_keys=True)
        with self.file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    def flush_retry(self) -> int:
        """Re-attempt queued events in original order. Returns how many
        remain queued. Also called opportunistically (bounded) at the
        head of append()."""
        with self._lock:
            still: List[Dict[str, Any]] = []
            for ev in self._retry:
                try:
                    self._write(ev)
                except OSError:
                    still.append(ev)
            self._retry = still
            return len(still)

    # --------------------------------------------------------------- read

    def events(self, path: Optional[Path] = None) -> Iterator[Dict[str, Any]]:
        """Iterate events in file order (skips unparseable lines, which
        only happen on torn tail writes)."""
        target = path or self.file
        if not target.exists():
            return
        with target.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def events_of_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.events() if e.get("type") == event_type]

    def last_event(self, event_type: Optional[str] = None
                   ) -> Optional[Dict[str, Any]]:
        last = None
        for e in self.events():
            if event_type is None or e.get("type") == event_type:
                last = e
        return last

    def verify_integrity(self) -> Dict[str, Any]:
        """Replay pass: seq strictly +1 from 1; no gaps; schema fields
        present; schema version accepted. Returns a report dict (ok,
        count, gaps, bad_events, unsupported_versions)."""
        count, gaps, bad, prev, ok = 0, [], 0, 0, True
        versions: set = set()
        for e in self.events():
            count += 1
            versions.add(e.get("v"))
            seq = e.get("seq")
            if not isinstance(seq, int) or seq != prev + 1:
                gaps.append({"expected": prev + 1, "got": seq})
                ok = False
            prev = seq if isinstance(seq, int) else prev + 1
            for field in ("v", "ts", "type", "data"):
                if field not in e:
                    bad += 1
                    ok = False
        unsupported = sorted(v for v in versions
                             if not isinstance(v, int) or v > SCHEMA_VERSION)
        if unsupported:
            ok = False
        return {"ok": ok, "count": count, "gaps": gaps, "bad_events": bad,
                "versions": sorted(v for v in versions if v is not None),
                "unsupported_versions": unsupported}

    # ------------------------------------------------------------ health

    def health(self) -> Dict[str, Any]:
        """J4 surface: gaps between what was appended and what reached
        disk. A recorder, not a gate — callers display, never block."""
        with self._lock:
            return {
                "file": str(self.file),
                "seq": self._seq,
                "queued": len(self._retry),
                "write_failures": self._write_failures,
                "torn_tail_lines": self._tail_torn_lines,
                "degraded": bool(self._retry),
                "started": self._started,
            }

    # ---------------------------------------------------------- helpers

    def record_ekd_mutation(self, rev_before: int, rev_after: int, *,
                            extractor: str = "",
                            nodes: int = 0, edges: int = 0,
                            reason: str = "",
                            delta: Optional[Dict[str, Any]] = None,
                            snapshot: Optional[str] = None,
                            snapshot_sha: Optional[str] = None,
                            extra: Optional[Dict[str, Any]] = None
                            ) -> Optional[Dict[str, Any]]:
        """J1 helper for the write path: called BEFORE the memory-store
        state is written, carrying the rev the write will carry — a crash
        between this journal line and the state write is exactly the case
        replay detects and repairs.

        `delta` carries the bounded batch delta (created/updated/
        invalidated node ids+keys, edges added — refs over blobs),
        `snapshot`/`snapshot_sha` reference the durable snapshot artifact
        that makes every committed revision byte-reconstructible, and
        `extra` carries batch linkage (e.g. tool_call_id).
        """
        data: Dict[str, Any] = {
            "rev_before": int(rev_before), "rev_after": int(rev_after),
            "extractor": extractor, "nodes": int(nodes), "edges": int(edges),
            "reason": reason}
        if delta:
            data["delta"] = delta
        if snapshot:
            data["snapshot"] = snapshot
            if snapshot_sha:
                data["snapshot_sha"] = snapshot_sha
        if extra:
            data.update(extra)
        return self.append("ekd_mutation", data, rev=int(rev_after))

    def record_ekd_reset(self, rev_before: int, source: str = "operator"
                         ) -> Optional[Dict[str, Any]]:
        """Operator /reset drops the graph back to rev 0. The journal
        chain must record the discontinuity or replay would see the rev
        go backwards as corruption."""
        return self.append(
            "ekd_reset",
            {"rev_before": int(rev_before), "rev_after": 0,
             "source": source},
            rev=0)

    def record_extractor_failure(self, extractor: str, reason: str, *,
                                 detail: str = "",
                                 tool: str = "") -> Optional[Dict[str, Any]]:
        """An extractor crashed on a journal batch: the batch is skipped
        and flagged — the flag IS this event."""
        data: Dict[str, Any] = {"extractor": extractor, "reason": reason}
        if detail:
            data["detail"] = detail
        if tool:
            data["tool"] = tool
        return self.append("error", data)

    def record_compaction(self, summary: str, *, messages_dropped: int,
                          summary_hash: str, rev: Optional[int] = None,
                          direction: Optional[str] = None,
                          tier: Optional[int] = None,
                          chunks: Optional[int] = None,
                          dropped_sig_shas: Optional[List[str]] = None,
                          drop_position: str = "head_after_objective",
                          recent_preserved: Optional[bool] = None,
                          id_violations: Optional[int] = None,
                          breaker_open: Optional[bool] = None,
                          manual: bool = False,
                          channel: str = ""
                          ) -> Optional[Dict[str, Any]]:
        """The episodic fold. The full residual text is a render input —
        replay re-renders briefs from it byte-identically. The journal
        payload guard clamps the INLINE copy at 4k, so the full text is
        stored as a sidecar artifact under <journal_dir>/compaction/ and
        referenced by name (summary_ref). The clamped inline summary and
        summary_head (200 chars) remain for quick grepping; the sidecar
        is the replay source of truth.

        Additive fields (all optional, pre-P3 emitters keep the base
        shape): `direction` (base | from | up_to — which verbatim template
        the summarizer ran), `tier` (the ladder tier that produced this
        fold, normally 3), `chunks` (window-fit chunking), the window
        surgery record (`dropped_sig_shas` + `drop_position` + the
        implicit drop_complete), continuation flags (`recent_preserved`),
        `id_violations` (review-gate result) and `breaker_open` (ladder
        state at fold time).

        Ordering (carried discipline): sidecar first, then the event — a
        crash between the two leaves an orphan file, harmless (replay
        reads only the refs events claim). A sidecar write failure never
        raises: the event degrades to the inline-only shape.
        """
        data: Dict[str, Any] = {
            "messages_dropped": int(messages_dropped),
            "summary_hash": summary_hash,
            "summary_head": summary[:200]}
        ref = self._write_residual_sidecar(summary, summary_hash)
        if ref:
            data["summary_ref"] = ref
        if summary:
            data["summary"] = summary
        if direction is not None:
            data["direction"] = str(direction)
        if tier is not None:
            data["tier"] = int(tier)
        if chunks is not None:
            data["chunks"] = int(chunks)
        if dropped_sig_shas:
            data["dropped_sig_shas"] = list(dropped_sig_shas)
            data["drop_complete"] = (
                len(dropped_sig_shas) == int(messages_dropped))
        data["drop_position"] = str(drop_position)
        if recent_preserved is not None:
            data["recent_preserved"] = bool(recent_preserved)
        if id_violations is not None:
            data["id_violations"] = int(id_violations)
        if breaker_open is not None:
            data["breaker_open"] = bool(breaker_open)
        if manual:
            data["manual"] = True
        if channel:
            # P3: subagent sidechain folds carry their channel — the
            # replay Zone W sim applies surgery per channel
            data["channel"] = str(channel)
        return self.append("compaction", data, rev=rev)

    def record_message(self, m, *, source: str = "",
                       replaces: Optional[str] = None,
                       extra: Optional[Dict[str, Any]] = None
                       ) -> Optional[Dict[str, Any]]:
        """One message landed in the working channel (window
        reconstruction: replay rebuilds the window from these events and
        byte-verifies the per-render window hashes).

        The event carries the canonical message_sig inline when it fits
        the clamp margin (MAX_INLINE_SIG_CHARS); oversized sigs (heavy
        tool results) go to a content-derived sidecar under
        <journal_dir>/messages/ referenced as sig_ref. sig_sha pins the
        identity the trim/compaction events reference; `replaces` names
        the sig_sha of a message being replaced in place (tier-2 stub).
        Never raises, never gates (J4) — a failed sidecar degrades to the
        inline head only and replay skips that window's byte-verification
        explicitly.
        """
        try:
            sig = message_sig(m)
            sha = hashlib.sha256(
                sig.encode("utf-8", "ignore")).hexdigest()[:16]
            content = getattr(m, "content", "")
            if not isinstance(content, str):
                content = str(content)
            data: Dict[str, Any] = {
                "role": str(getattr(m, "type", type(m).__name__)),
                "chars": len(content),
                "sig_sha": sha,
            }
            tcid = getattr(m, "tool_call_id", None)
            if tcid:
                data["tool_call_id"] = str(tcid)
            if source:
                data["source"] = str(source)
            if replaces:
                data["replaces"] = str(replaces)
            if extra:
                data.update(extra)
            if len(sig) <= MAX_INLINE_SIG_CHARS:
                data["sig"] = sig
            else:
                data["sig_head"] = sig[:200]
                ref = self._write_sig_sidecar(sig, sha)
                if ref:
                    data["sig_ref"] = ref
            return self.append("message", data)
        except Exception:
            return None  # J4: the recorder never gates the loop

    def _write_sig_sidecar(self, sig: str, sha: str) -> Optional[str]:
        """Durably store an oversized message sig. Content-derived name
        (idempotent across re-journals); a lying sha is caught by
        replay's chain pass. Never raises, never gates (J4)."""
        try:
            d = self.path / "messages"
            d.mkdir(parents=True, exist_ok=True)
            name = f"sig_{sha}.txt"
            path = d / name
            with path.open("w", encoding="utf-8") as f:
                f.write(sig)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return name
        except Exception:
            return None

    def record_compaction_trim(self, tier: int, *,
                               dropped: int = 0,
                               stubbed: int = 0,
                               sig_shas: Optional[List[str]] = None,
                               replaces: Optional[List[str]] = None,
                               tokens_before: int = 0,
                               tokens_after: int = 0,
                               reason: str = "",
                               channel: str = ""
                               ) -> Optional[Dict[str, Any]]:
        """A deterministic ladder tier applied at a turn boundary (tier 1
        window trim — whole turn pairs dropped beyond a reduced K; tier 2
        microcompact — heavy tool-result bodies older than the protected
        window stubbed in place, memory/journal refs kept). Tier 0
        (attachment hygiene) records here too when it actually dropped
        something. The sig lists are the window surgery record replay
        applies; `replaces` carries the ORIGINAL sig_shas of in-place
        stubs (tier 2), paired positionally with the replacement message
        events that follow."""
        data: Dict[str, Any] = {"tier": int(tier)}
        if dropped:
            data["dropped"] = int(dropped)
        if stubbed:
            data["stubbed"] = int(stubbed)
        if sig_shas:
            data["sig_shas"] = list(sig_shas)
            data["drop_complete"] = (len(sig_shas) == int(dropped))
        if replaces:
            data["replaces"] = list(replaces)
        if tokens_before or tokens_after:
            data["tokens_before"] = int(tokens_before)
            data["tokens_after"] = int(tokens_after)
        if reason:
            data["reason"] = str(reason)
        if channel:
            data["channel"] = str(channel)
        return self.append("compaction_trim", data)

    def record_compaction_breaker(self, action: str, *,
                                  failures: int = 0,
                                  detail: str = "",
                                  actor: str = "system"
                                  ) -> Optional[Dict[str, Any]]:
        """The 3-failure breaker surface. Actions: 'counted' (a failure
        joined the streak), 'open' (threshold reached — auto-compaction
        disabled, operator paged, deterministic tiers carry the load),
        'reset' (a success cleared the streak), 'override' (manual
        compaction ran with the breaker open — journaled override)."""
        return self.append("compaction_breaker", {
            "action": str(action), "failures": int(failures),
            "detail": str(detail)}, actor=actor)

    def _write_residual_sidecar(self, summary: str,
                                summary_hash: str) -> Optional[str]:
        """Durably store the full compaction residual. Returns the
        artifact filename or None on any failure — never raises, never
        gates (J4).

        The filename is content-derived (the caller's sha16 of the
        residual text), not rev- or turn-derived: byte-identical
        residuals across folds collapse onto one artifact (idempotent
        overwrite, no information loss), and /reset can never collide a
        post-reset artifact onto a pre-reset one. A caller that lied
        about its hash is caught by replay's chain pass (sidecar sha vs.
        the event's claim).
        """
        if not summary:
            return None
        key = summary_hash or hashlib.sha256(
            summary.encode("utf-8", "ignore")).hexdigest()[:16]
        try:
            d = self.path / "compaction"
            d.mkdir(parents=True, exist_ok=True)
            name = f"summary_{key}.md"
            path = d / name
            with path.open("w", encoding="utf-8") as f:
                f.write(summary)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return name
        except Exception:
            # The sidecar is a replay upgrade, never a write-path gate.
            # The event just carries the clamped inline copy.
            return None

    def record_side_query(self, *, trigger: str = "", ekd_rev: int = 0,
                          candidates: int = 0, model: str = "",
                          selected: Optional[List[str]] = None,
                          expansions: Optional[List[Dict[str, Any]]] = None,
                          surfaced: Optional[List[str]] = None,
                          skipped: str = "", failed: str = "",
                          ) -> Optional[Dict[str, Any]]:
        """One pre-expansion selector outcome. `trigger` records why the
        gate opened (revision_bump / new_entities); `skipped`/`failed`
        record why it did not run or failed (skip expansion, brief alone,
        health flag). `expansions` carries one {id, sha, chars, text} per
        attachment written — the sha pins the EXACT capped text injected
        (the cap is applied at injection, so the journal never distorts
        what the model received). `surfaced` is the post-run
        already-surfaced set head (the anti-re-pick surface). Never
        raises (J4): the selector is a strict optimization layer.
        """
        try:
            data: Dict[str, Any] = {
                "trigger": str(trigger or ""),
                "ekd_rev": int(ekd_rev or 0),
                "candidates": int(candidates or 0),
            }
            if model:
                data["model"] = str(model)
            if selected:
                data["selected"] = [str(x) for x in selected]
            if expansions:
                data["expansions"] = [
                    {"id": str(e.get("id", "")),
                     "sha": str(e.get("sha", "")),
                     "chars": int(e.get("chars", 0)),
                     "text": str(e.get("text", ""))}
                    for e in expansions]
            if surfaced:
                data["surfaced"] = [str(x) for x in surfaced]
            if skipped:
                data["skipped"] = str(skipped)
            if failed:
                data["failed"] = str(failed)[:200]
            return self.append("side_query", data)
        except Exception:
            return None  # J4: never gates the assembly path

    def record_subagent_spawn(self, mode: str, phase: str, *,
                              task: str = "", contract_hash: str = "",
                              brief_rev: int = 0,
                              brief_slice_hash: str = "",
                              scopes: Optional[List[str]] = None,
                              ceiling: int = 0,
                              ) -> Optional[Dict[str, Any]]:
        """A Task-tool child spawned (the 4.0 name for the 3.7 contract
        subagent — same event, same shape, so oracle-era spawns replay).
        J1-style write-ahead: journaled BEFORE the child runs, so the
        contract any child received is reconstructible from the journal
        alone even on a child crash. `contract_hash` pins the exact
        system prompt; the report-side linkage lands in
        record_subagent_report.
        """
        try:
            data: Dict[str, Any] = {
                "mode": str(mode),
                "phase": str(phase),
                "task": str(task)[:300],
            }
            if contract_hash:
                data["contract_hash"] = str(contract_hash)
            if brief_rev:
                data["brief_rev"] = int(brief_rev)
            if brief_slice_hash:
                data["brief_slice_hash"] = str(brief_slice_hash)
            if scopes:
                data["scopes"] = [str(s) for s in scopes]
            if ceiling:
                data["ceiling"] = int(ceiling)
            return self.append("subagent_spawn", data)
        except Exception:
            return None

    def record_subagent_report(self, spawn_seq: int, phase: str, *,
                               report_sha: str = "", report_chars: int = 0,
                               turns_used: int = 0, partial: bool = False,
                               ) -> Optional[Dict[str, Any]]:
        """Child report landed (the report itself rides message events
        with source='subagent:<phase>'). This event carries the spawn
        link + the sha of the FULL report text; together they pin the
        report end-to-end. `partial` flags the turn-budget ceiling case
        (done-so-far clause)."""
        try:
            data: Dict[str, Any] = {
                "spawn_seq": int(spawn_seq or 0),
                "phase": str(phase),
                "report_sha": str(report_sha),
                "report_chars": int(report_chars or 0),
                "turns_used": int(turns_used or 0),
                "partial": bool(partial),
            }
            return self.append("subagent_report", data)
        except Exception:
            return None

    def record_brief_render(self, brief: str, *, budget: int,
                            ekd_rev: int, render_hash: str,
                            now: Optional[float] = None,
                            prompt_hash: Optional[str] = None,
                            brief_hash: Optional[str] = None,
                            actor_hint: str = "",
                            contract: Optional[str] = None,
                            ceiling: Optional[int] = None,
                            window_msg_count: Optional[int] = None,
                            window_hash: Optional[str] = None,
                            cache_hit: Optional[bool] = None,
                            phase: Optional[str] = None,
                            escalation: Optional[bool] = None
                            ) -> Optional[Dict[str, Any]]:
        """J2 helper: the render is reconstructible from (rev, budget,
        pinned now); the hash pins byte-identity for the audit trail.

        `now` is the render clock the renderer actually used; `ekd_rev`
        is the revision the brief ACTUALLY rendered; `brief_hash` pins
        the brief alone (replay target) and `prompt_hash` the full
        assembled prompt (assembly forensics); `contract` names the
        renderer so replay picks the right one; `ceiling` is the hard
        ceiling the render was bounded by; `window_msg_count` /
        `window_hash` pin the window selection; `cache_hit` marks renders
        reused byte-for-byte from the (revision, budget) cache; `phase`
        is the engagement phase; `escalation` flags the floor-split path
        (the detail rides a brief_overflow event).
        """
        data: Dict[str, Any] = {
            "budget": int(budget), "rev": int(ekd_rev),
            "hash": render_hash, "chars": len(brief)}
        if now is not None:
            data["now"] = float(now)
        if brief_hash:
            data["brief_hash"] = brief_hash
        if prompt_hash:
            data["prompt_hash"] = prompt_hash
        if actor_hint:
            data["actor_hint"] = actor_hint
        if contract:
            data["contract"] = str(contract)
        if ceiling is not None:
            data["ceiling"] = int(ceiling)
        if window_msg_count is not None:
            data["window_msg_count"] = int(window_msg_count)
        if window_hash:
            data["window_hash"] = str(window_hash)
        if cache_hit is not None:
            data["cache_hit"] = bool(cache_hit)
        if phase:
            data["phase"] = str(phase)
        if escalation is not None:
            data["escalation"] = bool(escalation)
        # Prompt forensics (carried from the 2026-10-06 hardening):
        # persist the rendered brief TEXT as a sidecar so a replay
        # mismatch can be diffed with actual bytes, not just hashes.
        # Content-derived name (idempotent per render hash); never
        # raises, never gates (J4).
        try:
            if PROMPTS_ENABLED and brief:
                bd = self.path / "briefs"
                bd.mkdir(parents=True, exist_ok=True)
                _bname = f"brief_{render_hash}.md"
                _bpath = bd / _bname
                if not _bpath.exists():
                    with _bpath.open("w", encoding="utf-8") as f:
                        f.write(str(brief))
                        f.flush()
                        os.fsync(f.fileno())
                    try:
                        os.chmod(_bpath, 0o600)
                    except OSError:
                        pass
                data["brief_ref"] = f"briefs/{_bname}"
        except Exception:
            pass
        return self.append("brief_render", data, rev=int(ekd_rev))

    def record_llm_prompt(self, system_prompt: str, messages: List[Any],
                          *, node: str = "", model: str = ""
                          ) -> Optional[Dict[str, Any]]:
        """Persist WHAT the model actually received on this call — the
        full system prompt plus every message's role/chars — with the
        complete assembled prompt text as a prompts/prompt_<sha>.txt
        sidecar (capped). Hashes alone are not debuggable; this event +
        sidecar answer "what did we send?". est_tokens uses the chars/4
        estimator (same as the debug kit's llm/prompt event). Never
        raises, never gates (J4).
        """
        try:
            sys_txt = str(system_prompt or "")
            per_msg: List[Dict[str, Any]] = []
            body_parts: List[str] = [f"=== SYSTEM ({len(sys_txt)} chars) ===",
                                     sys_txt]
            total_chars = len(sys_txt)
            for m in list(messages or [])[:200]:
                content = getattr(m, "content", "")
                if not isinstance(content, str):
                    content = str(content)
                role = str(getattr(m, "type", "msg"))
                per_msg.append({"role": role, "chars": len(content)})
                total_chars += len(content)
                body_parts.append(f"=== {role.upper()} ({len(content)} "
                                  f"chars) ===")
                body_parts.append(content)
            prompt_text = "\n\n".join(body_parts)
            sha = hashlib.sha256(prompt_text.encode("utf-8",
                                                    "ignore")).hexdigest()[:16]
            data: Dict[str, Any] = {
                "node": str(node), "model": str(model),
                "system_chars": len(sys_txt), "system_sha": hashlib.sha256(
                    sys_txt.encode("utf-8", "ignore")).hexdigest()[:16],
                "n_messages": len(per_msg),
                "est_tokens": total_chars // 4,
                "chars": total_chars, "prompt_sha": sha}
            if len(per_msg) > 60:
                data["messages_head"] = per_msg[:60]
            else:
                data["messages"] = per_msg
            try:
                if PROMPTS_ENABLED:
                    d = self.path / "prompts"
                    d.mkdir(parents=True, exist_ok=True)
                    name = f"prompt_{sha}.txt"
                    path = d / name
                    if not path.exists():
                        with path.open("w", encoding="utf-8") as f:
                            f.write(prompt_text[:PROMPT_CAP])
                            f.flush()
                            os.fsync(f.fileno())
                        try:
                            os.chmod(path, 0o600)
                        except OSError:
                            pass
                    data["prompt_ref"] = f"prompts/{name}"
                    if len(prompt_text) > PROMPT_CAP:
                        data["prompt_truncated"] = True
            except Exception:
                pass
            return self.append("llm_prompt", data)
        except Exception:
            return None

    def record_brief_overflow(self, *, ekd_rev: int, budget: int,
                              ceiling: int, objective_id: str,
                              objective_chars: int,
                              first_line_chars: int) -> Optional[Dict[str, Any]]:
        """Brief over budget at floor: the degradation ladder exhausted
        the floor and the objective was split into a verbatim first line
        plus a journal pointer. Floor preserved; this event is the
        anomaly surface for operator review (never silent)."""
        return self.append("brief_overflow", {
            "rev": int(ekd_rev), "budget": int(budget),
            "ceiling": int(ceiling), "objective_id": str(objective_id),
            "objective_chars": int(objective_chars),
            "first_line_chars": int(first_line_chars),
        }, rev=int(ekd_rev))

    def record_phase_transition(self, phase: str, *, prev_phase: str = "",
                                reason: str = "",
                                actor: str = "operator"
                                ) -> Optional[Dict[str, Any]]:
        """Engagement phase change (re-render trigger + zone re-freeze).
        The static zone may legitimately change across a phase boundary —
        never within one."""
        return self.append("phase_transition", {
            "phase": str(phase), "prev_phase": str(prev_phase),
            "reason": str(reason),
        }, actor=actor)

    def record_objective(self, text: str, *,
                         actor: str = "operator"
                         ) -> Optional[Dict[str, Any]]:
        """The FULL objective text is a render input.

        Replay re-renders briefs through it — the ephemeral node of a
        fresh engagement AND the escalated primary both derive their
        rendered bytes from it. Shape (mirrors record_compaction):
        objectives longer than the clamp store the full text as a
        sidecar under <journal_dir>/objective/ referenced by
        content-derived name (text_ref + text_hash); the inline copy
        stays clamp-sized for grepping. Short objectives inline the full
        text and write no sidecar. Ordering: sidecar first, then the
        event. A sidecar write failure never raises (J4).
        """
        text = str(text or "")
        data: Dict[str, Any] = {"chars": len(text)}
        if text:
            th = hashlib.sha256(
                text.encode("utf-8", "ignore")).hexdigest()[:16]
            if len(text) > MAX_DATA_CHARS:
                ref = self._write_objective_sidecar(text, th)
                if ref:
                    data["text_ref"] = ref
                    data["text_hash"] = th
            data["text"] = text
        return self.append("objective", data, actor=actor)

    def _write_objective_sidecar(self, text: str,
                                 text_hash: str) -> Optional[str]:
        """Durably store a >clamp objective text. Content-derived name:
        the same objective re-journaled across resume/follow-up rounds
        collapses onto one artifact (idempotent overwrite); a lying hash
        is caught by replay's chain pass."""
        if not text:
            return None
        try:
            d = self.path / "objective"
            d.mkdir(parents=True, exist_ok=True)
            name = f"objective_{text_hash}.txt"
            path = d / name
            with path.open("w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return name
        except Exception:
            return None

    # ------------------------------------------------- 4.0 v2 helpers

    def record_loop_transition(self, transition: str, *, frm: str = "",
                               to: str = "", trigger: str = "",
                               turn: Optional[int] = None,
                               detail: Optional[Dict[str, Any]] = None,
                               ) -> Optional[Dict[str, Any]]:
        """4.0: the query loop's explicit state-machine move (the CC
        transition-table equivalent). Emitted by the loop itself at
        every continue path — the timeline mirrors it, the journal makes
        it replayable. `transition` is the canonical name (e.g.
        next_turn, tool_result, autocompact, collapse_drain_retry,
        max_output_tokens_escalate, queued_command, stop_hook_blocking);
        frm/to/trigger/detail are free-form context for the audit trail.
        """
        data: Dict[str, Any] = {"transition": str(transition)}
        if frm:
            data["from"] = str(frm)
        if to:
            data["to"] = str(to)
        if trigger:
            data["trigger"] = str(trigger)
        if detail:
            data["detail"] = detail
        return self.append("loop_transition", data, turn=turn)

    def record_permission_decision(self, tool: str, *, allowed: bool,
                                   rule: str = "", args_digest: str = "",
                                   scope_ref: str = "",
                                   reason: str = "",
                                   actor: str = "scope-gate"
                                   ) -> Optional[Dict[str, Any]]:
        """4.0 scope-gate audit record. In 4.0 enforcement is ON and
        deny-by-default; EVERY decision — allow and deny alike — writes
        one of these. `rule` names the scope-file clause that decided;
        `args_digest` is a sha16 of the validated tool arguments;
        `scope_ref` points at the engagement scope file revision. This
        is the SLO-1 surface (zero scope violations) and the P4
        cutover's audit exhibit."""
        data: Dict[str, Any] = {
            "tool": str(tool), "allowed": bool(allowed)}
        if rule:
            data["rule"] = str(rule)
        if args_digest:
            data["args_digest"] = str(args_digest)
        if scope_ref:
            data["scope_ref"] = str(scope_ref)
        if reason:
            data["reason"] = str(reason)[:500]
        return self.append("permission_decision", data, actor=actor)

    def record_turn_watchdog(self, *, turn: int, bound_s: float,
                             elapsed_s: float, action: str = "tripped",
                             detail: str = ""
                             ) -> Optional[Dict[str, Any]]:
        """4.0: one loop iteration hit its duration bound. Actions:
        'tripped' (the bound fired — cancellation begins), 'abandoned'
        (cancellation did not complete; transport timeouts reclaim),
        'recovered' (the turn completed after a trip was recorded). The
        24-minute single-LLM-call hang of the 3.x era is structurally
        impossible to miss in 4.0: it shows up HERE, in the timeline,
        and in the reaper's wire events."""
        return self.append("turn_watchdog", {
            "turn": int(turn), "bound_s": float(bound_s),
            "elapsed_s": round(float(elapsed_s), 3),
            "action": str(action), "detail": str(detail)[:500]})


def _clamp_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Keep event payloads bounded: refs over blobs (artifacts live in
    the workspace; the journal points at them)."""
    out: Dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str) and len(v) > MAX_DATA_CHARS:
            out[k] = v[:MAX_DATA_CHARS] + f"...[{len(v)} chars]"
        else:
            out[k] = v
    return out


def iter_journal_events(path: Path | str) -> Iterator[Dict[str, Any]]:
    """Standalone reader (replay/export tooling, no Journal instance).
    Accepts v1 (3.7.3) and v2 (4.0) journals alike."""
    j = Journal.__new__(Journal)
    return Journal.events(j, Path(path))  # type: ignore[arg-type]
