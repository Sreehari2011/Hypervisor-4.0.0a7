"""hypervisor.context.fingerprint — zone fingerprinting guard (P2).

PORT-10: the 3.7.3 cache-prefix fingerprint monitor (src/
fingerprint.py, 221 ln) carried as the assembly's drift instrument.

The M5 triple — (model identifier, comma-joined tool names, system
prompt content digest) — is computed per assembly BEFORE any expensive
serialization and compared against the actor's running baseline. In
Claude Code this gates prompt-dump logging; here it is the runtime
cache-break detector AND the attribution log: an unexpected change is
flagged and attributed (model / tools / system content), because a
changed prefix is a changed cache key, and a changed cache key is
money. M13 carried: the system prompt enters as a CONTENT digest
(sha256 head), not its length — a same-length rewrite of the static
zone must not slip through.

4.0 deltas: the "actors" are the main loop and (P3) each subagent —
per-actor baselines still hold, different actors are different cache
keys by design; the monitor rides the assembler's render path and
pairs with brief_render events; OpenAI-compatible endpoints have
different cache economics than the Anthropic API, so the fingerprint
is the DRIFT instrument and the cost model it feeds is deployment
tuning, not code.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence


def assembly_fingerprint(model: str,
                         tool_names: Iterable[str],
                         system_prompt: str) -> str:
    """The M5 triple as a stable digest. Pure function.

    tool_names order is normalized (sorted) so a tool-list reshuffle in
    the registry is NOT a cache break unless the set itself changes."""
    tools = ",".join(sorted(t for t in tool_names if t))
    sys_digest = hashlib.sha256(
        (system_prompt or "").encode("utf-8", "ignore")).hexdigest()[:16]
    basis = f"{model or '?'}|{tools}|{sys_digest}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _attributions(prev: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    why = []
    if prev["model"] != new["model"]:
        why.append("model")
    if prev["tools"] != new["tools"]:
        added = sorted(set(new["tools"]) - set(prev["tools"]))
        removed = sorted(set(prev["tools"]) - set(new["tools"]))
        detail = []
        if added:
            detail.append(f"+{added}")
        if removed:
            detail.append(f"-{removed}")
        why.append("tools(" + " ".join(detail) + ")" if detail else "tools")
    if prev["system_digest"] != new["system_digest"]:
        why.append("system-prompt(content)")
    elif prev.get("system_len") != new.get("system_len"):
        # length differs but digest matched is impossible (digest pins
        # content); kept only for forward-compat with foreign baselines
        why.append(f"system-length({prev.get('system_len')}->"
                   f"{new.get('system_len')})")
    return why


class ZoneViolationError(RuntimeError):
    """C1 carried: the Zone S prefix changed WITHIN an engagement phase.
    A build-level error — the assembly aborts rather than silently
    shipping a mutated cache prefix. The operator either fixes the
    change or transitions the phase (set_phase re-freezes baselines)."""


class FingerprintMonitor:
    """Per-engagement C6 monitor with per-actor baselines.

    Construct with a Journal (optional — None means compute-only, useful
    in tests). The first check_assembly() for a given actor establishes
    that actor's baseline; every subsequent one compares against it and
    journals drift with attribution.

    strict=True (C1): a fingerprint change WITHIN an engagement phase
    raises ZoneViolationError after the journal event; the baseline is
    NOT advanced (the violation persists until fixed or the phase
    transitions), and set_phase() re-freezes baselines so a legitimate
    cross-phase change starts a fresh comparison.
    """

    def __init__(self, journal: Any = None, *, label: str = "main",
                 strict: bool = False):
        self._lock = threading.Lock()
        self._journal = journal
        self._label = label
        self.strict = bool(strict)
        self.phase = "main"
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self.checks = 0
        self.drift_events: List[Dict[str, Any]] = []

    # -------------------------------------------------------------- api

    def set_phase(self, phase: str) -> None:
        """C1 trigger 3: a phase transition re-freezes the static zone —
        prior baselines no longer apply (tool schemas and guidelines
        legitimately change across the boundary)."""
        with self._lock:
            self.phase = str(phase or "main")
            self.baselines.clear()

    def check_assembly(self, model: str, tool_names: Sequence[str],
                       system_prompt: str, *,
                       turn: Optional[int] = None,
                       actor: Optional[str] = None
                       ) -> Dict[str, Any]:
        """Compute the fingerprint for one assembly; compare to the
        actor's baseline.

        Returns {"fingerprint", "changed", "attributions", "baseline",
        "actor"}. The first call for an actor establishes its baseline
        (changed=False, baseline=True). Drift is journaled as a
        cache_fingerprint event with prev/new digests and the
        attribution list; outside strict mode the new shape becomes the
        actor's baseline (the next stable state is measured against
        what is actually being sent now)."""
        key = actor or self._label
        tools = sorted(t for t in tool_names if t)
        snap = {
            "model": model or "?",
            "tools": tools,
            "system_len": len(system_prompt or ""),
            "system_digest": hashlib.sha256(
                (system_prompt or "").encode("utf-8", "ignore")
            ).hexdigest()[:16],
        }
        fp = assembly_fingerprint(model, tools, system_prompt or "")
        with self._lock:
            self.checks += 1
            base = self.baselines.get(key)
            if base is None:
                self.baselines[key] = {"fingerprint": fp, **snap}
                self._journal_safe(
                    {"kind": "baseline", "actor": key,
                     "fingerprint": fp, "model": snap["model"],
                     "tools": tools, "system_len": snap["system_len"],
                     "system_digest": snap["system_digest"]},
                    turn=turn, actor=key)
                return {"fingerprint": fp, "changed": False,
                        "attributions": [], "baseline": True, "actor": key}
            if fp == base["fingerprint"]:
                return {"fingerprint": fp, "changed": False,
                        "attributions": [], "baseline": False, "actor": key}
            why = _attributions(
                {"model": base["model"], "tools": base["tools"],
                 "system_len": base["system_len"],
                 "system_digest": base.get(
                     "system_digest", "")}, snap)
            drift = {
                "fingerprint": fp, "changed": True,
                "attributions": why, "baseline": False, "actor": key,
                "prev": base["fingerprint"],
            }
            self.drift_events.append(drift)
            self._journal_safe(
                {"kind": "drift", "actor": key, "fingerprint": fp,
                 "prev": drift["prev"], "attributions": why,
                 "model": snap["model"], "tools": tools,
                 "system_len": snap["system_len"],
                 "system_digest": snap["system_digest"]},
                turn=turn, actor=key)
            if self.strict:
                # C1: build-level error. Baseline intentionally NOT
                # advanced — the violation must keep firing until the
                # change is fixed or the phase legitimately transitions.
                raise ZoneViolationError(
                    f"Zone S prefix changed within phase '{self.phase}' "
                    f"for actor '{key}' (" + ", ".join(why) + ") — the "
                    f"static zone is immutable per engagement phase "
                    f"(rule C1); fix the change or transition the phase")
            self.baselines[key] = {"fingerprint": fp, **snap}
            return drift

    def _journal_safe(self, data: Dict[str, Any], *,
                      turn: Optional[int], actor: str) -> None:
        if self._journal is None:
            return
        try:
            self._journal.append("cache_fingerprint", data,
                                 turn=turn, actor=actor)
        except Exception:
            pass

    # ------------------------------------------------------------ report

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "label": self._label,
                "phase": self.phase,
                "strict": self.strict,
                "checks": self.checks,
                "actors": len(self.baselines),
                "drifts": len(self.drift_events),
                "baselines": {k: dict(v) for k, v in self.baselines.items()},
            }
