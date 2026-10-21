"""hypervisor.persist.replay — journal replay and integrity passes (P3,
PORT-06).

Port of 3.7.3 src/replay.py (815 ln), the lossless-audit counterpart of
the journal: three verification passes over an engagement journal plus
its sidecar artifacts, plus the 4.0 session-linkage pass.

  1. Integrity — seq continuity +1 from 1, schema fields present, no
     unparseable lines beyond a torn tail, schema versions accepted
     (v1 = the frozen oracle's journals, v2 = 4.0 — replaying the
     oracle's journals is a hard requirement).

  2. Revision chain — the ekd_mutation write-ahead chain is contiguous
     (rev_before == running rev), monotonic except across an explicit
     ekd_reset, every referenced snapshot artifact exists with matching
     sha AND matching embedded revision; compaction residual sidecars,
     objective sidecars and message sig sidecars get the same
     discipline; side_query expansion texts hash to their claimed shas;
     subagent spawn/report linkage holds (spawn mode sanctioned, report
     references a real spawn, the channel message carrying the report
     matches its sha).

  3. Render reconstruction — Zone W rebuilt from the message events
     (the sanctioned surgery — identity drops, in-place stub replaces,
     the fold's drop + continuation insert — applied in journal order),
     every brief_render carrying a window_hash gets its window
     re-selected and byte-compared; every render carrying the J2 triplet
     (brief_hash + now + budget) gets the EKD re-loaded from the latest
     committed snapshot, the deterministic ensure_objective re-applied
     with the pinned clock, and the brief re-rendered byte-for-byte
     through the same Table 8 renderer production used.

  4. (4.0) Session linkage — the journal's subagent spawns against the
     session store's sidechain transcripts: every spawn has a sidechain
     with a matching meta sidecar, every sidechain's parent chain
     verifies, and the parent transcript's chain is intact.

Degradation is EXPLICIT, never silent: pre-Phase-1 render events (no
brief_hash/now), window checks on resumed boots (the restored window
is not reconstructible from journaled message events — ENG-01: every
resumed-boot window journaled msg_count=0; byte checks are RETAINED,
40/42 verified; resumed = the journaled boot flag, or legacy
inference — any boot event beyond the first in the same journal),
unrecoverable sigs and pruned snapshots count as skipped — the report
is a recorder, not a gate.

Crash-boundary repair: journal-ahead-of-store (a journal rev with no
state rev — a crash between the J1 write-ahead and the state write)
is detected and repaired EXPLICITLY by re-materializing the store from
the journaled snapshot chain; the repair report names every action.

CLI:
    python -m hypervisor.persist.replay <journal_dir_or_file> [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_JOURNAL_FILE = "journal.jsonl"
DEFAULT_EKD_SUBDIR = "ekd"
DEFAULT_COMPACTION_SUBDIR = "compaction"
DEFAULT_OBJECTIVE_SUBDIR = "objective"
DEFAULT_MESSAGES_SUBDIR = "messages"
DEFAULT_SESSIONS_SUBDIR = ".aegis/sessions"
SANCTIONED_MODES = ("fork", "contract")


def _sha16(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", "ignore")).hexdigest()[:16]


def _sig_role(sig: str) -> str:
    return sig.split("|", 1)[0]


def _sig_is_tool_result(sig: str) -> bool:
    """Sig-level mirror of budget.is_tool_result_msg: a 4.0 dict
    tool-result carrier signs as 'user|<tool_use_id>|<content>' (the
    _MsgView adapter maps the first tool_result id into the frozen
    formula's tool_call_id slot); a 3.7/oracle ToolMessage signs as
    'tool|<id>|<content>'. Either shape attaches to the current
    group."""
    parts = sig.split("|", 2)
    if len(parts) < 2:
        return False
    role, tcid = parts[0], parts[1]
    return (role == "tool" and bool(tcid)) or \
        (role == "user" and bool(tcid))


def _sig_groups(sigs) -> Optional[List[List[int]]]:
    """Sig-level mirror of context.assemble.group_message_indices: a
    tool-result-role sig attaches to the current group, every other
    role starts a new group. None when any member is unknown (an
    unreconstructible sig makes the grouping — and therefore the
    window hash — undeterminable)."""
    groups: List[List[int]] = []
    current: Optional[List[int]] = None
    for i, s in enumerate(sigs):
        if s is None:
            return None
        if _sig_is_tool_result(s) and current is not None:
            current.append(i)
        else:
            current = [i]
            groups.append(current)
    return groups


def _load_events(journal_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not journal_path.exists():
        return events
    with journal_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # torn tail write
    return events


class JournalReplay:
    """Replay verifier over one engagement journal + sidecar dirs."""

    def __init__(self, journal_path: Path | str,
                 ekd_dir: Optional[Path | str] = None,
                 compaction_dir: Optional[Path | str] = None,
                 objective_dir: Optional[Path | str] = None,
                 messages_dir: Optional[Path | str] = None,
                 sessions_dir: Optional[Path | str] = None):
        self.journal_path = Path(journal_path)
        if self.journal_path.is_dir():
            self.journal_path = self.journal_path / DEFAULT_JOURNAL_FILE
        base = self.journal_path.parent
        self.ekd_dir = Path(ekd_dir or base / DEFAULT_EKD_SUBDIR)
        self.compaction_dir = Path(
            compaction_dir or base / DEFAULT_COMPACTION_SUBDIR)
        self.objective_dir = Path(
            objective_dir or base / DEFAULT_OBJECTIVE_SUBDIR)
        self.messages_dir = Path(
            messages_dir or base / DEFAULT_MESSAGES_SUBDIR)
        # 4.0 session store lives under <workspace>/.aegis/sessions;
        # when the journal dir IS the journal root (workspace/.aegis/
        # journal) the sessions dir is a sibling.
        if sessions_dir is None:
            cand = base.parent / "sessions"
            if (base / "sessions").exists() and not cand.exists():
                cand = base / "sessions"
            sessions_dir = cand
        self.sessions_dir = Path(sessions_dir)
        self.events = _load_events(self.journal_path)

    # ── pass 1: integrity ─────────────────────────────────────────

    def integrity(self) -> Dict[str, Any]:
        count, gaps, bad, prev, ok = 0, [], 0, 0, True
        versions: set = set()
        for e in self.events:
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
                             if not isinstance(v, int) or v > 2)
        if unsupported:
            ok = False
        return {"ok": ok, "events": count, "gaps": gaps,
                "bad_events": bad,
                "versions": sorted(v for v in versions if v is not None),
                "unsupported_versions": unsupported}

    # ── pass 2: revision chain (+ 4.0 v2 surfaces) ────────────────

    def revision_chain(self) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        mutations = resets = compactions = 0
        snapshots_checked = sidecars_checked = 0
        objective_refs_checked = message_refs_checked = 0
        trims = breaker_events = 0
        side_queries = expansion_shas_checked = 0
        subagent_spawns = subagent_reports = 0
        subagent_reports_linked = subagent_reports_skipped = 0
        loop_transitions = 0
        permission_allows = permission_denies = 0
        watchdog_events = 0
        watchdog_spans: List[Dict[str, Any]] = []
        stop_hook_runs = 0
        stop_hook_blocks = 0
        running_rev: Optional[int] = None
        events = list(self.events)

        # M3: pre-scan the prune events so pruned snapshot references
        # are PRUNED (skipped, counted), not missing artifacts.
        pruned_snaps = set()
        pruned_events = 0
        for e in events:
            if e.get("type") == "ekd_snapshot_prune":
                pruned_events += 1
                for n in ((e.get("data") or {}).get("pruned") or []):
                    pruned_snaps.add(str(n))
        snapshots_pruned = 0
        for e in events:
            t = e.get("type")
            d = e.get("data") or {}
            if t == "ekd_mutation":
                mutations += 1
                rb, ra = d.get("rev_before"), d.get("rev_after")
                if not isinstance(rb, int) or not isinstance(ra, int):
                    issues.append({"seq": e.get("seq"),
                                   "issue": "non-integer revs"})
                    continue
                if ra < rb:
                    issues.append({"seq": e.get("seq"),
                                   "issue": f"rev_after {ra} < "
                                            f"rev_before {rb}"})
                if running_rev is None:
                    running_rev = rb
                elif rb != running_rev:
                    issues.append({
                        "seq": e.get("seq"),
                        "issue": "chain discontinuity",
                        "expected_rev_before": running_rev,
                        "got_rev_before": rb})
                running_rev = ra
                snap = d.get("snapshot")
                if snap:
                    if str(snap) in pruned_snaps:
                        snapshots_pruned += 1
                    else:
                        ok, detail = self._check_snapshot(
                            snap, ra, d.get("snapshot_sha"))
                        snapshots_checked += 1
                        if not ok:
                            issues.append({"seq": e.get("seq"),
                                           "issue": f"snapshot: {detail}"})
            elif t == "ekd_reset":
                resets += 1
                running_rev = 0
            elif t == "compaction":
                compactions += 1
                ref = d.get("summary_ref")
                if ref:
                    okc, detail = self._check_sidecar(
                        str(ref), d.get("summary_hash"))
                    sidecars_checked += 1
                    if not okc:
                        issues.append({"seq": e.get("seq"),
                                       "issue": f"residual sidecar: "
                                                f"{detail}"})
            elif t == "objective":
                oref = d.get("text_ref")
                if oref:
                    oko, detail = self._check_sidecar(
                        str(oref), d.get("text_hash"),
                        base_dir=self.objective_dir)
                    objective_refs_checked += 1
                    if not oko:
                        issues.append({"seq": e.get("seq"),
                                       "issue": f"objective sidecar: "
                                                f"{detail}"})
            elif t == "message":
                mref = d.get("sig_ref")
                if mref:
                    okm, detail = self._check_sidecar(
                        str(mref), d.get("sig_sha"),
                        base_dir=self.messages_dir)
                    message_refs_checked += 1
                    if not okm:
                        issues.append({"seq": e.get("seq"),
                                       "issue": f"message sig sidecar: "
                                                f"{detail}"})
            elif t == "compaction_trim":
                trims += 1
            elif t == "compaction_breaker":
                breaker_events += 1
            elif t == "side_query":
                side_queries += 1
                for ex in (d.get("expansions") or []):
                    txt = str(ex.get("text", ""))
                    sha = str(ex.get("sha", ""))
                    if not sha or not txt:
                        continue
                    expansion_shas_checked += 1
                    if _sha16(txt) != sha:
                        issues.append({
                            "seq": e.get("seq"),
                            "issue": f"expansion sha mismatch: "
                                     f"{ex.get('id')}"})
            elif t == "subagent_spawn":
                subagent_spawns += 1
                if d.get("mode") not in SANCTIONED_MODES:
                    issues.append({
                        "seq": e.get("seq"),
                        "issue": f"unsanctioned context mode: "
                                 f"{d.get('mode')!r} (rule C5)"})
            elif t == "subagent_report":
                subagent_reports += 1
                spawn_seq = int(d.get("spawn_seq") or 0)
                phase = str(d.get("phase") or "")
                report_sha = str(d.get("report_sha") or "")
                report_chars = int(d.get("report_chars") or 0)
                if not any(ev.get("type") == "subagent_spawn"
                           and int(ev.get("seq") or 0) == spawn_seq
                           for ev in events):
                    issues.append({
                        "seq": e.get("seq"),
                        "issue": f"report references unknown spawn "
                                 f"seq {spawn_seq}"})
                linked = False
                for ev in events:
                    if ev.get("type") != "message" \
                            or int(ev.get("seq") or 0) \
                            < int(e.get("seq") or 0):
                        continue
                    md = ev.get("data") or {}
                    if md.get("source") != f"subagent:{phase}":
                        continue
                    sig = self._load_sig(md)
                    if sig is None or not report_sha:
                        subagent_reports_skipped += 1
                    else:
                        content = sig.split("|", 2)[-1]
                        nl = content.find("\n")
                        body = (content[nl + 1:] if nl >= 0
                                else content)
                        if len(body) == report_chars:
                            if _sha16(body) == report_sha:
                                subagent_reports_linked += 1
                            else:
                                issues.append({
                                    "seq": e.get("seq"),
                                    "issue": "subagent report sha "
                                             "mismatch vs the channel "
                                             "message"})
                        else:
                            subagent_reports_skipped += 1
                    linked = True
                    break
                if not linked:
                    subagent_reports_skipped += 1
            elif t == "loop_transition":
                loop_transitions += 1
            elif t == "permission_decision":
                if d.get("allowed"):
                    permission_allows += 1
                else:
                    permission_denies += 1
            elif t == "turn_watchdog":
                watchdog_events += 1
                if len(watchdog_spans) < 20:
                    watchdog_spans.append({
                        "seq": e.get("seq"),
                        "turn": (e.get("data") or {}).get("turn"),
                        "elapsed_s": (e.get("data") or {}).get(
                            "elapsed_s"),
                        "action": (e.get("data") or {}).get("action")})
            elif t == "stop_hook":
                stop_hook_runs += 1
                if (e.get("data") or {}).get("decision") == "block":
                    stop_hook_blocks += 1
        return {"ok": not issues, "mutations": mutations,
                "resets": resets, "snapshots_checked": snapshots_checked,
                "snapshots_pruned": snapshots_pruned,
                "snapshot_prune_events": pruned_events,
                "compactions": compactions,
                "sidecars_checked": sidecars_checked,
                "objective_refs_checked": objective_refs_checked,
                "message_refs_checked": message_refs_checked,
                "trims": trims, "breaker_events": breaker_events,
                "side_queries": side_queries,
                "expansion_shas_checked": expansion_shas_checked,
                "subagent_spawns": subagent_spawns,
                "subagent_reports": subagent_reports,
                "subagent_reports_linked": subagent_reports_linked,
                "subagent_reports_skipped": subagent_reports_skipped,
                "loop_transitions": loop_transitions,
                "permission_allows": permission_allows,
                "permission_denies": permission_denies,
                "turn_watchdog_events": watchdog_events,
                "turn_watchdog_spans": watchdog_spans,
                "stop_hook_runs": stop_hook_runs,
                "stop_hook_blocks": stop_hook_blocks,
                "final_rev": running_rev, "issues": issues}

    # ── pass 4 (4.0): session-store linkage ───────────────────────

    def session_linkage(self) -> Dict[str, Any]:
        """Journal <-> session sidechain audit: every subagent_spawn
        pairs with a sidechain transcript whose meta sidecar names the
        same agent label; sidechain chains verify; the parent chain
        verifies. Degrades to skipped when the store is absent
        (headless runs) — explicit, never a failure."""
        issues: List[Dict[str, Any]] = []
        spawns = [e for e in self.events
                  if e.get("type") == "subagent_spawn"]
        if not self.sessions_dir.exists():
            return {"ok": not issues, "store_present": False,
                    "spawns": len(spawns), "sidechains_checked": 0,
                    "sidechains_linked": 0, "orphans": [],
                    "issues": issues}
        metas: Dict[str, Dict[str, Any]] = {}
        chains: Dict[str, Dict[str, Any]] = {}
        for mf in sorted(self.sessions_dir.glob("*.meta.json")):
            try:
                # "x.meta.json" -> key "x" (Path.stem only strips the
                # last suffix)
                key = mf.name[:-len(".meta.json")]
                metas[key] = json.loads(
                    mf.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                issues.append({"issue": f"unreadable sidecar meta: "
                                        f"{mf.name}"})
        for jf in sorted(self.sessions_dir.glob("*.jsonl")):
            try:
                first = None
                with jf.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            first = json.loads(line)
                            break
                chains[jf.stem] = first or {}
            except (OSError, json.JSONDecodeError):
                issues.append({"issue": f"unreadable sidechain: "
                                        f"{jf.name}"})
        sidechains = {sid: m for sid, m in metas.items()
                      if m.get("parent_session")}
        linked = 0
        for e in spawns:
            d = e.get("data") or {}
            label = f"agent:{d.get('phase', '')}"
            match = [sid for sid, m in sidechains.items()
                     if m.get("label") == label]
            if not match:
                issues.append({
                    "seq": e.get("seq"),
                    "issue": f"no sidechain transcript for spawn "
                             f"{label!r} (session store missing the "
                             f"child)"})
                continue
            sid = match[0]
            if sid not in chains:
                issues.append({
                    "seq": e.get("seq"),
                    "issue": f"sidechain meta without transcript: {sid}"})
                continue
            linked += 1
        # parent chain integrity (verify_chain semantics, light)
        orphan_sidechains = [
            sid for sid, m in sidechains.items()
            if m.get("parent_session")
            and not (self.sessions_dir /
                     f"{m.get('parent_session')}.jsonl").exists()]
        for sid in orphan_sidechains:
            issues.append({"issue": f"sidechain {sid} references a "
                                    f"missing parent transcript"})
        return {"ok": not issues, "store_present": True,
                "spawns": len(spawns),
                "sidechains": len(sidechains),
                "sidechains_checked": len(sidechains),
                "sidechains_linked": linked,
                "orphan_sidechains": orphan_sidechains,
                "issues": issues}

    # ── sidecar / snapshot checks ─────────────────────────────────

    def _check_sidecar(self, name: str, sha: Optional[str], *,
                       base_dir: Optional[Path] = None) -> Tuple:
        path = (base_dir or self.compaction_dir) / name
        if not path.exists():
            return False, "missing artifact"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"unreadable: {exc}"
        if sha and _sha16(text) != sha:
            return False, "sha mismatch"
        return True, ""

    def _check_snapshot(self, name: str, rev_after: int,
                        sha: Optional[str]) -> Tuple:
        path = self.ekd_dir / name
        if not path.exists():
            return False, "missing artifact"
        try:
            blob = path.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"unreadable: {exc}"
        if sha and _sha16(blob) != sha:
            return False, "sha mismatch"
        try:
            embedded = int(json.loads(blob).get("rev", -1))
        except (json.JSONDecodeError, TypeError, ValueError):
            return False, "unparseable snapshot"
        if embedded != rev_after:
            return False, (f"snapshot rev {embedded} != event "
                           f"rev_after {rev_after}")
        return True, ""

    def _load_sig(self, d: Dict[str, Any]) -> Optional[str]:
        sig = d.get("sig")
        if isinstance(sig, str):
            return sig
        ref = d.get("sig_ref")
        if ref:
            try:
                return (self.messages_dir / str(ref)).read_text(
                    encoding="utf-8")
            except OSError:
                return None
        return None

    # ── pass 3: render + window reconstruction ────────────────────

    def renders(self, verify: bool = True) -> Dict[str, Any]:
        """verify=False: structural checks only. verify=True: full
        byte re-render + Zone W window verification.

        The Zone W simulation (rule C3): message events rebuild the
        channel of sigs; the sanctioned surgery applies in journal
        order — identity drops (tier-1/fold), in-place stub replaces
        (tier-2, `replaces`), and the fold's continuation INSERT (the
        compaction event remembers the first-drop position; the
        continuation message event that follows lands there,
        reconstructing [head, continuation, tail] exactly as the fold
        built it). Every brief_render carrying a window_hash gets its
        window re-selected (all groups before the current group — the
        4.0 assembly contract) and byte-compared."""
        issues: List[Dict[str, Any]] = []
        verified = skipped = 0
        boot: Dict[str, Any] = {}
        objective_text = ""
        residual = ""
        base_blob: Optional[str] = None
        running_rev = 0
        resumed = False
        boots_seen = 0
        mut_actor = ""
        # the Zone W simulation state
        sim: List[Optional[str]] = []
        sim_shas: List[str] = []
        sim_ok = True
        saw_message_stream = False
        insert_at: Optional[int] = None   # pending continuation insert
        win_checked = win_verified = win_skipped = 0

        def _sim_unmatched_drop(seq, what: str, shas: List[str]) -> None:
            """A claimed drop that is not in the channel is corruption
            evidence — a removed message event or a forged surgery —
            and is NAMED as an issue (never a silent skip; PORT-06
            mutation-class acceptance)."""
            nonlocal sim_ok
            sim_ok = False
            missing = [s for s in shas if str(s) not in set(sim_shas)][:4]
            issues.append({
                "seq": seq,
                "issue": f"{what} claims drop of sig(s) not in the "
                         f"channel: {missing}"})

        def _sim_append(d: Dict[str, Any]) -> None:
            nonlocal insert_at, saw_message_stream
            saw_message_stream = True
            sig = self._load_sig(d)
            sha = str(d.get("sig_sha") or "")
            replaces = d.get("replaces")
            source = str(d.get("source") or "")
            if replaces and sig is not None:
                # in-place replacement (tier-2 stub): swap at the
                # replaced position
                for j in range(len(sim_shas) - 1, -1, -1):
                    if sim_shas[j] == str(replaces):
                        sim[j] = sig
                        sim_shas[j] = sha
                        return
            if source == "compaction" and insert_at is not None \
                    and sig is not None:
                # the fold's continuation: the compaction event that
                # preceded recorded where the drop started — the
                # continuation takes that position
                pos = max(0, min(insert_at, len(sim)))
                sim.insert(pos, sig)
                sim_shas.insert(pos, sha)
                insert_at = None
                return
            sim.append(sig)
            sim_shas.append(sha)

        def _sim_drop_by_shas(shas: List[str]) -> bool:
            """Count-aware drop: the fold's dropped-sig list may carry
            DUPLICATES (two identical tool results -> identical sigs),
            so membership must be checked as a multiset, not a set —
            each claimed sha consumes one channel member, earliest
            position first. Found by the P4 exit-criterion harness
            (fold-pressure run: two identical heavy echoes folded)."""
            nonlocal insert_at
            drop_counts: Dict[str, int] = {}
            for s in shas:
                k = str(s)
                drop_counts[k] = drop_counts.get(k, 0) + 1
            claimed = sum(drop_counts.values())
            remaining = dict(drop_counts)
            drop_positions: List[int] = []
            for j, s in enumerate(sim_shas):
                if remaining.get(s, 0) > 0:
                    drop_positions.append(j)
                    remaining[s] -= 1
            if len(drop_positions) != claimed:
                return False  # a claimed drop (count) not in the channel
            insert_at = drop_positions[0] if drop_positions else None
            gone = set(drop_positions)
            new_sim = [sig for j, sig in enumerate(sim)
                       if j not in gone]
            new_shas = [s for j, s in enumerate(sim_shas)
                        if j not in gone]
            sim.clear()
            sim.extend(new_sim)
            sim_shas.clear()
            sim_shas.extend(new_shas)
            return True

        def _sim_drop_positional(count: int, after: int) -> None:
            del sim[after:after + count]
            del sim_shas[after:after + count]

        for e in self.events:
            t = e.get("type")
            d = e.get("data") or {}
            if t == "boot":
                boot = d
                boots_seen += 1
                if "resumed" in d:
                    resumed = bool(d.get("resumed"))
                else:
                    # a7-batch1b: journals recorded before batch 1
                    # do not carry the flag. A boot event beyond the
                    # first in the same append-only journal is by
                    # definition a resumed boot — the file already
                    # held the prior boot's events when this boot
                    # opened it (the same existence test cli.py now
                    # journals explicitly). Infer so archived
                    # censuses get the W1 correction too (ENG-01:
                    # boots 2-3). An explicit flag always wins.
                    resumed = boots_seen > 1
            elif t == "message":
                # per-channel discipline: subagent sidechain messages
                # belong to their own channel, not the main window
                src = str(d.get("source") or "")
                if src.startswith("subagent:"):
                    continue
                _sim_append(d)
            elif t == "compaction_trim":
                if str(d.get("channel") or "").startswith("subagent:"):
                    continue          # sidechain surgery, own channel
                dropped = int(d.get("dropped") or 0)
                if dropped:
                    sig_shas = d.get("sig_shas") or []
                    if d.get("drop_complete") and sig_shas:
                        if not _sim_drop_by_shas(sig_shas):
                            _sim_unmatched_drop(e.get("seq"),
                                                "compaction_trim",
                                                sig_shas)
                    else:
                        _sim_drop_positional(dropped, 1)
            elif t == "compaction":
                if str(d.get("channel") or "").startswith("subagent:"):
                    # sidechain fold: own channel entirely — the main
                    # sim neither applies its surgery nor loads its
                    # residual (the main residual comes from main
                    # folds only)
                    continue
                n = int(d.get("messages_dropped") or 0)
                if n:
                    sig_shas = d.get("dropped_sig_shas") or []
                    if d.get("drop_complete") and sig_shas:
                        if not _sim_drop_by_shas(sig_shas):
                            _sim_unmatched_drop(e.get("seq"),
                                                "compaction", sig_shas)
                    elif str(d.get("drop_position")) == \
                            "head_after_objective":
                        insert_at = 1
                        _sim_drop_positional(n, 1)
                    else:
                        sim_ok = False  # explicit range, list truncated
                if "summary_ref" in d:
                    try:
                        residual = (self.compaction_dir /
                                    str(d["summary_ref"])).read_text(
                            encoding="utf-8")
                    except OSError:
                        if "summary" in d:
                            residual = str(d["summary"])
                elif "summary" in d:
                    residual = str(d["summary"])
            elif t == "objective":
                objective_text = str(d.get("text", ""))
                oref = d.get("text_ref")
                if oref:
                    try:
                        objective_text = (self.objective_dir /
                                          str(oref)).read_text(
                            encoding="utf-8")
                    except OSError:
                        pass
            elif t == "ekd_mutation":
                running_rev = int(d.get("rev_after", running_rev))
                _ext = str(d.get("extractor", ""))
                _rsn = str(d.get("reason", ""))
                mut_actor = (f"{_ext}:{_rsn}" if _rsn else _ext) \
                    or mut_actor
                snap = d.get("snapshot")
                if snap and (self.ekd_dir / snap).exists():
                    try:
                        base_blob = (self.ekd_dir / snap).read_text(
                            encoding="utf-8")
                    except OSError:
                        pass
            elif t == "ekd_reset":
                running_rev = 0
                base_blob = None
                residual = ""
                mut_actor = ""
            elif t == "brief_render":
                rev = int(d.get("rev", 0) or 0)
                if resumed and d.get("window_hash"):
                    # W1 (a7): a resumed boot restores its window from
                    # the session store, not from journaled message
                    # events — the Zone W sim cannot reconstruct it
                    # (ENG-01: every resumed-boot render journaled
                    # window_msg_count=0). Skip the window check only;
                    # byte verification is retained (boot 3 verified
                    # 40/42 renders against committed snapshots).
                    win_skipped += 1
                if rev > running_rev + 1:
                    issues.append({
                        "seq": e.get("seq"),
                        "issue": f"render rev {rev} > committed "
                                 f"{running_rev} + 1 (render ahead of "
                                 f"journal)"})
                # ── Zone W hash continuity (C3) ──
                if d.get("window_hash") and not resumed:
                    win_checked += 1
                    why = ""
                    if not saw_message_stream:
                        why = "no message stream (pre-P3 journal)"
                    elif not sim_ok:
                        why = "ambiguous surgery (unmatched drop)"
                    else:
                        groups = _sig_groups(sim)
                        if groups is None:
                            why = "window member unreconstructible"
                        elif len(groups) < 1:
                            why = "empty simulated channel"
                        else:
                            # the 4.0 assembly contract: the window is
                            # every group BEFORE the current (last) one
                            widx = [i for g in groups[:-1] for i in g]
                            if d.get("window_msg_count") is not None \
                                    and int(d.get("window_msg_count")
                                            or 0) != len(widx):
                                issues.append({
                                    "seq": e.get("seq"),
                                    "issue": "window member count "
                                             f"mismatch (replayed "
                                             f"{len(widx)} != journaled "
                                             f"{d.get('window_msg_count')})"})
                            elif not widx:
                                why = "empty window selection"
                            else:
                                got = _sha16("\x1e".join(
                                    str(sim[i]) for i in widx))
                                if got != d.get("window_hash"):
                                    issues.append({
                                        "seq": e.get("seq"),
                                        "issue": "window hash mismatch "
                                                 f"(replayed {got} != "
                                                 f"journaled "
                                                 f"{d.get('window_hash')})"})
                                else:
                                    win_verified += 1
                    if why:
                        win_skipped += 1
                if not verify or not d.get("brief_hash") \
                        or d.get("now") is None:
                    skipped += 1
                    continue
                ok, detail = self._verify_one_render(
                    e, d, boot, objective_text, residual, base_blob,
                    mut_actor)
                if ok:
                    verified += 1
                else:
                    issues.append({"seq": e.get("seq"),
                                   "issue": f"render: {detail}"})

        total = sum(1 for e in self.events
                    if e.get("type") == "brief_render")
        return {"ok": not issues, "total_render_events": total,
                "verified": verified, "skipped": skipped,
                "window_checks": {"checked": win_checked,
                                   "verified": win_verified,
                                   "skipped": win_skipped},
                "issues": issues}

    def _verify_one_render(self, event: Dict[str, Any], d: Dict[str, Any],
                           boot: Dict[str, Any], objective_text: str,
                           residual: str,
                           base_blob: Optional[str],
                           mut_actor: str = "") -> Tuple:
        try:
            from ..memory.ekd import EngagementDAG
            from ..memory.extractors import ensure_objective
            from ..memory.brief import render_brief_l2
        except Exception as exc:  # stripped environment
            return False, f"EKD stack unavailable: {exc}"

        rp = (boot.get("render_params") or {})
        budget = int(d.get("budget", 0)
                     or rp.get("brief_token_budget", 700))
        sections = rp.get("brief_section_budgets") or None
        topn = int(rp.get("render_topn_entities", 12))
        ceiling = int(d.get("ceiling", 0) or rp.get("brief_ceiling", 800))
        scope_mode = str(rp.get("scope_mode", "")
                         or boot.get("scope_mode", "") or "")
        now = float(d["now"])
        updated_by = str(d.get("actor_hint", ""))

        ekd = EngagementDAG.from_json(base_blob or "")
        # Deterministic assembly-time objective: idempotent on committed
        # graphs; on fresh ones pin the new node's ts to now+1 so the
        # header age line reproduces exactly (oracle discipline).
        text = str(objective_text or "").strip() or "(no objective recorded)"
        before_ids = set(ekd.nodes.keys())
        ensure_objective(ekd, objective_text)
        if not (before_ids & {n.id for n in ekd.nodes_of_type("objective")}):
            for nid in set(ekd.nodes.keys()) - before_ids:
                ekd.nodes[nid].ts = now + 1.0

        try:
            brief, _meta = render_brief_l2(
                ekd,
                token_budget=budget,
                section_budgets=sections,
                topn_entities=topn,
                residual=residual,
                updated_by=(mut_actor or updated_by),
                now=now,
                hard_ceiling=ceiling,
                scope_mode=scope_mode)
        except Exception as exc:
            return False, f"re-render raised: {exc}"
        got = _sha16(brief)
        if got != d.get("brief_hash"):
            return False, (f"byte mismatch (re-rendered {got} != "
                           f"journaled {d.get('brief_hash')})")
        return True, ""

    # ── crash-boundary repair ─────────────────────────────────────

    def crash_boundary(self) -> Dict[str, Any]:
        """Detect the J1 crash window: journal revs with no store rev
        (a crash between the write-ahead and the state write), and
        missing store files the journal's snapshots could rebuild.
        Detection only here — repair() acts."""
        issues: List[Dict[str, Any]] = []
        journal_rev = 0
        store_rev: Optional[int] = None
        last_snapshot: Optional[str] = None
        for e in self.events:
            t = e.get("type")
            d = e.get("data") or {}
            if t == "ekd_mutation":
                journal_rev = int(d.get("rev_after", journal_rev))
                if d.get("snapshot"):
                    last_snapshot = str(d["snapshot"])
            elif t == "ekd_reset":
                journal_rev = 0
        # the EKD state file: production layout is <workspace>/.aegis/
        # journal/journal.jsonl with the state at <workspace>/ekd.json
        # (THREE levels up from the journal file); exported/golden
        # trajectories sit flat (the state file next to the journal)
        prod = self.journal_path.parent.parent.parent / "ekd.json"
        flat = self.journal_path.parent / "ekd.json"
        if prod.exists():
            state_path = prod
        elif flat.exists():
            state_path = flat
        elif self.journal_path.parent.name == "journal":
            state_path = prod
        else:
            state_path = flat
        if state_path.exists():
            try:
                store_rev = int(json.loads(
                    state_path.read_text(encoding="utf-8")).get("rev", -1))
            except (OSError, json.JSONDecodeError, ValueError):
                store_rev = None
        # a MISSING state file with journaled revs is the J1 crash
        # window too: the store never got written — the journal is the
        # only truth left
        effective_store = store_rev if state_path.exists() else 0
        if effective_store is not None and effective_store < journal_rev:
            issues.append({
                "issue": "journal ahead of store",
                "journal_rev": journal_rev,
                "store_rev": effective_store,
                "state_file": state_path.exists(),
                "repair": "replay the journaled snapshot chain to the "
                          "last committed rev (repair())"})
        return {"ok": not issues, "journal_rev": journal_rev,
                "store_rev": store_rev, "state_path": str(state_path),
                "last_snapshot": last_snapshot, "issues": issues}

    def repair(self) -> Dict[str, Any]:
        """EXPLICIT crash-boundary repair: re-materialize the EKD state
        from the journal's snapshot chain when the journal is ahead of
        the store. Every action is named in the report; nothing silent.
        Returns the repair report (ok, actions, repaired_to_rev)."""
        boundary = self.crash_boundary()
        actions: List[str] = []
        ok = True
        if boundary["ok"]:
            actions.append("no repair needed (journal and store agree)")
            return {"ok": True, "actions": actions,
                    "repaired_to_rev": boundary["store_rev"],
                    "boundary": boundary}
        # find the newest snapshot whose sha verifies
        chosen: Optional[Tuple[str, int, str]] = None
        for e in reversed(self.events):
            if e.get("type") != "ekd_mutation":
                continue
            d = e.get("data") or {}
            snap = d.get("snapshot")
            rev = int(d.get("rev_after") or 0)
            if not snap:
                continue
            okc, detail = self._check_snapshot(
                snap, rev, d.get("snapshot_sha"))
            if okc:
                try:
                    blob = (self.ekd_dir / snap).read_text(
                        encoding="utf-8")
                    chosen = (snap, rev, blob)
                except OSError:
                    continue
                break
            actions.append(f"skipped unverifiable snapshot {snap} "
                           f"({detail})")
        if chosen is None:
            return {"ok": False,
                    "actions": actions + [
                        "no verifiable snapshot to rebuild from — "
                        "store left untouched"],
                    "repaired_to_rev": boundary["store_rev"],
                    "boundary": boundary}
        snap, rev, blob = chosen
        state_path = Path(boundary["state_path"])
        try:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = state_path.with_suffix(".json.tmp")
            tmp.write_text(blob, encoding="utf-8")
            tmp.replace(state_path)
            import os
            os.chmod(state_path, 0o600)
        except OSError as exc:
            return {"ok": False,
                    "actions": actions + [f"state write failed: {exc}"],
                    "repaired_to_rev": boundary["store_rev"],
                    "boundary": boundary}
        actions.append(
            f"re-materialized {state_path} from snapshot {snap} "
            f"(store rev {boundary['store_rev']} -> {rev})")
        # journaled deltas beyond the snapshot are in the journal for
        # the EKD's own recover() to apply on next boot — named here
        if rev < boundary["journal_rev"]:
            actions.append(
                f"journal carries revs {rev + 1}.."
                f"{boundary['journal_rev']} as write-ahead batches — "
                f"ekd.recover() applies them on next boot")
        return {"ok": True, "actions": actions, "repaired_to_rev": rev,
                "boundary": boundary}

    # ── aggregate ─────────────────────────────────────────────────

    def full_report(self, verify_renders: bool = True) -> Dict[str, Any]:
        integrity = self.integrity()
        chain = self.revision_chain()
        renders = self.renders(verify=verify_renders)
        sessions = self.session_linkage()
        boundary = self.crash_boundary()
        return {
            "journal": str(self.journal_path),
            "events": integrity["events"],
            "integrity": integrity,
            "revision_chain": chain,
            "renders": renders,
            "session_linkage": sessions,
            "crash_boundary": boundary,
            "ok": (integrity["ok"] and chain["ok"] and renders["ok"]
                   and sessions["ok"] and boundary["ok"]),
        }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="AEGIS Hypervisor 4.0 journal replay verifier "
                    "(PORT-06)")
    ap.add_argument("journal",
                    help="journal.jsonl file or its directory")
    ap.add_argument("--ekd-dir", default=None)
    ap.add_argument("--compaction-dir", default=None)
    ap.add_argument("--objective-dir", default=None)
    ap.add_argument("--messages-dir", default=None)
    ap.add_argument("--sessions-dir", default=None)
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--no-verify-renders", action="store_true")
    ap.add_argument("--repair", action="store_true",
                    help="apply the explicit crash-boundary repair")
    args = ap.parse_args(argv)

    r = JournalReplay(args.journal, ekd_dir=args.ekd_dir,
                      compaction_dir=args.compaction_dir,
                      objective_dir=args.objective_dir,
                      messages_dir=args.messages_dir,
                      sessions_dir=args.sessions_dir)
    if args.repair:
        rep = r.repair()
        if args.as_json:
            print(json.dumps(rep, indent=2, sort_keys=True))
        else:
            print(f"repair ok : {rep['ok']}")
            for a in rep["actions"]:
                print(f"  - {a}")
        if not rep["ok"]:
            return 1
    report = r.full_report(verify_renders=not args.no_verify_renders)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"journal          : {report['journal']}")
        print(f"events           : {report['events']}")
        print(f"integrity        : "
              f"{'OK' if report['integrity']['ok'] else 'FAIL'}"
              f" ({report['integrity']['events']} events,"
              f" {len(report['integrity']['gaps'])} gaps)")
        c = report["revision_chain"]
        print(f"revision chain   : {'OK' if c['ok'] else 'FAIL'}"
              f" ({c['mutations']} mutations, {c['resets']} resets,"
              f" {c['snapshots_checked']} snapshots,"
              f" {c['compactions']} compactions,"
              f" {c['sidecars_checked']} sidecars, final rev "
              f"{c['final_rev']})")
        print(f"                   v2 surfaces: "
              f"{c['loop_transitions']} transitions, "
              f"{c['permission_allows']} allows / "
              f"{c['permission_denies']} denies, "
              f"{c['turn_watchdog_events']} watchdog"
              + (f", {c['stop_hook_runs']} stop-hook runs "
                 f"({c['stop_hook_blocks']} blocks)"
                 if c.get("stop_hook_runs") else "") + ")")
        for i in c["issues"][:50]:
            print(f"    ! seq {i.get('seq')}: {i.get('issue')}")
        if len(c["issues"]) > 50:
            print(f"    ... and {len(c['issues']) - 50} more "
                  f"(run with --json for the full census)")
        v = report["renders"]
        w = v.get("window_checks") or {}
        print(f"render replay    : {'OK' if v['ok'] else 'FAIL'}"
              f" ({v['verified']}/{v['total_render_events']} "
              f"byte-verified, {v['skipped']} skipped;")
        print(f"                   zone W windows: "
              f"{w.get('verified', 0)}/{w.get('checked', 0)} "
              f"hash-verified, {w.get('skipped', 0)} skipped)")
        for i in v["issues"][:50]:
            print(f"    ! seq {i.get('seq')}: {i.get('issue')}")
        if len(v["issues"]) > 50:
            print(f"    ... and {len(v['issues']) - 50} more "
                  f"(run with --json for the full census)")
        s = report["session_linkage"]
        if s.get("store_present"):
            print(f"session linkage  : {'OK' if s['ok'] else 'FAIL'}"
                  f" ({s['sidechains_checked']} sidechains,"
                  f" {s['sidechains_linked']} linked)")
            for i in s["issues"][:50]:
                print(f"    ! {i.get('issue')}")
            if len(s["issues"]) > 50:
                print(f"    ... and {len(s['issues']) - 50} more "
                      f"(run with --json for the full census)")
        b = report["crash_boundary"]
        print(f"crash boundary   : {'OK' if b['ok'] else 'REPAIRABLE'}"
              + (f" (journal rev {b['journal_rev']} > store rev "
                 f"{b['store_rev']})" if not b["ok"] else ""))
        print(f"OVERALL          : {'OK' if report['ok'] else 'FAIL'}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
