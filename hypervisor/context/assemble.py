"""hypervisor.context.assemble — byte-stable zone assembly (P2).

REFACTOR-02: the 3.7.3 context_assembler (549 ln) reduced to the live
L2 contract (the 2026-10-06 strip made L2 THE assembly — the legacy
full-replay and 3.6 brief+window branches do not port; they were
replay-compat only).

Zone shape (rules C1-C3 / A1-A3 carried):
  Zone S  static system prompt — frozen within an engagement phase;
           NOTHING learned ever enters it (the 3.6 default of assembling
           the brief into the system-prompt area is precisely the
           violation this shape makes impossible; a per-turn-changing
           system prompt also destroys the endpoint's prefix cache)
  Zone W  the working window — the post-preflight channel the loop
           owns (pairing-safe by construction; selection-is-not-mutation
           applies to the STATE, the sanctioned rewrites are the
           compaction ladder's)
  Zone T  the tail rebuilt every turn: the rendered brief as ONE
           user-context attachment in the fixed <aegis-brief> delimiter
           pair, then any drilldown expansions, immediately before the
           current turn's group. Learned engagement knowledge enters
           ONLY here — this module is the single injector (C2).

Byte-stability contract (principle 8): prefix-cache-stable ordering —
system + window prefix stays byte-identical turn over turn; the Zone-T
attachment sits near the tail by construction. The full prompt hash +
window hash are pinned per render through the brief renderer's J2
journaling (record_brief_render carries prompt_hash + window_hash).

Message shape: 4.0 dict messages (role/content block lists). The
frozen journal.message_sig formula (attribute-based) is fed through a
read-only _MsgView adapter — the FORMULA is untouched; the dict gains
the attribute surface the formula reads (type / tool_call_id /
content), so window hashes and drop sigs stay comparable across the
whole journal history, oracle included.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..persist.journal import message_sig
from .budget import blocks_of, is_tool_result_msg, tool_call_ids, \
    tool_result_ids
from .fingerprint import ZoneViolationError

# Zone T expansion delimiters (the side-query drilldown seam, P4):
# each expansion rides Zone T as its own attachment directly after the
# brief attachment, entity id on the first inner line.
EXPANSION_ATTACHMENT_OPEN = "<aegis-drilldown>"
EXPANSION_ATTACHMENT_CLOSE = "</aegis-drilldown>"


# ─── the frozen-formula adapter ──────────────────────────────────────


class _MsgView:
    """Read-only attribute surface over a 4.0 dict message so the
    FROZEN journal.message_sig formula (getattr-based, unchanged since
    the oracle) can sign dict messages. The formula is never modified
    here — only its input is normalized."""

    __slots__ = ("type", "tool_call_id", "content")

    def __init__(self, m: Dict[str, Any]):
        self.type = str(m.get("role", "?"))
        tids = tool_result_ids(m)
        self.tool_call_id = tids[0] if tids else ""
        self.content = m.get("content", "")


def sig_of(m: Dict[str, Any]) -> str:
    """The canonical signature of a 4.0 dict message (frozen formula)."""
    return message_sig(_MsgView(m))


def journal_channel_message(journal: Any, m: Dict[str, Any], *,
                            source: str = "",
                            replaces: Optional[str] = None) -> None:
    """Journal one channel message event through the frozen-sig view
    (P3, PORT-06: Zone W reconstruction — replay rebuilds the channel
    from these events and byte-verifies the per-render window hashes).
    J4 discipline: never raises, never gates."""
    if journal is None:
        return
    try:
        journal.record_message(_MsgView(m), source=source,
                               replaces=replaces)
    except Exception:
        pass


def sig_sha_of(m: Dict[str, Any]) -> str:
    """sha16 of the canonical signature (drop/replace sig identity)."""
    return hashlib.sha256(
        sig_of(m).encode("utf-8", "ignore")).hexdigest()[:16]


# ─── grouping (pairing discipline, D6 carried) ───────────────────────


def group_message_indices(messages: Sequence[Dict[str, Any]]
                          ) -> List[List[int]]:
    """Group message indices into conversation 'pairs': an assistant
    message plus its trailing tool-result carriers is ONE group (never
    split); every other message is its own group."""
    groups: List[List[int]] = []
    current: Optional[List[int]] = None
    for idx, m in enumerate(messages):
        if is_tool_result_msg(m):
            if current is None:
                current = [idx]
                groups.append(current)
            else:
                current.append(idx)
        else:
            current = [idx]
            groups.append(current)
    return groups


def select_working_window(messages: Sequence[Dict[str, Any]], k_pairs: int,
                          protect_first: bool = True
                          ) -> List[Dict[str, Any]]:
    """The last k_pairs conversation groups, never splitting a
    tool-call/result pair, with messages[0] (the round objective)
    protected exactly as the lineage protected it."""
    if not messages:
        return []
    k = max(1, int(k_pairs))
    if len(messages) <= k * 2 + 2:
        return list(messages)
    groups = group_message_indices(messages)
    window_groups = groups[-k:]
    start_idx = window_groups[0][0]

    # pairing guard: if the window opens on a tool-result carrier, its
    # parent assistant message must come along (walk back until clean)
    while start_idx > 0 and is_tool_result_msg(messages[start_idx]):
        start_idx -= 1

    window = list(messages[start_idx:])
    if protect_first and start_idx > 0:
        window = [messages[0]] + window
    return window


def window_is_pairing_safe(window: Sequence[Dict[str, Any]]) -> bool:
    """No orphaned tool result inside the window (its assistant parent
    is also inside)."""
    have: set = set()
    for m in window:
        for cid in tool_call_ids(m):
            have.add(cid)
    for m in window:
        for rid in tool_result_ids(m):
            if rid not in have:
                return False
    return True


def window_hash(window: Sequence[Dict[str, Any]]) -> str:
    """The C3 audit surface: a stable hash over the window's message
    sigs (replay byte-verifies the per-render window with it)."""
    return hashlib.sha256("\x1e".join(
        sig_of(m) for m in window).encode("utf-8", "ignore")
    ).hexdigest()[:16]


def protected_boundary_of(messages: Sequence[Dict[str, Any]],
                          *, protect_groups: int) -> int:
    """The group-based boundary of the protected recent window: the
    message index where the last `protect_groups` conversation groups
    begin (whole groups — pairing-safe by construction). Tiers 2 and 3
    share this boundary: tier-2 stubs apply strictly BEFORE it (older
    than the protected window), the up_to fold range is
    messages[1:boundary], and the from fold range is
    messages[boundary:split-of-the-newest-groups]."""
    msgs = list(messages)
    groups = group_message_indices(msgs)
    n = max(1, int(protect_groups))
    if not groups:
        return len(msgs)
    tail = groups[-n:] if len(groups) > n else groups
    return tail[0][0]


# ─── the compact boundary (loop step 1; 3.7.3 continuation marker) ───


def after_compact_boundary(messages: Sequence[Dict[str, Any]]
                           ) -> List[Dict[str, Any]]:
    """Messages before the LAST continuation marker are replaced by the
    boundary record the fold left: [objective] + [continuation] +
    post-boundary tail. Live operation is a no-op (the fold already
    rewrote the channel); the step earns its keep on RESUME, when the
    rebuilt channel carries pre-fold history the fold's view must
    supersede, and on any state pollution the marker makes visible."""
    msgs = list(messages)
    marker_at = -1
    for i in range(len(msgs) - 1, -1, -1):
        m = msgs[i]
        if m.get("role") != "user":
            continue
        c = m.get("content")
        text = c if isinstance(c, str) else ""
        if text.startswith("This session is being continued from a "
                           "previous conversation"):
            marker_at = i
            break
    if marker_at <= 0:
        return msgs
    return [msgs[0]] + msgs[marker_at:]


# ─── the zone assembly (the single injector, C2) ─────────────────────


def zone_t_attachments(ctx: Any) -> List[Dict[str, Any]]:
    """Drilldown expansions riding Zone T after the brief (P4 seam —
    the side-query selector writes the store, tier-0 hygiene clears it
    at compaction boundaries; empty means byte-identical output)."""
    out: List[Dict[str, Any]] = []
    att = ((ctx.extra or {}).get("tail_attachments")
           if getattr(ctx, "extra", None) else None)
    if isinstance(att, dict) and att:
        for eid, e in list(att.items()):
            text = str((e or {}).get("text", ""))
            body = (f"{EXPANSION_ATTACHMENT_OPEN}\n"
                    f"{(e or {}).get('id', eid)}\n{text}\n"
                    f"{EXPANSION_ATTACHMENT_CLOSE}")
            out.append({"role": "user", "content": body})
    return out


def assemble_prompt(system_prompt: str,
                    messages: List[Dict[str, Any]],
                    ctx: Any = None
                    ) -> List[Dict[str, Any]]:
    """Zone assembly: S + W + [T] + current group.

    Without a renderer on the context this is the P1 shape (system +
    messages, byte-stable) — the engine slots stay optional so every P1
    test and subagent path keeps working. With one, the brief renders
    from the live EKD (cache-keyed), journals the render truthfully
    (J2: brief hash + prompt hash + window hash + pinned now), and is
    injected as the single Zone-T attachment immediately before the
    current turn's group — never into the system prompt, never
    interleaved into Zone W.

    Returns the prompt message array; STATE is never mutated here
    (selection-is-not-mutation — the injected attachment is
    prompt-only, state.messages stays clean).
    """
    extras: Dict[str, Any] = getattr(ctx, "extra", None) or {}
    renderer = extras.get("renderer")

    # PORT-10: the drift guard rides the render path — every assembly
    # checks the (model, tools, system content) triple against the
    # actor's baseline. Compute-only when no monitor is attached.
    monitor = extras.get("fingerprint_monitor")
    if monitor is not None:
        try:
            model = str(extras.get("model", ""))
            tool_names = [getattr(t, "name", str(t))
                          for t in (extras.get("tool_names") or [])]
            monitor.check_assembly(model, tool_names, system_prompt or "",
                                   turn=getattr(ctx, "turn", None))
        except ZoneViolationError:
            raise         # C1 strict mode: build-level error, aborts
        except Exception:
            pass          # the guard never gates the assembly otherwise

    out: List[Dict[str, Any]] = []
    if system_prompt:
        out.append({"role": "system", "content": system_prompt})

    if renderer is None:
        out.extend(messages)
        return out

    ekd = extras.get("ekd")
    msgs = list(messages)
    groups = group_message_indices(msgs)

    # split the current turn's group (the tail the model answers into)
    current: List[Dict[str, Any]] = []
    window = msgs
    if groups:
        cur_ids = groups[-1]
        cut = cur_ids[0]
        # defensive pairing guard: a current turn opening on an orphan
        # tool result (corrupted state) degrades to the plain P1 shape
        # rather than preceding it with the attachment in a position
        # that would orphan it further
        if not (cut > 0 and is_tool_result_msg(msgs[cut])):
            window = msgs[:cut]
            current = msgs[cut:]

    attachments: List[Dict[str, Any]] = []
    if ekd is not None:
        extras = getattr(ctx, "extra", None) or {}
        residual = extras.get("episodic_residual", "") or ""
        scope_mode = ""
        scope = getattr(getattr(ctx, "permissions", None), "scope", None)
        if scope is not None:
            scope_mode = str(getattr(scope, "mode", "") or "")
        actor = str(extras.get("ekd_last_actor", "") or "")
        attachment, facts = renderer.render_attachment(
            ekd, residual,
            updated_by=actor or "loop",
            scope_mode=scope_mode)
        attachments.append(attachment)
        # J2: journal the render with the assembly forensics
        w_hash = window_hash(window)
        prompt_body = "".join(
            (system_prompt or "") + _flat(window) + _flat(attachments)
            + _flat(current))
        renderer.journal_render(
            facts,
            prompt_hash=hashlib.sha256(
                prompt_body.encode("utf-8", "ignore")).hexdigest()[:16],
            window_msg_count=len(window),
            window_hash=w_hash)
    attachments.extend(zone_t_attachments(ctx))

    out.extend(window)
    out.extend(attachments)
    out.extend(current)
    return out


def _flat(msgs: List[Dict[str, Any]]) -> str:
    parts = []
    for m in msgs:
        c = m.get("content")
        parts.append(c if isinstance(c, str) else str(c))
    return "\n".join(parts)
