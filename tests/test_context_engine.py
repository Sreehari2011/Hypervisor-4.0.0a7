"""Acceptance tests for the context engine (P2): window resolution +
budget manager (REFACTOR-01), zone assembly (REFACTOR-02), the tier
ladder + breaker + fold machinery (PORT-02), and PORT-01's byte-frozen
prompt family.
"""
import asyncio
import json
import os
from pathlib import Path

import pytest

from hypervisor.context.assemble import (
    EXPANSION_ATTACHMENT_OPEN, after_compact_boundary, assemble_prompt,
    group_message_indices, protected_boundary_of, select_working_window,
    sig_of, sig_sha_of, window_hash, window_is_pairing_safe,
)
from hypervisor.context.budget import (
    BudgetManager, chunk_messages, estimate_tokens, format_history_text,
    head_tail_truncate, resolve_context_window,
)
from hypervisor.context.compact import (
    AEGIS_ADDITIONAL_INSTRUCTIONS, CompactEngine, CompactState,
    build_continuation_message, chunk_directions, dropped_sig_shas,
    engagement_focus, format_compact_summary, get_compact_prompt,
    get_partial_compact_prompt, journal_transcript_pointer,
    plan_direction, stub_body, stub_message, tier0_attachment_hygiene,
    tier1_trim_plan, tier2_stub_targets, verify_id_preservation,
)
from hypervisor.memory.ekd import EngagementDAG
from hypervisor.memory.extractors import ensure_objective, parse_free_text
from hypervisor.persist.journal import Journal, message_sig


# ── PORT-01: byte-frozen prompt family ────────────────────────────────

ORACLE_PROMPTS = Path(
    os.environ.get("AEGIS_ORACLE_TREE",
                   "/home/z/my-project/Hypervisor-3.7.3")
) / "src/core/compact_prompts.py"


def test_prompt_constants_frozen_shas():
    """The sha16 pins from the UX-02 adaptation cut — a single changed
    byte anywhere in the family trips this. Replay semantics (UX-02
    finding, corrected from the port-era note): the summary_hash
    covers each fold's summary TEXT, journaled at fold time and
    verified against its sidecar; the templates shape FUTURE folds.
    prompt_hash is journaled forensics — replay asserts window_hash
    and brief_hash only. These pins remain the drift guard for the
    family; the six continuation/trailer/prefix constants are
    byte-identical to the oracle-era pins."""
    import hashlib
    from hypervisor.context import compact_prompts as cp
    pins = {
        "NO_TOOLS_PREAMBLE": "805264b7c4da85f1",
        "NO_TOOLS_TRAILER": "e8304a513b9da614",
        "BASE_COMPACT_TEMPLATE": "02418df14aa02221",
        "PARTIAL_COMPACT_TEMPLATE_FROM": "4366fe0bd808b290",
        "PARTIAL_COMPACT_TEMPLATE_UP_TO": "d4e365a816d10c51",
        "CONTINUATION_HEADER": "3a400c3c7217ffb1",
        "CONTINUATION_TRANSCRIPT_POINTER": "0a808405710cfff3",
        "CONTINUATION_RECENT_PRESERVED": "48539e58437fc91e",
        "CONTINUATION_RESUME_GUARD": "88ad74b02b98d989",
        "CONTINUATION_AUTONOMOUS_GUARD": "78305c99a4d5eae8",
        "ADDITIONAL_INSTRUCTIONS_PREFIX": "5728deca633e1448",
    }
    for name, sha in pins.items():
        got = hashlib.sha256(
            getattr(cp, name).encode("utf-8")).hexdigest()[:16]
        assert got == sha, f"{name} drifted: {got}"


def test_compaction_family_engagement_oriented():
    """UX-02: the compaction templates are engagement-native (VAPT),
    not coding-session texts. The load-bearing structure is asserted
    intact: nine numbered sections, the <analysis>/<summary> example
    shape, section 6 completeness and the section 9 verbatim-quote
    anti-drift clause (base + from; up_to carries the continuing-work
    variant by design)."""
    from hypervisor.context import compact_prompts as cp
    fam = [cp.BASE_COMPACT_TEMPLATE, cp.PARTIAL_COMPACT_TEMPLATE_FROM,
           cp.PARTIAL_COMPACT_TEMPLATE_UP_TO]
    for t in fam:
        # coding-era vocabulary is gone
        assert "continuing development work" not in t
        assert "Files and Code Sections" not in t
        assert "typescript" not in t
        assert "full code snippets" not in t
        # engagement vocabulary + structure are in
        assert "Hosts, Services, Endpoints and Artifacts" in t
        assert "credentials" in t and "tool commands" in t
        assert "<analysis>" in t and "<summary>" in t
        for i in range(1, 10):
            assert f"\n{i}. " in t or t.startswith(f"Your task") \
                or f"sections:\n\n{i}. " in t, f"section {i} missing"
        # section 6 completeness (anti-drift)
        assert "List ALL" in t
    # section 9 verbatim-quote anti-drift clause (base + from only)
    for t in (cp.BASE_COMPACT_TEMPLATE,
              cp.PARTIAL_COMPACT_TEMPLATE_FROM):
        assert "irect quotes" in t          # Include/include direct quotes
    assert "Context for Continuing Work" in \
        cp.PARTIAL_COMPACT_TEMPLATE_UP_TO
    # the preamble names AEGIS tools, not the upstream CLI's
    assert "Read, Bash, Grep, Glob, Edit, Write" not in \
        cp.NO_TOOLS_PREAMBLE
    assert "run_command" in cp.NO_TOOLS_PREAMBLE
    # the continuation pointer cites tool outputs, not code snippets
    assert "code snippets" not in cp.CONTINUATION_TRANSCRIPT_POINTER
    assert "tool outputs" in cp.CONTINUATION_TRANSCRIPT_POINTER
    assert "{transcriptPath}" in cp.CONTINUATION_TRANSCRIPT_POINTER


def test_prompt_family_byte_diff_against_oracle():
    """Direct byte-diff when the frozen oracle tree is present (the
    backup ships it under reference-repos/). UX-02: exactly five
    constants are expected to differ from the oracle (the three
    templates, the no-tools preamble, the transcript pointer); every
    other uppercase constant must still be byte-identical."""
    if not ORACLE_PROMPTS.exists():
        pytest.skip("oracle tree not present")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "oracle_prompts", ORACLE_PROMPTS)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    from hypervisor.context import compact_prompts as cp
    ux02_adapted = {
        "NO_TOOLS_PREAMBLE", "BASE_COMPACT_TEMPLATE",
        "PARTIAL_COMPACT_TEMPLATE_FROM", "PARTIAL_COMPACT_TEMPLATE_UP_TO",
        "CONTINUATION_TRANSCRIPT_POINTER"}
    for name in dir(oracle):
        if not name.isupper():
            continue
        if name in ux02_adapted:
            assert getattr(oracle, name) != getattr(cp, name), (
                f"{name} was NOT adapted but is on the UX-02 list")
        else:
            assert getattr(oracle, name) == getattr(cp, name), name


def test_assembly_seam_single_injection():
    p = get_compact_prompt("focus text")
    assert p.startswith("CRITICAL: Respond with TEXT ONLY")
    assert "focus text" in p
    assert "Additional Instructions:\nfocus text" in p
    assert p.endswith("you will fail the task.")
    # the AEGIS adaptation rides the seam verbatim
    full = get_partial_compact_prompt(AEGIS_ADDITIONAL_INSTRUCTIONS,
                                      direction="up_to")
    assert "ID PRESERVATION (binding)" in full
    assert engagement_focus("be quick").endswith("Operator focus: be quick")
    with pytest.raises(ValueError):
        get_partial_compact_prompt("", direction="sideways")


def test_stripper_and_directions():
    text = ("<analysis>thinking</analysis>\n<summary>\nLine one.\n\n\n\n"
            "Line two.\n</summary>")
    out, ok = format_compact_summary(text)
    assert ok and out.startswith("Summary:\nLine one.")
    assert "\n\n\n" not in out
    raw, ok2 = format_compact_summary("no summary block here")
    assert not ok2 and raw == "no summary block here"
    assert plan_direction(window_excess=True) == "from"
    assert plan_direction() == "up_to"
    assert chunk_directions(1, "up_to") == ["up_to"]
    assert chunk_directions(3, "from") == ["from"] * 3
    assert chunk_directions(1, "from", prefer_base=True) == ["base"]


def test_continuation_message_blocks():
    msg = build_continuation_message("Summary:\nstuff",
                                     transcript_pointer="J (seq 42)")
    assert msg.startswith("This session is being continued from a "
                          "previous conversation")
    assert "Summary:\nstuff" in msg
    assert "read the full transcript at: J (seq 42)" in msg
    assert "Recent messages are preserved verbatim." in msg
    assert "Continue the conversation from where it left off" in msg
    assert "autonomous/proactive mode" in msg
    ptr = journal_transcript_pointer("/j/dir", 7)
    assert "seq 7" in ptr and "/j/dir" in ptr


# ── budget: window resolution + thresholds ────────────────────────────

def test_window_resolution_env_override(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "26624")
    assert resolve_context_window("anything") == 26624
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "200k")
    assert resolve_context_window("x") == 200_000
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "1m")
    assert resolve_context_window("x") == 1_000_000
    monkeypatch.setenv("AEGIS_CONTEXT_WINDOW_TOKENS", "bogus")
    assert resolve_context_window("kimi-k2") == 128_000  # registry


def test_window_resolution_registry_and_default():
    # longest-key match beats shorter
    assert resolve_context_window("llama-3.1-70b") == 128_000
    assert resolve_context_workspace_safe("claude-sonnet-4-20250514") \
        == 200_000
    # unknown alias -> conservative default (with the loud warning)
    assert resolve_context_window("cisai-ultra") == 32_768


def resolve_context_workspace_safe(name):
    import io, logging as _l
    buf = io.StringIO()
    h = _l.StreamHandler(buf)
    _l.getLogger("AEGIS").addHandler(h)
    try:
        return resolve_context_window(name)
    finally:
        _l.getLogger("AEGIS").removeHandler(h)


def test_budget_manager_thresholds():
    bm = BudgetManager(131_072)
    assert bm.reserve == max(8000, int(131_072 * 0.25))
    assert bm.trigger == 131_072 - bm.reserve
    assert bm.target == int(131_072 * 0.35)
    assert bm.chunk_budget == int((131_072 - 4000) * 0.5)
    assert bm.microcompact_at < bm.trigger      # cheap stubs fire first
    assert bm.blocking_at > bm.trigger          # hard stop after the fold
    msgs = [{"role": "user", "content": "x" * 400}]
    assert estimate_tokens(msgs) == 100 + 8
    assert not bm.should_compress(msgs)
    big = [{"role": "user", "content": "y" * (bm.trigger * 4 + 40)}]
    assert bm.should_compress(big)
    huge = [{"role": "user", "content": "z" * (bm.blocking_at * 4 + 40)}]
    assert bm.should_block(huge)


def test_shaping_helpers():
    msgs = [{"role": "user", "content": "a" * 100},
            {"role": "assistant", "content": "b" * 100},
            {"role": "user", "content": "c" * 100}]
    chunks = chunk_messages(msgs, 60, estimate_tokens)
    assert len(chunks) == 3                     # each message its own chunk
    assert format_history_text(
        [{"role": "user", "content": "x" * 5000}],
        per_message_char_limit=100).count("TRUNCATED") == 1
    t = head_tail_truncate("z" * 1000, 200)
    assert len(t) < 400 and "aegis truncated" in t
    assert t.endswith("z" * 50)                 # tail kept verbatim


# ── assembly: grouping, window, sigs, zones ───────────────────────────

def _mk_convo(n_turns=6, heavy=False):
    """A realistic channel: objective, then assistant(tool_use) +
    user(tool_result) pairs, then a final user turn."""
    msgs = [{"role": "user", "content": "do the engagement"}]
    for i in range(n_turns):
        msgs.append({"role": "assistant", "content": [
            {"type": "text", "text": f"turn {i}"},
            {"type": "tool_use", "id": f"tu_{i}", "name": "run_command",
             "input": {"command": "echo hi"}}]})
        body = "B" * 5000 if heavy else f"output {i}"
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"tu_{i}",
             "content": body}]})
    msgs.append({"role": "user", "content": "final question"})
    return msgs


def test_grouping_never_splits_pairs():
    msgs = _mk_convo(4)
    groups = group_message_indices(msgs)
    # objective group, 4 assistant+result groups, final user group
    assert len(groups) == 6
    for g in groups[1:5]:
        assert len(g) == 2                       # assistant + its result
    assert window_is_pairing_safe(select_working_window(msgs, 3))
    assert not window_is_pairing_safe(msgs[2:])  # result without parent


def test_select_working_window_protects_objective():
    msgs = _mk_convo(8)
    w = select_working_window(msgs, 2)
    assert w[0] is msgs[0]                       # objective protected
    assert len(w) < len(msgs)
    assert window_is_pairing_safe(w)


def test_sig_adapter_frozen_formula():
    m = {"role": "user", "content": "hello world"}
    assert sig_of(m) == "user||hello world"
    tr = {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1",
         "content": "out"}]}
    assert sig_of(tr) == "user|tu_1|" + str(tr["content"])
    # stable identity for the surgery records
    assert sig_sha_of(m) == sig_sha_of(dict(m))


def test_after_compact_boundary():
    msgs = [{"role": "user", "content": "objective"},
            {"role": "assistant", "content": "old work"},
            {"role": "user", "content": "This session is being continued "
                                        "from a previous conversation "
                                        "that ran out of context.\nstuff"},
            {"role": "assistant", "content": "new work"}]
    out = after_compact_boundary(msgs)
    assert out[0] is msgs[0]
    assert out[1] is msgs[2]                     # pre-fold history dropped
    assert len(out) == 3
    assert after_compact_boundary(msgs[:2]) == msgs[:2]  # no marker: noop


def test_zone_assembly_s_w_t(tmp_path):
    from hypervisor.memory.brief import BriefRenderer
    j = Journal(tmp_path / "journal")
    ekd = EngagementDAG()
    ensure_objective(ekd, "the objective text")
    parse_free_text(ekd, "found 10.10.11.23 and "
                         "http://10.10.11.23/app", "c1", _NoScopeCtx())
    renderer = BriefRenderer(journal=j)

    class _Ctx:
        journal = j
        extra = {"renderer": renderer, "ekd": ekd,
                 "tail_attachments": {}, "episodic_residual": ""}
        permissions = None
        workspace = str(tmp_path)

    ctx = _Ctx()
    msgs = _mk_convo(3)
    prompt = assemble_prompt("SYSTEM PROMPT", msgs, ctx=ctx)
    # Zone S first, static
    assert prompt[0] == {"role": "system", "content": "SYSTEM PROMPT"}
    # Zone T: the brief attachment sits immediately before the current
    # turn's group (the final user message), never in the system prompt
    idx_att = next(i for i, m in enumerate(prompt)
                   if m["role"] == "user" and isinstance(m.get("content"), str)
                   and m["content"].startswith("<aegis-brief>"))
    assert prompt[-1] is msgs[-1]
    assert idx_att == len(prompt) - 2
    assert "SYSTEM PROMPT" not in prompt[idx_att]["content"]
    assert "the objective text" in prompt[idx_att]["content"]
    # prompt-only: state never mutated
    assert all("<aegis-brief>" not in json.dumps(m)[:20] for m in msgs)
    # J2 journaled with window + prompt hashes
    renders = j.events_of_type("brief_render")
    assert renders and renders[-1]["data"]["window_msg_count"] == len(msgs) - 1
    assert renders[-1]["data"].get("window_hash")
    # expansions ride Zone T after the brief
    ctx.extra["tail_attachments"] = {
        "x1": {"id": "e15", "text": "drilldown payload"}}
    prompt2 = assemble_prompt("SYSTEM PROMPT", msgs, ctx=ctx)
    exp = [m for m in prompt2
           if isinstance(m.get("content"), str)
           and m["content"].startswith(EXPANSION_ATTACHMENT_OPEN)]
    assert exp and "e15" in exp[0]["content"]


class _NoScopeCtx:
    journal = None
    extra = {}
    permissions = None
    workspace = ""
    label = "main"


def test_assembly_p1_fallback_without_renderer():
    msgs = _mk_convo(2)
    out = assemble_prompt("SYS", msgs)          # no ctx at all
    assert out[0]["role"] == "system"
    assert out[1:] == msgs


def test_protected_boundary():
    msgs = _mk_convo(6)
    b = protected_boundary_of(msgs, protect_groups=2)
    # the last 2 groups are intact from b onward
    groups = group_message_indices(msgs)
    assert b == groups[-2][0]
    assert window_is_pairing_safe(msgs[b:])


# ── the tier ladder ───────────────────────────────────────────────────

def test_tier0_attachment_hygiene():
    class _Ctx:
        extra = {"tail_attachments": {"a": {"id": "e1", "text": "x"},
                                     "b": {"id": "e2", "text": "y"}}}
    assert tier0_attachment_hygiene(_Ctx()) == 2
    assert tier0_attachment_hygiene(_Ctx()) == 0  # cleared


def test_tier1_trim_plan_protects_objective():
    msgs = _mk_convo(10)
    drop, k = tier1_trim_plan(msgs, k_reduced=3)
    assert 0 not in drop                        # objective never trimmed
    assert all(1 <= d < len(msgs) for d in drop)
    kept = [m for i, m in enumerate(msgs) if i not in set(drop)]
    assert window_is_pairing_safe(kept)
    assert len(group_message_indices(kept)) <= 3 + 2  # +objective+final


def test_tier2_stub_targets_and_replacement():
    msgs = _mk_convo(6, heavy=True)
    protect = protected_boundary_of(msgs, protect_groups=3)
    targets = tier2_stub_targets(msgs, protect_from=protect,
                                 char_threshold=1000)
    assert targets and all(t < protect for t in targets)
    m = msgs[targets[0]]
    stub = stub_body(m, tool_name="run_command",
                     ekd_ids=["c99"], journal_seq=17)
    assert stub.startswith("[aegis-microcompact: run_command result,")
    assert "c99" in stub and "seq 17" in stub
    replaced = stub_message(m, stub)
    ids = [b["tool_use_id"] for b in replaced["content"]
           if b.get("type") == "tool_result"]
    assert ids == ["tu_0"]                       # pairing preserved
    assert sig_sha_of(replaced) != sig_sha_of(m)


def test_verify_id_preservation():
    ekd = EngagementDAG()
    ensure_objective(ekd, "obj")
    parse_free_text(ekd, "host 10.10.11.23 with SQL injection",
                    "c1", _NoScopeCtx())
    host = ekd.by_key("ip:10.10.11.23")
    # mention without id -> violation
    v = verify_id_preservation("we saw 10.10.11.23 today", ekd)
    assert any(x["id"] == host.id for x in v)
    # mention with id -> clean
    assert verify_id_preservation(
        f"we saw {host.id} (10.10.11.23) today", ekd) == []
    # short titles are noise; unmentioned titles are not mentions
    assert verify_id_preservation("nothing relevant", ekd) == []


def test_dropped_sig_shas_capped():
    msgs = _mk_convo(30)
    shas = dropped_sig_shas(msgs, cap=5)
    assert len(shas) == 5 and len(set(shas)) == 5


# ── the breaker ───────────────────────────────────────────────────────

def test_breaker_three_failures_open_reset_override(tmp_path):
    j = Journal(tmp_path / "journal")
    st = CompactState()
    r1 = st.record_failure(j, "e1")
    r2 = st.record_failure(j, "e2")
    assert not st.breaker_open and r2["action"] == "counted"
    r3 = st.record_failure(j, "e3")
    assert st.breaker_open and r3["action"] == "open"
    evs = j.events_of_type("compaction_breaker")
    assert [e["data"]["action"] for e in evs] == \
        ["counted", "counted", "open"]
    # success resets
    st.record_success(j)
    assert not st.breaker_open and st.failures == 0
    evs = j.events_of_type("compaction_breaker")
    assert evs[-1]["data"]["action"] == "reset"
    # override bypasses but journals
    st.note_override(j)
    assert j.events_of_type("compaction_breaker")[-1]["data"]["action"] \
        == "override"


def test_breaker_threshold_env(monkeypatch):
    monkeypatch.setenv("AEGIS_COMPACT_BREAKER_THRESHOLD", "1")
    from hypervisor.context.compact import breaker_threshold
    assert breaker_threshold() == 1
    monkeypatch.setenv("AEGIS_COMPACT_BREAKER_THRESHOLD", "not-a-number")
    assert breaker_threshold() == 3


# ── the engine: budget cascade + microcompact ─────────────────────────

class _Ctx2:
    def __init__(self, journal=None, extra=None):
        self.journal = journal
        self.extra = dict(extra or {})
        self.permissions = None
        self.workspace = ""
        self.label = "main"


def test_apply_tool_result_budget_caps_old_results(tmp_path):
    j = Journal(tmp_path / "journal")
    # small window -> per-message char cap (2048) < the 5000-char
    # heavy bodies, so pre-window results qualify for the cascade
    bm = BudgetManager(8192)
    eng = CompactEngine(bm, protect_groups=3)
    ctx = _Ctx2(j)
    msgs = _mk_convo(8, heavy=True)
    out = eng.apply_tool_result_budget(msgs, ctx)
    assert len(out) == len(msgs)
    # some old tool result got capped (truncation marker present)
    capped = [m for m in out
              if "aegis truncated" in json.dumps(m.get("content"))]
    assert capped
    # the NEWEST tool results (inside the protected window) untouched
    newest = out[-2]
    assert "aegis truncated" not in json.dumps(newest.get("content"))
    # surgery journaled with replaces pairing
    trims = [e for e in j.events_of_type("compaction_trim")
             if e["data"]["tier"] == 2]
    assert trims and trims[-1]["data"]["replaces"]
    assert estimate_tokens(out) < estimate_tokens(msgs)


def test_microcompact_stubs_below_trigger():
    bm = BudgetManager(8192)
    bm.microcompact_at = 10          # force the threshold to fire
    eng = CompactEngine(bm, protect_groups=3)
    ctx = _Ctx2()
    ctx.extra["ekd_call_ids"] = {"tu_0": "c1"}
    msgs = _mk_convo(8, heavy=True)
    out = asyncio.run(eng.microcompact(msgs, ctx))
    stubs = [m for m in out
             if "aegis-microcompact" in json.dumps(m.get("content"))]
    assert stubs
    # pairing preserved
    assert window_is_pairing_safe(out)
    # stub keeps the EKD ref when the call map knows the id
    assert "c1" in json.dumps(stubs[0])


# ── the fold (tier 3) with a fake summarizer ─────────────────────────

def _fake_summary(text):
    return ("<analysis>draft</analysis>\n<summary>\n"
            f"Summary of the slice. {text}\n</summary>")


def test_autocompact_fold_full_path(tmp_path):
    j = Journal(tmp_path / "journal")
    ekd = EngagementDAG()
    ensure_objective(ekd, "the objective")
    parse_free_text(ekd, "found 10.10.11.23", "c1", _NoScopeCtx())

    class _Session:
        summaries = []
        def append_summary(self, text, **kw):
            self.summaries.append(text)

    session = _Session()
    ctx = _Ctx2(j, {"ekd": ekd, "session": session,
                    "objective_id": "O1", "episodic_residual": ""})

    # tiny window so the fold fires on a modest channel
    bm = BudgetManager(2048)
    seen_prompts = []

    async def summarizer(messages, max_tokens):
        seen_prompts.append(messages)
        return _fake_summary("chunk content")

    eng = CompactEngine(bm, summarizer=summarizer, protect_groups=2)
    msgs = _mk_convo(10, heavy=True)
    assert bm.should_compress(msgs)

    out, folded = asyncio.run(eng.autocompact(msgs, ctx))
    assert folded is True
    # the channel now opens with objective + continuation, and shrank
    assert estimate_tokens(out) < estimate_tokens(msgs)
    cont = out[1]
    assert cont["role"] == "user"
    assert cont["content"].startswith(
        "This session is being continued from a previous conversation")
    assert "Summary:" in cont["content"]
    assert "read the full transcript at:" in cont["content"]
    # the summarizer saw the verbatim prompt family (preamble + seam)
    first_call = seen_prompts[0]
    assert first_call[0]["role"] == "system"
    sys_text = first_call[0]["content"]
    assert sys_text.startswith("CRITICAL: Respond with TEXT ONLY")
    assert "ID PRESERVATION (binding)" in sys_text
    assert "AEGIS autonomous black-box VAPT" in sys_text
    # compaction event journaled with the full surgery record
    comps = j.events_of_type("compaction")
    assert comps
    c = comps[-1]["data"]
    assert c["direction"] in ("up_to", "from") and c["tier"] == 3
    assert c["messages_dropped"] > 0
    assert c["dropped_sig_shas"] and c["drop_complete"]
    assert c["summary_hash"]
    assert c["id_violations"] == 0
    # residual recorded for the brief + session summary chain
    assert ctx.extra["episodic_residual"].startswith("Summary:")
    assert session.summaries and session.summaries[0].startswith("Summary:")
    # the pair-safety of the surviving window
    assert window_is_pairing_safe(out)
    # fold audit ran: hard facts in the folded slice are graph nodes
    assert ekd.by_key("ip:10.10.11.23") is not None


def test_autocompact_noop_below_trigger():
    bm = BudgetManager(131_072)
    eng = CompactEngine(bm)
    ctx = _Ctx2()
    msgs = _mk_convo(3)
    out, folded = asyncio.run(eng.autocompact(msgs, ctx))
    assert out == msgs and folded is False


def test_autocompact_breaker_open_deterministic_only(tmp_path):
    j = Journal(tmp_path / "journal")
    bm = BudgetManager(2048)
    eng = CompactEngine(bm)          # NO summarizer: fold unavailable
    eng.state.breaker_open = True
    ctx = _Ctx2(j)
    msgs = _mk_convo(12, heavy=True)
    out, folded = asyncio.run(eng.autocompact(msgs, ctx))
    assert folded is True
    assert estimate_tokens(out) < estimate_tokens(msgs)
    # deterministic trim journaled; NO compaction (fold) event
    assert j.events_of_type("compaction") == []
    assert any(e["data"].get("reason") == "breaker_open_deterministic_relief"
               for e in j.events_of_type("compaction_trim"))
    # objective survives
    assert out[0] is msgs[0]


def test_autocompact_failure_counts_toward_breaker(tmp_path):
    j = Journal(tmp_path / "journal")
    bm = BudgetManager(2048)

    async def bad_summarizer(messages, max_tokens):
        raise RuntimeError("summarizer down")

    eng = CompactEngine(bm, summarizer=bad_summarizer, protect_groups=2)
    ctx = _Ctx2(j)
    msgs = _mk_convo(10, heavy=True)
    out, folded = asyncio.run(eng.autocompact(msgs, ctx))
    # deterministic relief still applied
    assert folded is True
    assert eng.state.failures == 1
    evs = [e["data"]["action"] for e in
           j.events_of_type("compaction_breaker")]
    assert "counted" in evs
    # three failures open it
    asyncio.run(eng.autocompact(_mk_convo(10, heavy=True), ctx))
    asyncio.run(eng.autocompact(_mk_convo(10, heavy=True), ctx))
    assert eng.state.breaker_open is True


# ── PORT-10: zone fingerprinting (drift guard) ───────────────────────

def test_fingerprint_frozen_vector():
    from hypervisor.context.fingerprint import assembly_fingerprint
    import hashlib
    fp = assembly_fingerprint("kimi-k2", ["b", "a", ""], "SYS")
    # tool order normalized; empty names dropped
    assert fp == assembly_fingerprint("kimi-k2", ["a", "b"], "SYS")
    assert fp == hashlib.sha256(
        b"kimi-k2|a,b|" + hashlib.sha256(b"SYS").hexdigest()[:16].encode()
    ).hexdigest()[:16]
    assert fp != assembly_fingerprint("kimi-k2", ["a", "b"], "SYST")
    # M13: same-length rewrite IS a change (content digest, not length)
    assert assembly_fingerprint("m", [], "AAAA") != \
        assembly_fingerprint("m", [], "BBBB")


def test_fingerprint_monitor_baseline_drift_strict(tmp_path):
    from hypervisor.context.fingerprint import (
        FingerprintMonitor, ZoneViolationError,
    )
    j = Journal(tmp_path / "journal")
    m = FingerprintMonitor(j)
    r1 = m.check_assembly("model-x", ["a", "b"], "SYS", turn=1)
    assert r1["baseline"] is True and r1["changed"] is False
    r2 = m.check_assembly("model-x", ["a", "b"], "SYS", turn=2)
    assert r2["changed"] is False
    # drift with attribution (model changed)
    r3 = m.check_assembly("model-y", ["a", "b"], "SYS", turn=3)
    assert r3["changed"] is True and r3["attributions"] == ["model"]
    # tools drift carries the diff detail
    r4 = m.check_assembly("model-y", ["a", "c"], "SYS", turn=4)
    assert "tools" in " ".join(r4["attributions"])
    # journaled: baseline + 2 drifts
    evs = j.events_of_type("cache_fingerprint")
    kinds = [e["data"]["kind"] for e in evs]
    assert kinds == ["baseline", "drift", "drift"]
    assert evs[1]["data"]["prev"] != evs[1]["data"]["fingerprint"]
    assert evs[1]["data"]["attributions"] == ["model"]
    assert m.summary()["drifts"] == 2 and m.summary()["checks"] == 4

    # strict mode: drift within the phase raises; phase transition
    # re-freezes the baseline (a legitimate change starts fresh)
    ms = FingerprintMonitor(j, strict=True)
    ms.check_assembly("m", ["t"], "SYS-1")
    with pytest.raises(ZoneViolationError, match="Zone S prefix changed"):
        ms.check_assembly("m", ["t"], "SYS-2")
    # baseline NOT advanced: the violation keeps firing
    with pytest.raises(ZoneViolationError):
        ms.check_assembly("m", ["t"], "SYS-2")
    ms.set_phase("exploit")
    r = ms.check_assembly("m", ["t"], "SYS-2")
    assert r["baseline"] is True and r["changed"] is False


def test_fingerprint_monitor_rides_assembly(tmp_path):
    from hypervisor.context.fingerprint import FingerprintMonitor
    from hypervisor.memory.brief import BriefRenderer
    j = Journal(tmp_path / "journal")
    ekd = EngagementDAG()
    ensure_objective(ekd, "obj")
    monitor = FingerprintMonitor(j)
    renderer = BriefRenderer(journal=j)

    class _Ctx:
        journal = j
        turn = 1
        extra = {"renderer": renderer, "ekd": ekd,
                 "tail_attachments": {}, "episodic_residual": "",
                 "fingerprint_monitor": monitor,
                 "model": "kemi-k2.7", "tool_names": ["run_command",
                                                      "memory_query"]}
        permissions = None
        workspace = str(tmp_path)

    msgs = [{"role": "user", "content": "go"}]
    assemble_prompt("SYS", msgs, ctx=_Ctx())
    assemble_prompt("SYS", msgs, ctx=_Ctx())
    assert monitor.summary()["checks"] == 2
    assert monitor.summary()["drifts"] == 0
    evs = j.events_of_type("cache_fingerprint")
    assert evs and evs[0]["data"]["kind"] == "baseline"
    assert evs[0]["data"]["model"] == "kemi-k2.7"
