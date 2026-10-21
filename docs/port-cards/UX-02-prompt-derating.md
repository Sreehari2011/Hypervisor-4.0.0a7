# UX-02 — Prompt De-Upstreaming & Engagement Orientation

| | |
|---|---|
| Card | UX-02 (4.0-native addition, a7 candidate) |
| Component | Model-facing prompt surfaces: agent contracts + compaction family |
| 4.0 home | `hypervisor/agents/prompts.py`, `hypervisor/context/compact_prompts.py`, `hypervisor/context/compact.py` (seam) |
| Status | ✅ done |
| Supersedes | The port-era byte-freeze annotations on the six agent constants and the eleven compaction constants |

## Motivation (operator findings, post-pilot review)

Two model-facing prompt surfaces still carried the upstream CLI's
identity and orientation after the 3.7.3 → 4.0 clean-room rebuild:

1. **Identity.** `DEFAULT_AGENT_PROMPT` (the general-purpose fallback
   contract) opened with *"You are an agent for Claude Code,
   Anthropic's official CLI for Claude."* — an upstream identity
   declaration. The main-loop `SYSTEM_PROMPT` and all 22 phase/expert
   agent definitions were already AEGIS-branded; the fallback was the
   sole remaining upstream identity text, live in the wire format the
   moment any caller falls back to it and documented verbatim in the
   operator reference deliverable.

2. **Orientation.** The three compaction task templates (BASE /
   FROM / UP_TO) were coding-session texts: they asked for "code
   patterns and architectural decisions … essential for continuing
   development work", collected "file names / full code snippets /
   function signatures / file edits", ran a "Files and Code Sections"
   section, and closed with example instructions about "typescript
   code changes" and "test output and code changes". The
   Additional-Instructions seam re-mapped the sections for VAPT at
   call time, but the template text itself pushed the summarizer
   toward a coding mental model on every fold.

## The freeze-conflict analysis (why this is safe)

The port-era annotations claimed a changed template "silently breaks
replay's summary-hash verification for every fold ever journaled."
Code audit (this card's acceptance basis) shows the real semantics:

- `summary_hash` (`persist/journal.py::record_compaction`) is the
  sha16 of the fold's **summary text**, stored as a sidecar and
  verified by `persist/replay.py::_check_sidecar` — it never covers
  the prompt templates.
- Replay re-renders briefs from the **summary text** + EKD + budget;
  `prompt_hash` (which does cover system prompt + window) is journaled
  **forensics only** — `_verify_one_render` asserts `window_hash` and
  `brief_hash`, never `prompt_hash`.
- The actual freeze enforcement was dev-time only: sha16 pins in
  `tests/test_agents.py` and `tests/test_context_engine.py`, plus the
  oracle byte-diff test (skipped when the 3.7.3 tree is absent).

Therefore: existing journals (golden-fold, golden-quiet, pilot-01/02/03,
dppm-run1/2/3) verify identically before and after UX-02; only FUTURE
folds are shaped by the new texts. The pins are re-cut (that IS the
version gate) and remain the drift guard going forward.

## Changes

### `hypervisor/agents/prompts.py`
- `DEFAULT_AGENT_PROMPT`: identity sentence re-authored to *"You are an
  agent for AEGIS Hypervisor, an autonomous VAPT engagement platform."*
  The rest of the contract (tool mandate, completion bar, report-back,
  audience clause) is structurally unchanged — it mirrors the
  SKELETON splice the 22 definitions already use.
- `AGENT_HYGIENE_NOTES`: coding examples re-pointed at engagement
  evidence (command lines, payloads, output excerpts, PoC steps,
  findings); "bash calls" → `run_command` calls (AEGIS tool name);
  absolute-path, no-emoji and no-colon-before-tool-calls rules kept.
- `SKELETON_*` fragments: byte-unchanged (identity-neutral).
- `scripts/port_agent_prompts.py`: refuses to regenerate over an
  adapted file without `--force-verbatim` (anti-silent-revert guard).

### `hypervisor/context/compact_prompts.py`
- The three templates re-oriented to engagement vocabulary while
  preserving the load-bearing structure exactly: nine numbered
  sections; `<analysis>`/`<summary>` example shape (the stripper's
  contract); section 6 "ALL operator messages" completeness; the
  section 9 verbatim-quote anti-drift clause (base + from; up_to
  keeps its "Context for Continuing Work" variant).
  - Section 3 becomes **"Hosts, Services, Endpoints and Artifacts"**.
  - The analysis checklist collects hosts/ports/services, endpoints/
    parameters/routes, credentials/tokens/session state, tool commands
    + key outputs, artifact/evidence/finding ids.
  - Sections 1/2/4/5/7/8 descriptions re-pointed at objective/scope/
    RoE, engagement stack/attack classes, tool failures + operator
    feedback, hypotheses/exploit outcomes, task state, active phase.
  - Closing example instructions now reference credential handling /
    scope bounds / exploit outcomes / evidence artifacts.
- `NO_TOOLS_PREAMBLE`: the tool list names AEGIS tools
  (`run_command, read_file, write_file, http_probe`) instead of the
  upstream CLI's Read/Bash/Grep/Glob/Edit/Write.
- `CONTINUATION_TRANSCRIPT_POINTER`: "exact code snippets" → "exact
  tool outputs … artifacts you generated"; `{transcriptPath}` format
  unchanged.
- `NO_TOOLS_TRAILER`, `CONTINUATION_HEADER/RECENT_PRESERVED/
  RESUME_GUARD/AUTONOMOUS_GUARD`, `ADDITIONAL_INSTRUCTIONS_PREFIX`:
  byte-unchanged.

### `hypervisor/context/compact.py`
- `AEGIS_ADDITIONAL_INSTRUCTIONS` (the single seam): the section
  mapping verb softened from "Map the sections…" (re-interpretation)
  to "Keep the summary sections populated…" (reinforcement) now that
  the templates are engagement-native; the binding
  **ID PRESERVATION** rule is unchanged byte-for-byte.

### Tests
- `tests/test_agents.py`: UX-02 pins (`d5efad4e81ed7801`,
  `cb1ecb64a7ea17a3`); new
  `test_agent_surfaces_carry_no_upstream_identity` (no "Anthropic" /
  "Claude Code" on any contract surface; all 23 assembled contracts
  open on "You are …").
- `tests/test_context_engine.py`: UX-02 pins for the family; new
  `test_compaction_family_engagement_oriented` (coding vocabulary
  absent, engagement vocabulary + 9-section + anti-drift structure
  present); oracle byte-diff test updated to assert the diff is
  EXACTLY the five adapted constants.

## Acceptance

- Full suite: 386 passed (384 pre-UX-02 + 2 new), zero regressions;
  golden-fold / golden-quiet replay tests green (old journals verify
  unchanged).
- `test_prompt_constants_frozen_shas` passes with the UX-02 pins; the
  six intentionally-unchanged constants match their oracle-era pins
  byte-for-byte.
- Wire-format check: `python3 -m hypervisor.cli --doctor` registry
  composition unaffected (9/33/34); no tool surface touched.

## Provenance

The oracle-verbatim originals remain in the frozen 3.7.3 tree
(`src/core/subagent_prompts.py`, `src/core/compact_prompts.py`) and in
the port scripts' generation history. The reference deliverable
(`download/AEGIS-4.0-Agent-Prompts-and-Tools.md`) is regenerated from
the adapted code, so it continues to mirror the wire format exactly.
