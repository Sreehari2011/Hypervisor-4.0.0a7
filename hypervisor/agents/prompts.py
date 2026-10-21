"""hypervisor.agents.prompts — the agent contract texts (P3).

ORIGIN: scripts/port_agent_prompts.py generated this file verbatim from
the frozen 3.7.3 oracle (src/core/subagent_prompts.py), itself verbatim
extractions of the Claude Code leak-repo Task-tool contract texts
(prompts.ts L758 + L766-770).

UX-02 (a7): the two identity-bearing constants were re-authored for the
AEGIS platform. DEFAULT_AGENT_PROMPT no longer declares a Claude Code /
Anthropic identity — it is the general-purpose fallback contract and now
opens on the same AEGIS identity the 22 phase/expert definitions carry;
AGENT_HYGIENE_NOTES' coding-era examples were re-pointed at engagement
evidence (commands, payloads, artifacts). The oracle-verbatim originals
remain recoverable from the 3.7.3 tree via scripts/port_agent_prompts.py
(it refuses to overwrite an adapted file without --force-verbatim). The
four SKELETON_* fragments were always identity-neutral and are
byte-unchanged; the sha pins in tests/test_agents.py are the UX-02 cuts.

REFACTOR-03: the phase/expert agent definitions (defs.py) splice the
SKELETON_* fragments into AEGIS identity sentences exactly as 3.7's
Table 11 did; DEFAULT_AGENT_PROMPT is the fallback contract for the
general-purpose agent.
"""
DEFAULT_AGENT_PROMPT = (
    "You are an agent for AEGIS Hypervisor, an autonomous VAPT "
    "engagement platform. Given the user's message, you should use the "
    "tools available to complete the task. Complete the task fully—don't "
    "gold-plate, but don't leave it half-done. When you complete the "
    "task, respond with a concise report covering what was done and any "
    "key findings — the caller will relay this to the user, so it only "
    "needs the essentials."
)


AGENT_HYGIENE_NOTES = (
    'Notes:\n- Agent threads spawn a fresh shell in the workspace for '
    'every run_command call, as a result please only use absolute file '
    'paths.\n- In your final response, share evidence and artifact '
    'paths (always absolute, never relative) that are relevant to the '
    'task. Include command lines, payloads or output excerpts only '
    'when the exact text is load-bearing (e.g., a failing command, a '
    'proof-of-concept step, a finding the caller asked for) — do not '
    'recap output you merely read.\n- For clear communication with the '
    'user the assistant MUST avoid using emojis.\n- Do not use a colon '
    'before tool calls. Text like "Let me probe the endpoint:" '
    'followed by a probe tool call should just be "Let me probe the '
    'endpoint." with a period.'
)


SKELETON_TOOL_MANDATE = (
    "Given the user's message, you should use the tools available to complete"
    ' the task.'
)


SKELETON_COMPLETION_BAR = (
    "Complete the task fully—don't gold-plate, but don't leave it half-done."
)


SKELETON_REPORT_BACK = (
    'When you complete the task, respond with a concise report covering what '
    'was done and any key findings'
)


SKELETON_AUDIENCE_CLAUSE = (
    'the caller will relay this to the user, so it only needs the essentials'
)
