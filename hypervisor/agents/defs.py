"""hypervisor.agents.defs — agent definitions as data (P3, REFACTOR-03).

The fifteen 3.7.3 registry experts (src/agents/registry_v2.py) plus the
six Table 11 phase contracts (src/core/subagents.py PHASE_CONTRACTS) are
re-authored HERE as agent definition files: prompt, tool allowlist, turn
ceiling, brief-slice scopes. Data, not code — editable without touching
the platform, auditable in git, spawnable on demand via the Task tool
(DELETE-02 deleted the registry nodes these replace).

Every definition carries the SAME skeleton discipline the 3.7 contract
spawn used: identity -> tool mandate -> completion bar -> report-back
format -> audience constraint (the spliced SKELETON_* fragments are
byte-verbatim from agents/prompts.py), then the hygiene notes, the
evidence-citation clause, the phase-scoped brief slice at spawn time,
and the explicit no-history-inheritance statement (rule C5).

Tool allowlists reference the 4.0 registry names (run_command, read_file,
network_scan_nmap, ...). The empty tuple () means "the full parent
toolset minus the Task tool itself" — reserved for the general-purpose
agent. Children NEVER see the Task tool (spawn depth is capped at 2 by
the Task tool's own gate; the allowlist makes it structural).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .prompts import (AGENT_HYGIENE_NOTES, SKELETON_AUDIENCE_CLAUSE,
                      SKELETON_COMPLETION_BAR, SKELETON_REPORT_BACK,
                      SKELETON_TOOL_MANDATE)

# Section keys of render_brief_l2 a slice may keep (Part 5 fixed set).
L2_SECTION_KEYS: Tuple[str, ...] = ("objective", "tasks", "findings",
                                    "attack_surface", "hypotheses",
                                    "residual")

_ALL_ENTITY_SUBTYPES = ("host", "net", "domain", "port_service", "endpoint",
                        "tech", "credential", "user_account", "payload",
                        "file", "mobile_app", "crypto_material")

# The 4.0 recon/exploit toolset names these definitions allow. Kept as
# registry names, not tool objects — the Task tool resolves them against
# the parent registry at spawn time and refuses unknown names.
_RECON_TOOLS: Tuple[str, ...] = (
    "run_command", "network_scan_nmap", "check_port_listener",
    "advanced_http_request", "retrieve_url_content", "detect_waf",
    "headless_dom_navigate", "headless_dom_interact", "web_search_osint",
    "map_vhost", "read_file", "ls", "glob", "grep", "write_file",
    "memory_query", "passive_scan", "todo_write", "list_buffers",
)
_EXPLOIT_TOOLS: Tuple[str, ...] = _RECON_TOOLS + (
    "execute_code", "execute_exploit_script", "generate_oob_payload",
    "poll_oob_interactions",
)
_MOBILE_TOOLS: Tuple[str, ...] = _RECON_TOOLS + ("analyze_apk",
                                                 "analyze_ipa")
_ANALYSIS_TOOLS: Tuple[str, ...] = (
    "run_command", "read_file", "ls", "glob", "grep", "write_file",
    "memory_query", "analyze_entropy", "crypto_analyzer", "analyze_apk",
    "analyze_ipa", "passive_scan", "todo_write", "list_buffers",
    "check_port_listener",
)


@dataclass(frozen=True)
class AgentDef:
    """One spawnable agent (a row of Table 11 or a registry_v2 expert,
    re-authored). All prompt fields are spliced by build_agent_spawn in
    agents/task.py — the def itself is inert data."""
    name: str                       # Task-tool key ("recon", "sast", ...)
    label: str                      # human label ("Recon", "SAST")
    description: str                # model-facing one-liner (tool prompt)
    identity: str                   # "an AEGIS ... subagent (...)"
    completion_bar: str             # testable bar (verbatim class)
    report_emphasis: str            # Table 11 report-back emphasis
    brief_sections: Tuple[str, ...]  # slice keys
    query_types: Tuple[str, ...]    # memory_query scope (node types)
    query_subtypes: Tuple[str, ...]  # entity subtypes in scope
    tools: Tuple[str, ...] = ()     # () = full parent toolset
    ceiling: int = 8                # turn ceiling (done-so-far partial)
    refute_not_confirm: bool = False
    model_role: str = "executor"    # D3: which tier spawns run on


# ─── the six Table 11 phase contracts (verbatim bars/emphases) ────────

_PHASES: Tuple[AgentDef, ...] = (
    AgentDef(
        name="recon", label="Recon",
        description=("Map the authorized attack surface: scan targets, "
                     "enumerate services, catalogue what is reachable."),
        identity=("an AEGIS recon-phase subagent (autonomous black-box "
                  "VAPT harness)"),
        completion_bar=("Every authorized target scanned once at agreed "
                        "depth; no unscoped touch"),
        report_emphasis=("Surface map deltas, new EKD entities with ids"),
        brief_sections=("objective", "tasks", "attack_surface"),
        query_types=("entity", "artifact"),
        query_subtypes=("host", "net", "domain", "port_service",
                        "endpoint", "tech"),
        tools=_RECON_TOOLS),
    AgentDef(
        name="web-exploit", label="Web exploit",
        description=("Test web candidates to conclusion: injectable "
                     "inputs, auth flaws, logic bugs, safe PoCs."),
        identity=("an AEGIS web-exploitation subagent (autonomous "
                  "black-box VAPT harness)"),
        completion_bar=("Each candidate endpoint tested to conclusion or "
                        "documented dead end"),
        report_emphasis=("Findings with evidence artifact ids, "
                         "reproduction steps"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("endpoint", "domain", "tech", "host"),
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="network-exploit", label="Network exploit",
        description=("Escalate validated network findings: pivots, "
                     "service exploitation, credential reuse."),
        identity=("an AEGIS network-exploitation subagent (autonomous "
                  "black-box VAPT harness)"),
        completion_bar=("Each validated finding escalated or blocked, "
                        "with the blocker identified"),
        report_emphasis=("Chains attempted, credentials gained (masked), "
                         "pivot state"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("host", "net", "port_service", "credential"),
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="credential-attack", label="Credential attack",
        description=("Test and reuse credential material: validity "
                     "matrix, spraying discipline, hash handling."),
        identity=("an AEGIS credential-attack subagent (autonomous "
                  "black-box VAPT harness)"),
        completion_bar=("Each credential material tested or queued with "
                        "reason"),
        report_emphasis=("Validity matrix, hashes masked, next targets"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("credential", "user_account", "crypto_material",
                        "host"),
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="verification", label="Verification",
        description=("Refute claimed findings before they reach the "
                     "report; only survivors pass."),
        identity=("an AEGIS verification subagent (autonomous black-box "
                  "VAPT harness)"),
        completion_bar=("Attempt to refute each claimed finding; only "
                        "survivors pass"),
        report_emphasis=("Refuted claims with the refuting evidence, "
                         "prominently"),
        brief_sections=("objective", "findings", "hypotheses"),
        query_types=("finding", "hypothesis", "entity", "artifact"),
        query_subtypes=("host", "endpoint", "domain", "credential",
                        "port_service"),
        # 7.3: this phase exists specifically to refute, not confirm.
        refute_not_confirm=True,
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="reporting", label="Reporting",
        description=("Compile the evidence-chained report: findings, "
                     "reproduction, traceability to the objective."),
        identity=("an AEGIS reporting subagent (autonomous black-box VAPT "
                  "harness)"),
        completion_bar=("Every reported claim traceable to evidence id "
                        "and objective"),
        report_emphasis=("Draft sections with id citations, no unsourced "
                         "claims"),
        brief_sections=("objective", "tasks", "findings", "hypotheses",
                        "residual"),
        query_types=("finding", "hypothesis", "artifact", "task", "entity"),
        query_subtypes=_ALL_ENTITY_SUBTYPES,
        tools=_ANALYSIS_TOOLS + ("compile_report",)),
)

# ─── the fifteen registry_v2 experts, re-authored as definitions ──────
#
# registry_v2.py AGENTS_CONFIG rows carried: name, system prompt,
# allowed tools, allowed transfers. The transfers (grid handoff edges)
# do not port (DELETE-01/02); the tool allowlists translate to the 4.0
# registry names, and each expert's ceiling defaults to the Table 11
# value unless the role needs more room (fuzz/DFIR run long).

_EXPERTS: Tuple[AgentDef, ...] = (
    AgentDef(
        name="planner", label="Planner",
        description=("Plan the engagement: sequence phases, decompose "
                     "the objective into tasks, track dependencies."),
        identity="an AEGIS engagement-planning subagent (VAPT harness)",
        completion_bar=("A task plan covering the whole objective, each "
                        "task with a definition of done"),
        report_emphasis=("Task list with ids, dependency order, first "
                         "phase recommendation"),
        brief_sections=("objective", "tasks", "findings", "residual"),
        query_types=("task", "objective", "finding", "entity"),
        query_subtypes=_ALL_ENTITY_SUBTYPES,
        tools=("run_command", "read_file", "ls", "glob", "grep",
               "write_file", "memory_query", "todo_write")),
    AgentDef(
        name="network-analyzer", label="Network analyzer",
        description=("Analyze network topology and traffic: segments, "
                     "services, exposure deltas."),
        identity="an AEGIS network-analysis subagent (VAPT harness)",
        completion_bar=("Every observed segment and service catalogued "
                        "with an id"),
        report_emphasis=("Topology deltas, service inventory, exposure "
                         "notes"),
        brief_sections=("objective", "tasks", "attack_surface"),
        query_types=("entity", "artifact", "finding"),
        query_subtypes=("host", "net", "port_service", "tech", "domain"),
        tools=_RECON_TOOLS),
    AgentDef(
        name="web-enumerator", label="Web enumerator",
        description=("Enumerate web assets: endpoints, parameters, "
                     "forms, hidden routes, technologies."),
        identity="an AEGIS web-enumeration subagent (VAPT harness)",
        completion_bar=("The target's reachable endpoint set enumerated "
                        "and recorded"),
        report_emphasis=("Endpoint inventory with ids, parameter "
                         "surface, tech fingerprint"),
        brief_sections=("objective", "tasks", "attack_surface"),
        query_types=("entity", "artifact"),
        query_subtypes=("endpoint", "domain", "tech", "host"),
        tools=_RECON_TOOLS),
    AgentDef(
        name="bug-bounter", label="Bug bounter",
        description=("Hunt exploitable bugs across the enumerated "
                     "surface with safe proofs of concept."),
        identity="an AEGIS bug-hunting subagent (VAPT harness)",
        completion_bar=("Each tested bug class either proven (PoC + "
                        "evidence id) or written off"),
        report_emphasis=("Validated bugs with severity, PoC artifact "
                         "ids, affected entities"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("endpoint", "domain", "tech", "host", "payload"),
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="red-team", label="Red team",
        description=("Chain validated findings into an attack path: "
                     "foothold, pivots, objective reach."),
        identity="an AEGIS red-team subagent (VAPT harness)",
        completion_bar=("An attack path to the stated objective or a "
                        "hard blocker, each step evidenced"),
        report_emphasis=("Chain narrative with per-step evidence ids, "
                         "pivot state, blockers"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact", "credential"),
        query_subtypes=_ALL_ENTITY_SUBTYPES,
        tools=_EXPLOIT_TOOLS,
        ceiling=10),
    AgentDef(
        name="mobile-analyzer", label="Mobile analyzer",
        description=("Static analysis of mobile packages: manifest, "
                     "permissions, secrets, transport posture."),
        identity="an AEGIS mobile-analysis subagent (VAPT harness)",
        completion_bar=("The package fully inventoried: manifest, "
                        "permissions, embedded secrets, endpoints"),
        report_emphasis=("Permission risks, hardcoded secrets (masked), "
                         "endpoint/URL inventory with ids"),
        brief_sections=("objective", "tasks", "attack_surface"),
        query_types=("entity", "artifact", "finding"),
        query_subtypes=("mobile_app", "file", "endpoint", "domain",
                        "crypto_material"),
        tools=_MOBILE_TOOLS),
    AgentDef(
        name="mobile-exploiter", label="Mobile exploiter",
        description=("Exploit validated mobile findings: IPC abuse, "
                     "weak storage, transport attacks."),
        identity="an AEGIS mobile-exploitation subagent (VAPT harness)",
        completion_bar=("Each mobile finding exploited to a safe proof "
                        "or written off"),
        report_emphasis=("Exploitation proofs with artifact ids, "
                         "affected components"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("mobile_app", "file", "credential", "payload"),
        tools=_MOBILE_TOOLS + ("execute_code",
                               "execute_exploit_script")),
    AgentDef(
        name="sast", label="SAST",
        description=("Static source analysis: sinks, taint paths, "
                     "crypto misuse, secret leakage."),
        identity="an AEGIS static-analysis subagent (VAPT harness)",
        completion_bar=("Every scanned path either cleared or carrying "
                        "a finding id with file:line"),
        report_emphasis=("Findings with file:line anchors and evidence "
                         "artifact ids"),
        brief_sections=("objective", "tasks", "findings"),
        query_types=("finding", "artifact", "entity"),
        query_subtypes=("file", "endpoint", "tech"),
        tools=_ANALYSIS_TOOLS,
        ceiling=12),
    AgentDef(
        name="dast", label="DAST",
        description=("Dynamic testing of the running target: probes, "
                     "payloads, response analysis."),
        identity="an AEGIS dynamic-analysis subagent (VAPT harness)",
        completion_bar=("The dynamic test matrix executed per the "
                        "objective's scope and depth"),
        report_emphasis=("Responses that proved a finding (with ids), "
                         "dead ends documented"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("endpoint", "domain", "host", "tech"),
        tools=_EXPLOIT_TOOLS),
    AgentDef(
        name="fuzz", label="Fuzz",
        description=("Bounded fuzzing of inputs and interfaces with "
                     "crash triage."),
        identity="an AEGIS fuzzing subagent (VAPT harness)",
        completion_bar=("The fuzz budget spent per target with each "
                        "crash triaged or queued"),
        report_emphasis=("Crash triage, coverage notes, artifact ids for "
                         "reproducers"),
        brief_sections=("objective", "tasks", "findings"),
        query_types=("finding", "artifact", "entity"),
        query_subtypes=("endpoint", "payload", "file"),
        tools=_EXPLOIT_TOOLS,
        ceiling=12),
    AgentDef(
        name="blue-team", label="Blue team",
        description=("Defensive review: detection gaps, hardening "
                     "priorities, log coverage."),
        identity="an AEGIS blue-team subagent (VAPT harness)",
        completion_bar=("Each observed attack class paired with its "
                        "detection/hardening state"),
        report_emphasis=("Detection gaps, hardening list with owner-"
                         "ready wording"),
        brief_sections=("objective", "findings", "hypotheses"),
        query_types=("finding", "entity", "artifact"),
        query_subtypes=_ALL_ENTITY_SUBTYPES,
        tools=_ANALYSIS_TOOLS),
    AgentDef(
        name="dfir", label="DFIR",
        description=("Forensic collection and analysis within the "
                     "workspace: timelines, artifacts, indicators."),
        identity="an AEGIS forensic subagent (VAPT harness)",
        completion_bar=("A defensible timeline of the examined "
                        "artifacts with hash-anchored evidence"),
        report_emphasis=("Timeline, indicators, artifact ids, chain-of-"
                         "custody notes"),
        brief_sections=("objective", "tasks", "findings", "residual"),
        query_types=("artifact", "entity", "finding"),
        query_subtypes=("file", "host", "user_account", "payload"),
        tools=_ANALYSIS_TOOLS,
        ceiling=12),
    AgentDef(
        name="reverse-engineering", label="Reverse engineering",
        description=("Binary and protocol reversing: packing, symbols, "
                     "crypto, protocol structure."),
        identity="an AEGIS reverse-engineering subagent (VAPT harness)",
        completion_bar=("The binary's structure, protections and entry "
                        "points documented with artifacts"),
        report_emphasis=("Architecture notes, protections, crypto use, "
                         "artifact ids"),
        brief_sections=("objective", "tasks", "findings"),
        query_types=("artifact", "entity", "finding"),
        query_subtypes=("file", "payload", "crypto_material"),
        tools=_ANALYSIS_TOOLS,
        ceiling=12),
    AgentDef(
        name="memory-analysis", label="Memory analysis",
        description=("Memory image and dump triage: processes, "
                     "injection, credentials in memory."),
        identity="an AEGIS memory-analysis subagent (VAPT harness)",
        completion_bar=("The dump triaged: process list, anomalies, "
                         "recoverable secrets (masked)"),
        report_emphasis=("Injected code, credential material (masked), "
                         "artifact ids"),
        brief_sections=("objective", "tasks", "findings"),
        query_types=("artifact", "entity", "finding"),
        query_subtypes=("file", "user_account", "credential",
                        "crypto_material"),
        tools=_ANALYSIS_TOOLS,
        ceiling=12),
    AgentDef(
        name="replay-attack", label="Replay attack",
        description=("Session and token replay testing: fixation, "
                     "reuse windows, nonce discipline."),
        identity="an AEGIS replay-attack subagent (VAPT harness)",
        completion_bar=("Each token/session class replay-tested with "
                        "outcomes recorded"),
        report_emphasis=("Replay outcomes per token class, evidence "
                         "artifact ids"),
        brief_sections=("objective", "tasks", "findings", "attack_surface"),
        query_types=("entity", "finding", "artifact"),
        query_subtypes=("credential", "endpoint", "user_account"),
        tools=_EXPLOIT_TOOLS),
)

# ─── the general-purpose fallback (CC Task tool's default) ────────────

_GENERAL = AgentDef(
    name="general-purpose", label="General purpose",
    description=("Research, explore and answer across the workspace "
                 "with the full toolset. Use for any task that does not "
                 "fit a named expert."),
    identity="an AEGIS general-purpose subagent (VAPT harness)",
    completion_bar=("Complete the task fully - don't gold-plate, but "
                    "don't leave it half-done"),
    report_emphasis=("What was done and any key findings"),
    brief_sections=L2_SECTION_KEYS,
    query_types=("entity", "finding", "artifact", "task", "hypothesis"),
    query_subtypes=_ALL_ENTITY_SUBTYPES,
    tools=(),                     # full parent toolset (minus Task tool)
)

# legacy registry_v2 names that map onto re-keyed 4.0 definitions
_LEGACY_ALIASES: Dict[str, str] = {
    "selection": "planner",            # registry_v2 Selection_Agent
    "selection-agent": "planner",
}

AGENTS: Dict[str, AgentDef] = {d.name: d
                               for d in (*_PHASES, *_EXPERTS, _GENERAL)}
AGENT_ORDER: Tuple[str, ...] = tuple(AGENTS.keys())


def get_agent(name: str) -> AgentDef:
    """Resolve a definition by name, label, or legacy registry name
    (case-insensitive; hyphens/underscores interchangeable; a trailing
    '_agent' suffix strips). Raises KeyError listing the valid keys —
    an agent definition is load-bearing, guessing one silently is a
    defect (3.7 parity)."""
    key = str(name or "").strip().lower().replace("_", "-")
    if key.endswith("-agent"):
        key = key[:-len("-agent")]
    if key in _LEGACY_ALIASES:
        key = _LEGACY_ALIASES[key]
    if key in AGENTS:
        return AGENTS[key]
    for d in AGENTS.values():
        if d.label.lower() == key:
            return d
    raise KeyError(
        f"unknown agent {name!r} — spawnable agents: "
        f"{', '.join(AGENT_ORDER)}")


def list_agents() -> List[AgentDef]:
    """All definitions in registry order."""
    return [AGENTS[n] for n in AGENT_ORDER]


def system_prompt_for(defn: AgentDef, *, slice_text: str = "",
                      slice_rev: int = 0, workspace: str = "",
                      model_name: str = "") -> str:
    """Assemble the contract system prompt (the Table 11 + Part 7.1/7.2
    splice, 3.7 build_contract_spawn shape):

      1. skeleton: identity + verbatim tool mandate + verbatim
         completion bar + phase bar + verbatim report-back + audience
         clause;
      2. the refute-not-confirm clause when the def carries it;
      3. the verbatim hygiene notes;
      4. the AEGIS evidence-citation clause;
      5. the phase report-back emphasis;
      6. the phase-scoped brief slice at rev N;
      7. the memory_query scope line + the no-inheritance statement;
      8. the environment line.
    """
    skeleton = (
        f"You are {defn.identity}. {SKELETON_TOOL_MANDATE} "
        f"{SKELETON_COMPLETION_BAR} Completion bar for this role "
        f"({defn.label}): {defn.completion_bar}. "
        f"{SKELETON_REPORT_BACK} — {SKELETON_AUDIENCE_CLAUSE}."
    )
    if defn.refute_not_confirm:
        skeleton += (
            " This role exists specifically to REFUTE claimed findings, "
            "not to confirm them — attempt to break each claim; only "
            "survivors pass.")

    aegis_note = (
        "In your final report, every evidence claim must cite the EKD "
        "artifact, finding or entity id it rests on (e.g. F3, a12, h2) — "
        "an unsourced claim is a report defect.")

    scope_line = (
        "QUERY SCOPE: your memory_query tool is scoped for this role to "
        f"node types ({', '.join(defn.query_types)}) and entity subtypes "
        f"({', '.join(defn.query_subtypes)}) — query any id you see "
        "above for full depth. You have NO other engagement history: "
        "the parent window and journal are not inherited.")

    env_line = f"Environment: AEGIS 4.0 · agent {defn.name}"
    if workspace:
        env_line += f" · workspace {workspace}"
    if model_name:
        env_line += f" · model {model_name}"

    parts = [skeleton, AGENT_HYGIENE_NOTES, aegis_note,
             f"Report-back emphasis ({defn.label}): "
             f"{defn.report_emphasis}."]
    if slice_text:
        parts.append(
            f"ENGAGEMENT KNOWLEDGE (phase-scoped brief slice, rev "
            f"{int(slice_rev)}):\n{slice_text}")
    parts.append(scope_line)
    parts.append(env_line)
    return "\n\n".join(parts)
