"""hypervisor.agents — the Task tool, run_agent and agent definitions
(P3, REFACTOR-03).

task.py     the Task tool + run_agent: THE query loop at depth+1 as a
            nested async generator (never a graph node), contract mode
            only through the tool plane — brief-slice context, scoped
            tools, single-result contract, turn ceiling with the
            done-so-far partial clause, spawn/report journal linkage
            (write-ahead preserved), session sidechain transcripts
defs.py     the agent definitions as data: the six Table 11 phase
            contracts plus the fifteen registry_v2 experts re-authored
            (prompt, tool allowlist, ceiling, scopes) — DELETE-02
            deleted the registry nodes these replace
prompts.py  the verbatim Task-tool contract texts (generated from the
            frozen oracle; byte-identity asserted by the port script)
"""
from .defs import AGENTS, AGENT_ORDER, AgentDef, get_agent, list_agents
from .task import (AgentReport, TaskTool, build_child_registry,
                   build_fork_context, brief_slice_for_agent, run_agent,
                   slice_brief, scoped_query)

__all__ = [
    "AGENTS", "AGENT_ORDER", "AgentDef", "get_agent", "list_agents",
    "AgentReport", "TaskTool", "build_child_registry",
    "build_fork_context", "brief_slice_for_agent", "run_agent",
    "slice_brief", "scoped_query",
]
