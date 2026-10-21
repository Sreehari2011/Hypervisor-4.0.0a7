#!/usr/bin/env python3
"""P3 smoke: imports, defs, registry, prompts byte-identity."""
import sys
sys.path.insert(0, "/home/z/my-project/hypervisor-4.0")

import hypervisor.agents as A                                   # noqa: E402
from hypervisor.tools.core import build_registry               # noqa: E402
from hypervisor.agents import get_agent                        # noqa: E402

print("defs:", len(A.AGENTS))
reg = build_registry()
print("registry:", len(reg), "tools; task:", reg.resolve("task") is not None,
      "nmap:", reg.resolve("network_scan_nmap") is not None)
print("label-resolve:", get_agent("Replay_Attack_Agent").name, "/",
      get_agent("Selection_Agent").name)

# prompts byte-identity vs oracle when present
import os                                                      # noqa: E402
oracle = os.environ.get("AEGIS_ORACLE_TREE",
                        "/home/z/my-project/Hypervisor-3.7.3")
src = os.path.join(oracle, "src/core/subagent_prompts.py")
if os.path.exists(src):
    ns = {}
    exec(A.prompts.__doc__ and "" or "", {})  # no-op guard
    from hypervisor.agents import prompts as p4
    text = open(src, encoding="utf-8").read()
    ons = {}
    import re
    cleaned = re.sub(r'^GENERATED FILE.*?"""', '"""x"""', text,
                     count=1, flags=re.S)
    exec(cleaned, ons)
    bad = [c for c in ("DEFAULT_AGENT_PROMPT", "AGENT_HYGIENE_NOTES",
                       "SKELETON_TOOL_MANDATE", "SKELETON_COMPLETION_BAR",
                       "SKELETON_REPORT_BACK", "SKELETON_AUDIENCE_CLAUSE")
           if getattr(p4, c) != ons[c]]
    print("prompt byte-identity:", "OK (6/6)" if not bad else f"FAIL {bad}")
else:
    print("prompt byte-identity: oracle absent, skipped")

# scoped child registry
from hypervisor.memory.ekd import EngagementDAG                # noqa: E402
from hypervisor.agents.task import build_child_registry        # noqa: E402
ekd = EngagementDAG()
d = get_agent("recon")
child = build_child_registry(reg, d, ekd)
names = set(child.names())
print("child registry:", len(names), "tools; no task:",
      "task" not in names, "; has scoped memory_query:",
      "memory_query" in names)
missing = [n for n in d.tools if n != "memory_query" and n not in names]
print("allowlist satisfied:", not missing, missing or "")
