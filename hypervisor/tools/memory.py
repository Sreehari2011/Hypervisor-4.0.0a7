"""hypervisor.tools.memory — engagement-memory tools (P2).

memory_query: the EKD drilldown surface every brief line points at
("every id above is queryable via memory_query"). READ-class, local,
concurrency-safe — it reads the live graph riding the tool context,
never the network. This is the tool that makes degradation cost depth,
never discoverability (the I2 invariant).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..memory.brief import render_node_detail
from ..memory.ekd import EngagementDAG
from ..permissions import SafetyClass
from .base import Tool, ToolContext, ToolResult


class MemoryQueryTool(Tool):
    name = "memory_query"
    aliases = ("dag_query",)
    input_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "minLength": 1,
                "description": "An EKD node id (e15, F7, T4...), a "
                               "canonical key (ip:10.10.11.23, "
                               "url:https://.../path, cve:CVE-2021-44228, "
                               "domain:example.com), or a substring of "
                               "a title/attr.",
            },
            "detail": {
                "type": "boolean",
                "description": "Render full node detail (attrs, edges, "
                               "provenance, entity history) instead of "
                               "the one-line match list.",
                "default": True,
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    }
    timeout_s = 10.0

    def prompt(self) -> str:
        return ("Query the engagement knowledge graph (EKD). Pass a node "
                "id from the engagement brief, a canonical key "
                "(ip/domain/url/cve), or a search substring. Returns the "
                "match list plus full detail: attrs, edges, evidence "
                "calls, entity history and provenance back to the root "
                "objective. Use this for drilldown whenever a brief line "
                "references an id you need more depth on.")

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return True

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.READ

    def max_result_chars(self) -> int:
        return 8000

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
        if not isinstance(ekd, EngagementDAG):
            return ToolResult.error(
                "engagement knowledge graph not available in this "
                "context")
        q = str(args.get("query", "")).strip()
        if not q:
            return ToolResult.error("empty query")
        want_detail = bool(args.get("detail", True))
        matches = ekd.query(q, limit=8)
        if not matches:
            stats = ekd.stats()
            return ToolResult(
                f"No EKD match for {q!r}. Graph holds "
                f"{stats['nodes_current']} live nodes "
                f"(rev {stats['rev']}). Try a node id from the brief, a "
                f"canonical key, or a shorter substring.")
        lines = [f"{len(matches)} match(es) for {q!r}:"]
        for n in matches:
            state = "" if n.valid_to is None else \
                f" [invalidated r{n.valid_to}]"
            lines.append(f"  {n.id} {n.type}"
                         + (f"/{n.subtype}" if n.subtype else "")
                         + f" · {n.title[:100]}{state}")
        if want_detail:
            lines.append("")
            lines.append(render_node_detail(ekd, matches[0].id))
        return ToolResult("\n".join(lines),
                          metadata={"matches": len(matches),
                                    "rev": ekd.rev})


MEMORY_TOOLS: Tuple[type, ...] = (MemoryQueryTool,)
