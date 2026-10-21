"""hypervisor.tools.vapt.report — the evidence-chained report compiler
(P3, REFACTOR-05).

The 3.7 reporting phase's deliverable surface as a tool: compiles the
engagement's findings from the EKD (severity-ordered, with evidence
artifact ids, affected entities and per-finding provenance) into a
markdown report artifact in the workspace. Every claim in the output
carries the EKD id it rests on — the Table 11 reporting completion bar
("every reported claim traceable to evidence id and objective") made
mechanical.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ...permissions import SafetyClass
from ..base import Tool, ToolContext, ToolResult

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   "info": 4}


class CompileReportTool(Tool):
    name = "compile_report"
    input_schema = {
        "type": "object",
        "properties": {
            "output_path": {
                "type": "string", "maxLength": 300,
                "default": "report.md",
                "description": "Workspace-relative output file "
                               "(default report.md).",
            },
            "include_hypotheses": {"type": "boolean", "default": True},
            "include_surface": {"type": "boolean", "default": True},
        },
        "additionalProperties": False,
    }
    timeout_s = 30.0
    path_args = ("output_path",)

    def prompt(self) -> str:
        return ("Compile the engagement report from the EKD: "
                "severity-ordered findings with evidence artifact ids, "
                "affected entities, the attack-surface inventory and "
                "open hypotheses — every claim carries the id it rests "
                "on. Writes a markdown artifact into the workspace and "
                "returns its path plus the counts.")

    def safety_class(self, args: Dict[str, Any]) -> SafetyClass:
        return SafetyClass.WRITE       # workspace-local write only

    def concurrency_safe(self, args: Dict[str, Any]) -> bool:
        return False                    # one writer per report file

    def is_persistent(self, args: Dict[str, Any]) -> bool:
        return False

    def extract_targets(self, args: Dict[str, Any]) -> List[str]:
        return []                       # no estate targets

    def description(self, args: Dict[str, Any]) -> str:
        return f"compile_report -> {args.get('output_path', 'report.md')}"

    async def call(self, args: Dict[str, Any],
                   ctx: ToolContext) -> ToolResult:
        from ...memory.ekd import EngagementDAG
        ekd = (ctx.extra or {}).get("ekd") if ctx.extra else None
        if ekd is None:
            return ToolResult.error(
                "no engagement graph attached to this context — the "
                "report compiles from the EKD")

        findings = list(ekd.nodes_of_type("finding"))
        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.get(str(f.attrs.get("severity", "")).lower(),
                                5), -f.rev))

        objectives = list(ekd.nodes_of_type("objective"))
        objective = (str(objectives[-1].attrs.get(
            "text", objectives[-1].title)
        ) if objectives else "(no objective recorded)")

        lines: List[str] = []
        lines.append("# AEGIS Engagement Report")
        lines.append("")
        lines.append(f"**Objective:** {objective}")
        lines.append(f"**EKD revision:** {ekd.rev} · "
                     f"**Findings:** {len(findings)}")
        lines.append("")

        lines.append("## Findings")
        if not findings:
            lines.append("_No findings recorded in the engagement "
                         "graph._")
        for f in findings:
            sev = str(f.attrs.get("severity", "info")).upper()
            lines.append("")
            lines.append(f"### {f.id} — {f.title} [{sev}]")
            desc = f.attrs.get("description") or f.attrs.get("detail")
            if desc:
                lines.append(f"\n{desc}")
            # evidence: artifact + entity neighbours
            evidence = list(ekd.neighbors(
                f.id, kinds=None, direction="in"))
            if evidence:
                lines.append("\n**Evidence:** "
                             + ", ".join(sorted({e.id for e in evidence})))
            affected = list(ekd.neighbors(
                f.id, kinds=None, direction="out"))
            if affected:
                lines.append("\n**Affected:** "
                             + ", ".join(sorted({a.id for a
                                                 in affected})))
            if f.attrs.get("call_id"):
                lines.append(f"\n_Provenance: tool call "
                             f"{f.attrs['call_id']}_")

        if args.get("include_surface", True):
            entities = list(ekd.nodes_of_type("entity"))
            if entities:
                lines.append("")
                lines.append("## Attack Surface Inventory")
                for e in entities[:200]:
                    sub = f"/{e.subtype}" if e.subtype else ""
                    lines.append(f"- {e.id} (entity{sub}): {e.title}")

        if args.get("include_hypotheses", True):
            hyps = list(ekd.nodes_of_type("hypothesis"))
            if hyps:
                lines.append("")
                lines.append("## Open Hypotheses / Chains")
                for h in hyps[:100]:
                    status = h.attrs.get("status", "active")
                    lines.append(f"- {h.id} [{status}]: {h.title}")

        body = "\n".join(lines) + "\n"
        out_rel = str(args.get("output_path") or "report.md")
        out_path = os.path.join(ctx.workspace,
                                os.path.normpath(out_rel).lstrip("/"))
        if not os.path.realpath(out_path).startswith(
                os.path.realpath(ctx.workspace)):
            return ToolResult.error(
                f"output path {out_rel!r} escapes the workspace")
        try:
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(body)
        except OSError as exc:
            return ToolResult.error(f"report write failed: {exc}")
        return ToolResult(
            json.dumps({"path": out_rel, "chars": len(body),
                        "findings": len(findings),
                        "entities": len(list(ekd.nodes_of_type(
                            "entity"))),
                        "hypotheses": len(list(ekd.nodes_of_type(
                            "hypothesis")))}, indent=2),
            metadata={"path": out_rel, "findings": len(findings)})
