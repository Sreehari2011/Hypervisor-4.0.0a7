"""hypervisor.tools — the tool system (P1 base, P3 VAPT set).

base.py    Tool protocol + dispatcher (P1; Skeleton 9-2): tools are pure
           data — name, schema, concurrency class, safety class, render.
core.py    the CC-parity platform tools (P1; REFACTOR-05): run_command,
           read/write/edit, ls, glob, grep, todo_write.
vapt/      the VAPT toolset (P3): recon, exploit, fs, shell, report —
           ported from 3.7.3 tools/* through REFACTOR-05 with the scope
           gate (permissions.py) as the single authority.
"""
from .base import (Tool, ToolContext, ToolRegistry, ToolResult,
                   dispatch_tools, partition_batches, redact_secrets,
                   render_capped, run_one, validate_schema)

__all__ = [
    "Tool", "ToolContext", "ToolRegistry", "ToolResult",
    "dispatch_tools", "partition_batches", "redact_secrets",
    "render_capped", "run_one", "validate_schema",
]
